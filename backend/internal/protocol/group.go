package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/molepipe/molepipe/backend/internal/crypto"
	"github.com/molepipe/molepipe/backend/internal/identity"
)

// groupContext is the signing label for group messages, DISTINCT from the
// direct ("message") and mailbox ("mailbox-message") labels so signed bytes can
// never be replayed across paths. signBlob is length-prefixed, so a distinct
// label is enough to keep the three domains disjoint.
const groupContext = "group-message"

// groupImageContext is the distinct signing label for a group IMAGE message, so
// its signed bytes can never be replayed as a text message (and vice versa) and
// text-message signatures stay byte-for-byte unchanged.
const groupImageContext = "group-image-message"

// groupReplyContext is the distinct signing label for a group text message that
// is a REPLY (carries ReplyID). It gives the reply its own signed domain — like
// groupImageContext — so a reply's signature can never be replayed as a plain
// text message, and, crucially, a plain (non-reply) text message's signed bytes
// stay byte-for-byte identical to before replies existed. That byte-identity is
// what keeps ordinary group traffic verifiable by members who predate this field.
const groupReplyContext = "group-reply-message"

// MaxGroupThumbBytes bounds the inline thumbnail that fans out with a group image
// message. Small on purpose: it rides in every per-member envelope (and gossips),
// so it must stay well inside the group envelope's plaintext guard (4*maxPlaintext)
// even after base64 in the JSON wire form. The FULL image is fetched on demand.
const MaxGroupThumbBytes = 16 << 10

// GroupMessage is one message in a group, signed by its AUTHOR over the
// plaintext content. That is the crucial property behind the "everyone relays"
// model: because the signature covers the content and not any transport, any
// member who has the message can re-seal it for another member and forward it,
// and the recipient still verifies it as authentically from the original author
// — the courier can neither forge nor reattribute it. Authorship is bound
// implicitly: the signature only verifies under Author's key, so changing Author
// invalidates it. The signature does NOT cover Author for the same reason
// MailEnvelope omits Sender — Author *is* the verifying key.
type GroupMessage struct {
	GroupID string
	Author  string // original sender's account
	At      time.Time
	Text    string // a text message; empty for an image message

	// ReplyID, when non-empty, marks this text message as a reply to the group
	// message with that id (the deterministic GroupMessageID of the quoted
	// message, which both ends compute identically). It is folded into the signed
	// blob under groupReplyContext so a forwarding courier cannot repoint the
	// quote. Only the id is signed/carried — the quoted preview and author are
	// re-derived locally by the recipient, exactly as on the 1:1 path.
	ReplyID string

	// Image message (all zero for a text message). The THUMBNAIL rides inline and
	// fans out to every member (and gossips like any message); the FULL image is
	// fetched on demand (a later phase) and verified against FullHash. Because
	// FullHash is author-signed, a member serving the full image later cannot
	// substitute a different image behind the thumbnail the group already saw.
	Thumb     []byte // small blurry low-res preview (JPEG), inlined
	ThumbMime string
	FullID    string // fetch/store id of the full image (32-hex)
	FullHash  []byte // sha256 of the full image bytes: id component + download verification
	FullMime  string
	FullSize  int

	Sig []byte // Sign(author_Ed, signingBlob) — two forms, see signingBlob
}

// isImage reports whether this is an image message (vs a text message).
func (m GroupMessage) isImage() bool { return m.FullID != "" }

func (m GroupMessage) signingBlob() []byte {
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(m.At.UnixNano()))
	if m.isImage() {
		var sz [8]byte
		binary.BigEndian.PutUint64(sz[:], uint64(m.FullSize))
		// Cover the thumbnail AND all full-image metadata, so a forwarding courier
		// can tamper with neither — the full-image hash in particular.
		return signBlob(sigContextFor(protoVerCurrent), []byte(groupImageContext), []byte(m.GroupID), ts[:],
			m.Thumb, []byte(m.ThumbMime), []byte(m.FullID), m.FullHash, []byte(m.FullMime), sz[:])
	}
	if m.ReplyID != "" {
		// A reply: its own signed domain, covering the quoted id so a courier can't
		// repoint it. Non-reply text never reaches here, so its bytes are unchanged.
		return signBlob(sigContextFor(protoVerCurrent), []byte(groupReplyContext), []byte(m.GroupID), ts[:], []byte(m.Text), []byte(m.ReplyID))
	}
	return signBlob(sigContextFor(protoVerCurrent), []byte(groupContext), []byte(m.GroupID), ts[:], []byte(m.Text))
}

// Verify reports whether the author's signature is valid. The caller still has
// to check that Author is actually a member of the group's roster — the
// signature proves who wrote it, not that they belong.
func (m GroupMessage) Verify() bool {
	authorEd, err := identity.AccountNumberFromString(m.Author)
	if err != nil {
		return false
	}
	return ed25519.Verify(authorEd, m.signingBlob(), m.Sig)
}

// OpenGroup verifies and decrypts a group envelope addressed to this peer,
// without exposing the identity to the caller (mirrors OpenMail).
func (p *Peer) OpenGroup(env GroupEnvelope) (GroupMessage, error) {
	return OpenGroupEnvelope(p.id, env)
}

// SealGroup seals a group message for one recipient using this peer's identity
// as the carrier — used when answering a gossip pull (we forward on the author's
// behalf).
func (p *Peer) SealGroup(gm GroupMessage, recipient string, recipientDH [32]byte) (GroupEnvelope, error) {
	return SealGroupMessage(p.id, gm, recipient, recipientDH)
}

const groupSyncContext = "group-sync"

// GroupSyncRequest is a gossip pull: "for group GroupID I already hold these
// message ids and this roster epoch; send me any messages I'm missing and a
// newer roster if you have one." It is signed so the responder can confirm the
// requester is a roster member (and so only members trigger the re-sealing
// work). No live nonce is needed — a replay is idempotent and the response is
// sealed for the requester, so it helps no one else. HaveEpoch is inside the
// signed blob so a courier can't strip it to trick the responder into re-sending
// (or withholding) a roster.
type GroupSyncRequest struct {
	GroupID   string   `json:"group_id"`
	Sender    string   `json:"sender"`
	Have      []string `json:"have"`       // message ids the sender already holds for this group
	HaveEpoch uint64   `json:"have_epoch"` // roster epoch the sender currently holds
	Sig       []byte   `json:"sig"`
}

func groupSyncSignBlob(groupID, sender string, have []string, haveEpoch uint64) []byte {
	sorted := append([]string(nil), have...)
	sort.Strings(sorted)
	h := sha256.New()
	for _, id := range sorted {
		h.Write([]byte(id))
		h.Write([]byte{0})
	}
	var ep [8]byte
	binary.BigEndian.PutUint64(ep[:], haveEpoch)
	return signBlob(sigContextFor(protoVerCurrent), []byte(groupSyncContext), []byte(groupID), []byte(sender), h.Sum(nil), ep[:])
}

// SignGroupSync signs a pull request as id.
func SignGroupSync(id *identity.Identity, groupID string, have []string, haveEpoch uint64) []byte {
	return ed25519.Sign(id.Keys.Signing.Private, groupSyncSignBlob(groupID, id.AccountNumber(), have, haveEpoch))
}

// Verify checks the requester's signature. The caller still gates on roster
// membership — the signature only proves who is asking.
func (r GroupSyncRequest) Verify() bool {
	senderEd, err := identity.AccountNumberFromString(r.Sender)
	if err != nil {
		return false
	}
	return ed25519.Verify(senderEd, groupSyncSignBlob(r.GroupID, r.Sender, r.Have, r.HaveEpoch), r.Sig)
}

// NewGroupMessage builds and signs a group message authored by id. An optional
// replyID marks it as a reply to that group message (variadic so the many plain
// callers stay unchanged); an empty replyID is treated as no reply.
func NewGroupMessage(id *identity.Identity, groupID, text string, at time.Time, replyID ...string) (GroupMessage, error) {
	if len(text) == 0 {
		return GroupMessage{}, fmt.Errorf("empty message")
	}
	if len(text) > maxPlaintext {
		return GroupMessage{}, fmt.Errorf("message too long (max %d bytes)", maxPlaintext)
	}
	if groupID == "" {
		return GroupMessage{}, fmt.Errorf("missing group id")
	}
	m := GroupMessage{GroupID: groupID, Author: id.AccountNumber(), At: at.UTC(), Text: text}
	if len(replyID) > 0 {
		m.ReplyID = replyID[0]
	}
	m.Sig = ed25519.Sign(id.Keys.Signing.Private, m.signingBlob())
	return m, nil
}

// NewGroupImageMessage builds and signs a group IMAGE message: an inline blurry
// thumbnail plus the metadata to fetch the full image on demand. The full image's
// BYTES are not carried here — only its content hash (fullHash), which is signed
// so a later fetch can be verified against it. thumbMime/fullMime must be
// allowlisted image types; fullHash must be sha256 (32 bytes) of the full image.
func NewGroupImageMessage(id *identity.Identity, groupID string, thumb []byte, thumbMime, fullID string, fullHash []byte, fullMime string, fullSize int, at time.Time) (GroupMessage, error) {
	if groupID == "" {
		return GroupMessage{}, fmt.Errorf("missing group id")
	}
	if len(thumb) == 0 || len(thumb) > MaxGroupThumbBytes {
		return GroupMessage{}, fmt.Errorf("thumbnail size out of range")
	}
	if fullID == "" || len(fullHash) != 32 || fullSize <= 0 || fullSize > MaxAttachmentBytes {
		return GroupMessage{}, fmt.Errorf("bad full-image metadata")
	}
	if !allowedImageMIME[thumbMime] || !allowedImageMIME[fullMime] {
		return GroupMessage{}, fmt.Errorf("unsupported image type")
	}
	m := GroupMessage{
		GroupID: groupID, Author: id.AccountNumber(), At: at.UTC(),
		Thumb: thumb, ThumbMime: thumbMime, FullID: fullID, FullHash: fullHash, FullMime: fullMime, FullSize: fullSize,
	}
	m.Sig = ed25519.Sign(id.Keys.Signing.Private, m.signingBlob())
	return m, nil
}

// GroupEnvelope carries a GroupMessage to one member. The entire signed message
// is encrypted inside Box under the directional key between the CARRIER (the
// immediate sender — the author, or any member forwarding on their behalf) and
// the recipient, so a hop reveals nothing about the group, the author, or the
// content to anyone but the recipient. The recipient decrypts, then verifies the
// inner author signature. Re-sealing for the next member produces a fresh Box
// with a new carrier key while the inner author signature rides along unchanged.
type GroupEnvelope struct {
	Recipient    string `json:"recipient"`
	Carrier      string `json:"carrier"`        // immediate sender: author or a forwarding member
	CarrierDHPub []byte `json:"carrier_dh_pub"` // carrier's X25519 key, to derive the box key
	Box          []byte `json:"box"`            // XChaCha20-Poly1305 sealed groupMsgWire
}

// groupMsgWire is the exact serialized form sealed inside a GroupEnvelope.Box.
// At is carried as unix-nanos (not time.Time) so the bytes are canonical across
// marshal round-trips and match what signingBlob hashes.
type groupMsgWire struct {
	GroupID string `json:"g"`
	Author  string `json:"a"`
	AtNanos int64  `json:"t"`
	Text    string `json:"x,omitempty"`
	ReplyID string `json:"ri,omitempty"` // reply target; omitempty keeps a non-reply wire form unchanged
	Sig     []byte `json:"s"`
	// Image fields, all omitempty so a text message's wire form is unchanged.
	Thumb     []byte `json:"th,omitempty"`
	ThumbMime string `json:"tm,omitempty"`
	FullID    string `json:"fi,omitempty"`
	FullHash  []byte `json:"fh,omitempty"`
	FullMime  string `json:"fm,omitempty"`
	FullSize  int    `json:"fs,omitempty"`
}

// SealGroupMessage encrypts a signed group message for one recipient, from the
// carrier's identity. carrier is the author when first sending and any relaying
// member when forwarding — either way the recipient decrypts with the carrier's
// key and verifies the (unchanged) inner author signature. recipientDH is the
// recipient's X25519 key, taken from the group roster.
func SealGroupMessage(carrier *identity.Identity, gm GroupMessage, recipient string, recipientDH [32]byte) (GroupEnvelope, error) {
	if _, err := identity.AccountNumberFromString(recipient); err != nil {
		return GroupEnvelope{}, fmt.Errorf("bad recipient: %w", err)
	}
	if gm.isImage() {
		if len(gm.Thumb) == 0 || len(gm.Thumb) > MaxGroupThumbBytes {
			return GroupEnvelope{}, fmt.Errorf("bad thumbnail length")
		}
	} else if len(gm.Text) == 0 || len(gm.Text) > maxPlaintext {
		return GroupEnvelope{}, fmt.Errorf("bad message length")
	}
	carrierAcct := carrier.AccountNumber()
	wire, err := json.Marshal(groupMsgWire{
		GroupID: gm.GroupID, Author: gm.Author, AtNanos: gm.At.UnixNano(), Text: gm.Text, ReplyID: gm.ReplyID, Sig: gm.Sig,
		Thumb: gm.Thumb, ThumbMime: gm.ThumbMime, FullID: gm.FullID, FullHash: gm.FullHash, FullMime: gm.FullMime, FullSize: gm.FullSize,
	})
	if err != nil {
		return GroupEnvelope{}, err
	}
	shared, err := crypto.SharedSecret(carrier.Keys.DH.Private, recipientDH)
	if err != nil {
		return GroupEnvelope{}, err
	}
	key := crypto.DeriveDirectionalKey(shared, msgKeyInfo(carrierAcct, recipient))
	box, err := crypto.SealMessage(key, wire, aad(carrierAcct, recipient))
	if err != nil {
		return GroupEnvelope{}, err
	}
	dh := carrier.Keys.DH.Public
	return GroupEnvelope{Recipient: recipient, Carrier: carrierAcct, CarrierDHPub: dh[:], Box: box}, nil
}

// OpenGroupEnvelope decrypts an envelope addressed to id and returns the inner
// group message, having verified the author signature. It does NOT check roster
// membership — the caller decides whether Author (and the carrier) belong to the
// group, exactly as direct/mailbox opens leave contact gating to the caller.
func OpenGroupEnvelope(id *identity.Identity, env GroupEnvelope) (GroupMessage, error) {
	if env.Recipient != id.AccountNumber() {
		return GroupMessage{}, fmt.Errorf("recipient mismatch")
	}
	if _, err := identity.AccountNumberFromString(env.Carrier); err != nil {
		return GroupMessage{}, fmt.Errorf("bad carrier account: %w", err)
	}
	if len(env.CarrierDHPub) != 32 {
		return GroupMessage{}, fmt.Errorf("bad carrier dh key length")
	}
	var carrierDH [32]byte
	copy(carrierDH[:], env.CarrierDHPub)
	shared, err := crypto.SharedSecret(id.Keys.DH.Private, carrierDH)
	if err != nil {
		return GroupMessage{}, err
	}
	key := crypto.DeriveDirectionalKey(shared, msgKeyInfo(env.Carrier, id.AccountNumber()))
	pt, err := crypto.OpenMessage(key, env.Box, aad(env.Carrier, id.AccountNumber()))
	if err != nil {
		return GroupMessage{}, err
	}
	// Generous guard against unmarshaling absurd input; the true limit is on the
	// text itself, checked after decode so a max-length message (whose JSON
	// wrapper + base64 signature exceed maxPlaintext) still round-trips exactly
	// like a 1:1 message at the ceiling.
	if len(pt) > 4*maxPlaintext {
		return GroupMessage{}, fmt.Errorf("message too large")
	}
	var w groupMsgWire
	if err := json.Unmarshal(pt, &w); err != nil {
		return GroupMessage{}, fmt.Errorf("bad group message: %w", err)
	}
	gm := GroupMessage{
		GroupID: w.GroupID, Author: w.Author, At: time.Unix(0, w.AtNanos).UTC(), Text: w.Text, ReplyID: w.ReplyID, Sig: w.Sig,
		Thumb: w.Thumb, ThumbMime: w.ThumbMime, FullID: w.FullID, FullHash: w.FullHash, FullMime: w.FullMime, FullSize: w.FullSize,
	}
	// Enforce the caps + allowlist ON OPEN (the carrier/author is untrusted), the
	// same discipline as the mailbox image path.
	if gm.isImage() {
		if len(gm.Thumb) == 0 || len(gm.Thumb) > MaxGroupThumbBytes {
			return GroupMessage{}, fmt.Errorf("bad thumbnail")
		}
		if len(gm.FullHash) != 32 || gm.FullSize <= 0 || gm.FullSize > MaxAttachmentBytes {
			return GroupMessage{}, fmt.Errorf("bad full-image metadata")
		}
		if !allowedImageMIME[gm.ThumbMime] || !allowedImageMIME[gm.FullMime] {
			return GroupMessage{}, fmt.Errorf("unsupported image type")
		}
	} else if len(w.Text) > maxPlaintext {
		return GroupMessage{}, fmt.Errorf("message too large")
	}
	if !gm.Verify() {
		return GroupMessage{}, fmt.Errorf("author signature verification failed")
	}
	return gm, nil
}
