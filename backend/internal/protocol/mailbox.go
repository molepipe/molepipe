package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/molepipe/molepipe/backend/internal/crypto"
	"github.com/molepipe/molepipe/backend/internal/identity"
)

// mailContext is the signing label for store-and-forward mailbox messages. It is
// deliberately DISTINCT from the direct-message label ("message"): the signed
// bytes must never collide across the two paths, or a captured direct message
// could be replayed as a valid mailbox drop-off (or vice versa). signBlob is
// length-prefixed, so only the label needs to differ for the paths to be disjoint.
const mailContext = "mailbox-message"

// MailEnvelope is a message left at a recipient's mailbox for later pickup, used
// when the recipient can't be reached directly. Unlike Envelope, it binds no
// live challenge nonce — the recipient issues none, because they're offline when
// it's sent. It is therefore self-authenticating (the sender's signature is
// verified on pickup) and its replay protection comes from ID(): a replayed
// drop-off has identical bytes, hence an identical ID, and collapses on ingest
// instead of duplicating. The encrypted Box uses the same directional-key crypto
// as a direct message, so only the outer authenticator differs.
type MailEnvelope struct {
	Recipient   string `json:"recipient"`     // account this mail is addressed to
	Sender      string `json:"sender"`        // sender's account
	SenderDHPub []byte `json:"sender_dh_pub"` // sender's X25519 public key
	SentAt      int64  `json:"sent_at"`       // unix seconds; preserves ordering on pickup
	Box         []byte `json:"box"`           // XChaCha20-Poly1305 nonce‖ciphertext
	Sig         []byte `json:"sig"`           // Sign(sender_Ed, ctx‖"mailbox-message"‖recipient‖sender_dh‖sent_at‖box)
}

// idBlob is the length-prefixed content hashed into ID(). ID() is a STORAGE KEY
// and replay-dedup key (relay/mailbox DropOff, mailboxloop delivered-set), not a
// signature — so its domain is PINNED to v1 forever, exactly like msgKeyInfo's
// KDF domain. If it tracked protoVerCurrent, a v2 build would compute a different
// ID for the same logical message: stored mail would become unfindable and a
// re-delivery would dedup as new. Only signingBlob (the authenticator) is allowed
// to become version-aware.
func (m MailEnvelope) idBlob() []byte {
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(m.SentAt))
	return signBlob(sigContextFor(1), []byte(mailContext), []byte(m.Recipient), []byte(m.Sender), m.SenderDHPub, ts[:], m.Box)
}

// signingBlob is what the sender signs (and the recipient verifies). It omits
// Sender because that is recovered from m.Sender and pins the verifying key, so
// tampering with the sender changes which key must verify.
func (m MailEnvelope) signingBlob() []byte {
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(m.SentAt))
	return signBlob(sigContextFor(protoVerCurrent), []byte(mailContext), []byte(m.Recipient), m.SenderDHPub, ts[:], m.Box)
}

// ID is the deterministic content hash used to key storage and de-duplicate
// replays. Identical bytes ⇒ identical ID ⇒ one stored message.
func (m MailEnvelope) ID() string {
	sum := sha256.Sum256(m.idBlob())
	return hex.EncodeToString(sum[:16])
}

// Mailbox account-authenticated operation labels. The account owner signs a
// server-issued nonce with their identity key to prove ownership for these ops.
const (
	MailboxOpCheckin = "mailbox-checkin"
	MailboxOpPickup  = "mailbox-pickup"
	MailboxOpDelete  = "mailbox-delete"
	MailboxOpForget  = "mailbox-forget"
	// Backup (bak- class) operations: the owner storing durable group-image
	// backups in its OWN mailbox. Distinct labels keep a backup signature from
	// ever being replayable as a message operation.
	MailboxOpBackupDropoff = "mailbox-backup-dropoff"
	MailboxOpBackupPickup  = "mailbox-backup-pickup"
	MailboxOpBackupPurge   = "mailbox-backup-purge"
	// Scalable restore path: list the backup ids/sizes, then fetch missing ones by
	// id one at a time. The whole-set BackupPickup cannot carry a realistic byte
	// budget in a single response, so restore uses list + per-id fetch instead.
	MailboxOpBackupList  = "mailbox-backup-list"
	MailboxOpBackupFetch = "mailbox-backup-fetch"
)

// MailboxBackupBinding is the op-specific extra bound into the auth signature for
// a backup drop-off: the stable blob id the client chose plus the requested byte
// budget. Binding both stops a captured drop-off from being re-aimed at a
// different id or budget. Returned as separate []byte extras to spread into
// MailboxAuthBlob.
func MailboxBackupBinding(id string, budget int64) [][]byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(budget))
	return [][]byte{[]byte(id), b[:]}
}

// MailboxBackupFetchBinding binds the single blob id a by-id backup fetch requests,
// so a captured fetch cannot be re-aimed at a different id. (List needs no extra —
// it returns only ids and sizes for the authenticated owner's own account.)
func MailboxBackupFetchBinding(id string) [][]byte {
	return [][]byte{[]byte(id)}
}

// MailboxAuthBlob builds the exact bytes an account owner signs (and the mailbox
// verifies) to authorize an operation. Shared by client and server so the two
// always agree. extra binds any op-specific arguments (e.g. the ids to delete).
func MailboxAuthBlob(op string, nonce []byte, account string, extra ...[]byte) []byte {
	parts := [][]byte{sigContextFor(protoVerCurrent), []byte(op), nonce, []byte(account)}
	parts = append(parts, extra...)
	return signBlob(parts...)
}

// VerifySignature checks a mailbox envelope's signature WITHOUT decrypting it, so
// the mailbox server can reject forged/garbage drop-offs (and bind a drop-off to
// a real sender key) while remaining unable to read the contents.
func (m MailEnvelope) VerifySignature() bool {
	senderEd, err := identity.AccountNumberFromString(m.Sender)
	if err != nil || len(m.SenderDHPub) != 32 {
		return false
	}
	if _, err := identity.AccountNumberFromString(m.Recipient); err != nil {
		return false
	}
	return ed25519.Verify(senderEd, m.signingBlob(), m.Sig)
}

// OpenMail verifies and decrypts a mailbox/relay envelope addressed to this peer,
// without exposing the identity to the caller.
func (p *Peer) OpenMail(m MailEnvelope) (sender, msgID, text string, sentAt time.Time, err error) {
	return OpenMailEnvelope(p.id, m)
}

// OpenMailContent is the full-content counterpart of OpenMail: it also returns
// the reply context (and image fields). The relay path uses it so a reply sent
// while the recipient was offline keeps its quote.
func (p *Peer) OpenMailContent(m MailEnvelope) (MailContent, error) {
	return OpenMailContent(p.id, m)
}

// SealMailEnvelope encrypts and signs a mailbox message for recipient, using the
// recipient's X25519 key (which the sender must have cached from a prior online
// profile exchange — there is no live handshake for an offline recipient). An
// optional Reply attaches reply-with-context.
func SealMailEnvelope(id *identity.Identity, recipient string, recipientDH [32]byte, msgID, text string, sentAt time.Time, reply ...Reply) (MailEnvelope, error) {
	if len(text) == 0 {
		return MailEnvelope{}, fmt.Errorf("empty message")
	}
	if len(text) > maxPlaintext {
		return MailEnvelope{}, fmt.Errorf("message too long (max %d bytes)", maxPlaintext)
	}
	if _, err := identity.AccountNumberFromString(recipient); err != nil {
		return MailEnvelope{}, fmt.Errorf("bad recipient: %w", err)
	}
	sender := id.AccountNumber()
	shared, err := crypto.SharedSecret(id.Keys.DH.Private, recipientDH)
	if err != nil {
		return MailEnvelope{}, err
	}
	key := crypto.DeriveDirectionalKey(shared, msgKeyInfo(sender, recipient))
	box, err := crypto.SealMessage(key, EncodePayload(msgID, text, reply...), aad(sender, recipient))
	if err != nil {
		return MailEnvelope{}, err
	}
	myDH := id.Keys.DH.Public
	m := MailEnvelope{Recipient: recipient, Sender: sender, SenderDHPub: myDH[:], SentAt: sentAt.Unix(), Box: box}
	m.Sig = ed25519.Sign(id.Keys.Signing.Private, m.signingBlob())
	return m, nil
}

// SealMailImageEnvelope is the image counterpart of SealMailEnvelope: it seals an
// image for an OFFLINE recipient's mailbox. It enforces the same size cap and
// MIME allowlist as the direct attachment path (ReceiveAttachment), so a bad
// image never goes on the wire; the recipient re-checks both on open. The bytes
// live inside the AEAD, so the mailbox operator stores only opaque ciphertext.
func SealMailImageEnvelope(id *identity.Identity, recipient string, recipientDH [32]byte, msgID, mime string, data []byte, sentAt time.Time) (MailEnvelope, error) {
	if len(data) == 0 || len(data) > MaxAttachmentBytes {
		return MailEnvelope{}, fmt.Errorf("attachment size out of range")
	}
	if !allowedImageMIME[mime] {
		return MailEnvelope{}, fmt.Errorf("unsupported image type")
	}
	if _, err := identity.AccountNumberFromString(recipient); err != nil {
		return MailEnvelope{}, fmt.Errorf("bad recipient: %w", err)
	}
	sender := id.AccountNumber()
	shared, err := crypto.SharedSecret(id.Keys.DH.Private, recipientDH)
	if err != nil {
		return MailEnvelope{}, err
	}
	key := crypto.DeriveDirectionalKey(shared, msgKeyInfo(sender, recipient))
	box, err := crypto.SealMessage(key, EncodeImagePayload(msgID, mime, data), aad(sender, recipient))
	if err != nil {
		return MailEnvelope{}, err
	}
	myDH := id.Keys.DH.Public
	m := MailEnvelope{Recipient: recipient, Sender: sender, SenderDHPub: myDH[:], SentAt: sentAt.Unix(), Box: box}
	m.Sig = ed25519.Sign(id.Keys.Signing.Private, m.signingBlob())
	return m, nil
}

// SealSelfBackupImage seals a group image as a durable backup addressed to the
// owner's OWN mailbox: recipient == sender == the caller. It produces an ordinary
// MailEnvelope (so it round-trips through the same VerifySignature / openMailBox
// path), decryptable only by the owner's own devices — the shared secret is
// SharedSecret(myDH.Private, myDH.Public), which only the owner's key can rederive.
// The mailbox operator stores opaque ciphertext exactly as for a forwarded image.
func SealSelfBackupImage(id *identity.Identity, msgID, mime string, data []byte, sentAt time.Time) (MailEnvelope, error) {
	self := id.AccountNumber()
	return SealMailImageEnvelope(id, self, id.Keys.DH.Public, msgID, mime, data, sentAt)
}

// openMailBox does the shared recipient-check, signature-verify and decrypt for
// a picked-up mail envelope, returning the sealed plaintext. It applies NO
// contact gating and NO payload interpretation — those are the caller's job.
func openMailBox(id *identity.Identity, m MailEnvelope) ([]byte, error) {
	if m.Recipient != id.AccountNumber() {
		return nil, fmt.Errorf("recipient mismatch")
	}
	senderEd, err := identity.AccountNumberFromString(m.Sender)
	if err != nil {
		return nil, fmt.Errorf("bad sender account: %w", err)
	}
	if len(m.SenderDHPub) != 32 {
		return nil, fmt.Errorf("bad sender dh key length")
	}
	if !ed25519.Verify(senderEd, m.signingBlob(), m.Sig) {
		return nil, fmt.Errorf("signature verification failed")
	}
	var theirDH [32]byte
	copy(theirDH[:], m.SenderDHPub)
	shared, err := crypto.SharedSecret(id.Keys.DH.Private, theirDH)
	if err != nil {
		return nil, err
	}
	key := crypto.DeriveDirectionalKey(shared, msgKeyInfo(m.Sender, m.Recipient))
	return crypto.OpenMessage(key, m.Box, aad(m.Sender, m.Recipient))
}

// OpenMailEnvelope verifies a picked-up mailbox message and decrypts it as TEXT.
// It does NOT apply contact gating — the caller decides whether to accept the
// sender, exactly as with a direct message. An image payload is refused here, so
// the friend-relay path (which opens envelopes through this) can never deliver an
// image: images travel only to a recipient's OWN chosen mailbox, never a friend's
// relay. Use OpenMailContent to accept both.
func OpenMailEnvelope(id *identity.Identity, m MailEnvelope) (sender, msgID, text string, sentAt time.Time, err error) {
	c, err := OpenMailContent(id, m)
	if err != nil {
		return "", "", "", time.Time{}, err
	}
	if c.Kind == MailKindImage {
		return "", "", "", time.Time{}, fmt.Errorf("image payload not accepted on the text path")
	}
	return c.Sender, c.MsgID, c.Text, c.SentAt, nil
}

// MailContent is a decrypted mail envelope's content, interpreting text vs image.
type MailContent struct {
	Sender string
	MsgID  string
	Kind   string // "" for text, MailKindImage for an image
	Text   string
	Mime   string
	Data   []byte
	Reply  Reply // reply-with-context; zero for a non-reply (text only)
	SentAt time.Time
}

// OpenMailContent verifies, decrypts and interprets a picked-up mail envelope,
// returning either text or an image. The image size cap and MIME allowlist are
// enforced HERE, on open: the sender is untrusted, so the checks cannot live only
// at seal time (the same reason ReceiveAttachment re-checks on the direct path).
func OpenMailContent(id *identity.Identity, m MailEnvelope) (MailContent, error) {
	pt, err := openMailBox(id, m)
	if err != nil {
		return MailContent{}, err
	}
	if p, ok := decodePayload(pt); ok && p.Kind == MailKindImage {
		if len(p.Data) == 0 || len(p.Data) > MaxAttachmentBytes {
			return MailContent{}, fmt.Errorf("mailbox image size out of range")
		}
		if len(p.Mime) > maxMimeLen || !allowedImageMIME[p.Mime] {
			return MailContent{}, fmt.Errorf("unsupported image type")
		}
		return MailContent{Sender: m.Sender, MsgID: p.ID, Kind: MailKindImage, Mime: p.Mime, Data: p.Data, SentAt: time.Unix(m.SentAt, 0)}, nil
	}
	// Text (or a legacy bare-text plaintext). Bound size as before.
	if len(pt) > maxPlaintext {
		return MailContent{}, fmt.Errorf("message too large")
	}
	msgID, text, reply := DecodePayloadFull(pt)
	return MailContent{Sender: m.Sender, MsgID: msgID, Text: text, Reply: reply, SentAt: time.Unix(m.SentAt, 0)}, nil
}
