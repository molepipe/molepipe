// Package protocol implements the peer-to-peer exchanges that run over Tor
// between two identities: profile lookup, friend requests, and messaging.
//
// Dialing an onion authenticates the recipient (their Ed25519 identity) but
// never the caller, so every request that asserts an identity is signed by the
// caller's Ed25519 key and bound to a fresh one-time challenge nonce issued by
// the recipient. Messages are additionally encrypted (X25519 ECDH →
// XChaCha20-Poly1305).
//
// v2 introduces X3DH session establishment with signed prekeys and Double
// Ratchet message encryption. v1 static-X25519 encryption is retained as a
// fallback for peers that haven't upgraded yet. The challenge endpoint's
// Ver field (unsigned at v1) is folded into the signed challenge at v2 so
// downgrade attacks cannot force a v1 session on a v2-capable peer.
package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/molepipe/molepipe/backend/internal/crypto"
	"github.com/molepipe/molepipe/backend/internal/identity"
)

const (
	sigContext = "onion-chat/v1"

	// Protocol version negotiation. sigContext is the v1 signature domain; it is
	// ALSO the KDF domain in msgKeyInfo, which is deliberately NOT versioned (see
	// the note there). protoVerMin..protoVerCurrent is the inclusive range of wire
	// versions this build speaks. Every signature routes its domain bytes through
	// sigContextFor(v) so a future build can verify a peer under the version that
	// peer used; today the only version is 1. See sigContextFor.
	protoVerMin     uint16 = 1
	protoVerCurrent uint16 = 2

	nonceLen = 32
	nonceTTL = 5 * time.Minute
	// maxNonces caps the live challenge jar. /p2p/challenge is unauthenticated
	// and reachable by anyone on Tor, and each call stores a nonce for nonceTTL;
	// pruneLocked only drops EXPIRED entries, so without a ceiling a sustained
	// flood grows the jar to (rate x nonceTTL) — an uncapped memory-exhaustion
	// vector, the same class the /sync body cap and maxPublicInFlight guard.
	// At the cap we evict the oldest outstanding nonce, so a legitimate peer's
	// fresh challenge always succeeds (an attacker's stale nonces are what get
	// dropped; a peer whose nonce was evicted mid-handshake simply re-fetches).
	maxNonces = 4096
	// helloSkew bounds how far a profile hello's timestamp may sit from our clock,
	// in EITHER direction. A hello is self-stamped — there is no server-issued
	// nonce, which is exactly what keeps it free (see ServeProfileHello) — so
	// freshness is the only thing stopping an old stamp being replayed forever,
	// and a future-dated stamp is just as replayable as a stale one. Matches
	// nonceTTL: the same freshness window the gated handshake already uses.
	helloSkew = 5 * time.Minute
	// maxHellos caps the seen-hello jar, for the reason maxNonces caps the
	// challenge jar: /p2p/profile is unauthenticated and reachable by anyone on
	// Tor. Only VERIFIED hellos take a slot (see ServeProfileHello's check order),
	// so filling this needs a signature that checks out — but a contact gone bad
	// should still not be able to grow it without bound.
	maxHellos     = 4096
	maxPlaintext  = 16 * 1024 // 16 KiB per message (v1)
	maxNameRunes  = 64        // attacker-controlled; cap before storing/displaying
	maxMailboxLen = 256       // attacker-controlled mailbox address; cap before caching
	// maxAvatarHashLen bounds the avatar hash carried in the public card. It is a
	// sha256 hex digest (64 chars); anything longer is attacker junk we never act
	// on. "" means "no avatar".
	maxAvatarHashLen = 64

	// Peer-facing endpoints served on the onion listener.
	ChallengePath         = "/p2p/challenge"
	MessagePath           = "/p2p/message"
	ProfilePath           = "/p2p/profile"
	FriendRequestPath     = "/p2p/friend-request"
	FriendAcceptPath      = "/p2p/friend-accept"
	DeleteMessagePath     = "/p2p/delete-message"
	GroupMessagePath      = "/p2p/group-message"
	GroupReactPath        = "/p2p/group-react"
	GroupSyncPath         = "/p2p/group-sync"
	GroupRosterPath       = "/p2p/group-roster"
	GroupInvitePath       = "/p2p/group-invite"
	GroupInviteAcceptPath = "/p2p/group-invite-accept"
	AttachmentPath        = "/p2p/attachment"
	// ContactProfilePath serves operational profile fields kept OUT of the public
	// card (currently the mailbox URL) only to an accepted contact who proves
	// their identity against a fresh challenge nonce.
	ContactProfilePath = "/p2p/contact-profile"
	// AvatarPath serves avatar image bytes by content hash. Ungated (a stranger
	// deciding whether to add you benefits from seeing your face), but the card
	// carries only the hash so this is fetched at most once per distinct image.
	AvatarPath = "/p2p/avatar"
	// PrekeyBundlePath serves the v2 prekey bundle for session establishment.
	// Gated to accepted contacts — a stranger must not learn our prekeys.
	PrekeyBundlePath = "/p2p/prekey-bundle"
	// RatchetInitPath receives the FIRST v2 message of a session: an
	// InitialRatchetEnvelope carrying the X3DH handshake (ephemeral key, prekey
	// IDs) alongside the ratchet header and ciphertext, so the responder can
	// establish the session before decrypting. Separate from RatchetMessagePath so
	// each route decodes exactly one concrete type (the repo does no union-sniffing).
	RatchetInitPath = "/p2p/ratchet-init"
	// RatchetMessagePath receives every subsequent v2 message of an ESTABLISHED
	// session: a plain RatchetEnvelope (ratchet header + ciphertext, no X3DH).
	RatchetMessagePath = "/p2p/ratchet-message"
)

// RatchetHeader is the v2 message header carrying ratchet state for Double
// Ratchet decryption. It is included in v2 Envelopes and authenticated as
// associated data (not encrypted).
type RatchetHeader struct {
	RatchetPub   []byte `json:"rp"` // sender's current ratchet public key
	PrevChainLen uint32 `json:"pn"` // number of messages in previous sending chain
	MsgNum       uint32 `json:"mn"` // message number in current sending chain
}

// HeaderBytes returns the canonical byte encoding of the header for AAD.
func (h *RatchetHeader) HeaderBytes() []byte {
	return signParts(
		h.RatchetPub,
		u32Bytes(h.PrevChainLen),
		u32Bytes(h.MsgNum),
	)
}

// u32Bytes encodes a uint32 as 4 big-endian bytes.
func u32Bytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// signParts length-prefixes each part to prevent ambiguity.
func signParts(parts ...[]byte) []byte {
	var b []byte
	var l [4]byte
	for _, part := range parts {
		binary.BigEndian.PutUint32(l[:], uint32(len(part)))
		b = append(b, l[:]...)
		b = append(b, part...)
	}
	return b
}

// Challenge is the recipient's reply to a challenge request.
type Challenge struct {
	Nonce []byte `json:"nonce"`
	DHPub []byte `json:"dh_pub"` // recipient's X25519 public key
	Sig   []byte `json:"sig"`    // Sign(recipient_Ed, ctx‖"challenge"‖recipient_acct‖dh_pub)
	// Ver advertises the responder's maximum wire version so the caller can
	// negotiate before signing. Advisory and UNSIGNED at v1 (absent ⇒ v1), which
	// is exactly why introducing it needs no flag-day; the v2 handshake folds the
	// advertised max into the signed challenge so a downgrade can't be forced.
	Ver uint16 `json:"ver,omitempty"`
}

// Profile is an identity's public, self-signed card (served ungated).
//
// It carries only what a stranger needs to identify and encrypt to us: account,
// name, DH key, and — for recognition at add-time — the hash of our avatar. Our
// mailbox URL is operational metadata that used to live here; it moved to the
// contact-gated ContactProfilePath so a stranger holding our account number can
// no longer learn which relay we use. The avatar BYTES are not here (they'd bloat
// every presence poll); only the hash is, and AvatarPath serves the bytes.
type Profile struct {
	Account     string `json:"account"`
	DisplayName string `json:"display_name"`
	DHPub       []byte `json:"dh_pub"`                // our X25519 public key, so senders can encrypt offline mail
	AvatarHash  string `json:"avatar_hash,omitempty"` // sha256 hex of our avatar image ("" = none)
	Sig         []byte `json:"sig"`                   // Sign(Ed, ctx‖"profile"‖account‖display_name‖dh_pub‖avatar_hash)
	// Ver is the wire version this card was signed under. The card is ungated and
	// self-signed with no handshake, so a verifier treats Ver as a HINT (try it
	// first, fall back across supported versions) — never as a hard selector, or
	// a flipped byte would deny a valid card. Advisory/unsigned at v1 (absent ⇒ v1).
	Ver uint16 `json:"ver,omitempty"`
}

// ContactProfileRequest asks an accepted contact's onion for the operational
// profile fields kept out of the public card (currently the mailbox URL). Bound
// to a one-time challenge nonce like a message, so a captured request can't be
// replayed to pull the mailbox, and to the recipient account so it can't be
// redirected at another onion.
type ContactProfileRequest struct {
	From  string `json:"from"`
	Nonce []byte `json:"nonce"`
	Sig   []byte `json:"sig"` // Sign(from_Ed, ctx‖"contact-profile"‖nonce‖recipient)
}

// ContactProfile is the gated response to a ContactProfileRequest.
type ContactProfile struct {
	MailboxURL string `json:"mailbox_url"` // "" if we have none, or the requester isn't an accepted contact
}

// PrekeyBundleRequest asks an accepted contact's onion for a v2 prekey bundle
// to establish a Double Ratchet session. Gated like ContactProfileRequest: a
// stranger must not learn our prekeys or drain our one-time-prekey pool, so the
// request is bound to a fresh challenge nonce and the recipient account and
// signed by the caller's identity key. Fetching a bundle consumes a one-time
// prekey, which is exactly why it must be gated to real contacts.
type PrekeyBundleRequest struct {
	From  string `json:"from"`
	Nonce []byte `json:"nonce"`
	Sig   []byte `json:"sig"` // Sign(from_Ed, ctx‖"prekey-bundle"‖nonce‖recipient)
}

// PrekeyBundleSigningBlob is the signed bytes for a PrekeyBundleRequest.
func PrekeyBundleSigningBlob(nonce []byte, recipient string) []byte {
	return signBlob(sigContextFor(protoVerCurrent), []byte("prekey-bundle"), nonce, []byte(recipient))
}

// HelloSigningBlob is the blob a presence hello signs: the caller's timestamp
// bound to the recipient account they are addressing.
//
// Binding the recipient is what stops a hello being lifted and replayed to a
// DIFFERENT contact. Without it, any contact of ours could take the hello we sent
// them and present it to another contact to fake our presence there; with it, the
// only party who can replay our hello to someone is the party we sent it to,
// which is self-deception and buys an attacker nothing. Same reason the gated
// requests bind their recipient (see ServeContactProfile).
//
// Exported so the client, the handler and the golden vectors all build it the
// same way.
func HelloSigningBlob(ts int64, recipient string) []byte {
	var stamp [8]byte
	binary.BigEndian.PutUint64(stamp[:], uint64(ts))
	return signBlob(sigContextFor(protoVerCurrent), []byte("profile-hello"), stamp[:], []byte(recipient))
}

// FriendRequest asks an identity to become a contact.
type FriendRequest struct {
	From     string `json:"from"`      // requester's account
	FromName string `json:"from_name"` // requester's display name
	ReqID    string `json:"req_id"`    // ties this request to its future accept
	Nonce    []byte `json:"nonce"`     // recipient's challenge nonce
	Sig      []byte `json:"sig"`       // Sign(from_Ed, ctx‖"friend-request"‖nonce‖recipient‖from_name‖req_id)
	// InviteToken is the one-time invite code's secret, carried when the requester
	// added us via a single-use code (see chatstore.Data.InviteToken). It is
	// DELIBERATELY NOT in the signed blob above: the request already rides an
	// authenticated onion connection to our own service and consumeNonce bounds
	// replay, so signing it buys nothing — and appending it to the blob would
	// break signature verification for every not-yet-rebuilt peer (including the
	// desktop) even when the field is empty. An unknown-field-tolerant decode
	// means old peers simply omit it and keep verifying. Empty when the requester
	// used a bare account number rather than a one-time code.
	InviteToken string `json:"invite_token,omitempty"`
}

// FriendAccept confirms a friend request; echoes the request's ReqID.
type FriendAccept struct {
	From     string `json:"from"`      // accepter's account
	FromName string `json:"from_name"` // accepter's display name
	ReqID    string `json:"req_id"`    // must equal the original request's id
	Nonce    []byte `json:"nonce"`
	Sig      []byte `json:"sig"` // Sign(from_Ed, ctx‖"friend-accept"‖nonce‖recipient‖from_name‖req_id)
}

// Envelope is a sent message.
type Envelope struct {
	Sender      string `json:"sender"`
	SenderDHPub []byte `json:"sender_dh_pub"`
	Nonce       []byte `json:"nonce"`
	Sig         []byte `json:"sig"` // Sign(sender_Ed, ctx‖"message"‖nonce‖recipient‖sender_dh_pub)
	Box         []byte `json:"box"` // XChaCha20-Poly1305 nonce‖ciphertext
}

// RatchetEnvelope is a v2 message on an ESTABLISHED session (posted to
// RatchetMessagePath). The RatchetHeader is authenticated by the envelope
// signature (not encrypted); replay/ordering are handled by the ratchet
// counters, so unlike the v1 Envelope it carries no challenge nonce.
type RatchetEnvelope struct {
	Sender  string        `json:"sender"`
	Ratchet RatchetHeader `json:"ratchet"`
	Sig     []byte        `json:"sig"` // Sign(sender_Ed, ctx‖"ratchet-msg"‖sender‖recipient‖ratchet_header_bytes)
	Box     []byte        `json:"box"` // XChaCha20-Poly1305 nonce‖ciphertext
}

// X3DHInit carries the initiator's half of an X3DH handshake. It rides the
// FIRST v2 message (InitialRatchetEnvelope) so the responder can derive the
// shared secret and stand up its session. IdentityDHPub is the initiator's
// X25519 identity key (id.Keys.DH.Public): the envelope signature binds it to
// the sender's Ed account, and the responder additionally cross-checks it
// against the DH key it already holds for that contact.
type X3DHInit struct {
	EphemeralPub    []byte  `json:"ek"`            // initiator's one-shot X25519 ephemeral public
	IdentityDHPub   []byte  `json:"ik"`            // initiator's X25519 identity public
	SignedPrekeyID  uint32  `json:"spk"`           // which of the responder's signed prekeys was used
	OneTimePrekeyID *uint32 `json:"opk,omitempty"` // which one-time prekey, if any (nil = none available)
}

// InitialRatchetEnvelope is the FIRST v2 message of a session (posted to
// RatchetInitPath): the X3DH handshake plus the ratchet header and ciphertext
// of the initiator's first message. Once the responder establishes from it,
// both sides use plain RatchetEnvelopes on RatchetMessagePath.
type InitialRatchetEnvelope struct {
	Sender  string        `json:"sender"`
	Init    X3DHInit      `json:"init"`
	Ratchet RatchetHeader `json:"ratchet"`
	Sig     []byte        `json:"sig"` // Sign(sender_Ed, ctx‖"ratchet-init"‖sender‖recipient‖init_bytes‖ratchet_header_bytes)
	Box     []byte        `json:"box"` // XChaCha20-Poly1305 nonce‖ciphertext
}

// initBytes is the canonical, length-prefixed byte encoding of the X3DH init
// fields for signing. The one-time prekey ID is encoded as a presence flag plus
// its value so "no OTP" and "OTP id 0" never collide.
func (x *X3DHInit) initBytes() []byte {
	var otpFlag byte
	var otpID uint32
	if x.OneTimePrekeyID != nil {
		otpFlag = 1
		otpID = *x.OneTimePrekeyID
	}
	return signParts(
		x.EphemeralPub,
		x.IdentityDHPub,
		u32Bytes(x.SignedPrekeyID),
		[]byte{otpFlag},
		u32Bytes(otpID),
	)
}

// Hooks let the receiving Peer consult and mutate the API's trust state without
// owning it. All are called only after the relevant signature is verified.
type Hooks struct {
	// DisplayName returns our current display name (for our profile).
	DisplayName func() string
	// AvatarHash returns the sha256 hex of our current avatar image ("" = none).
	// Rides in the public card so a stranger can preview our face at add-time.
	AvatarHash func() string
	// ContactMailbox returns our mailbox URL to disclose to `sender`, or "" unless
	// sender is an accepted contact. Called by ServeContactProfile only AFTER the
	// request's nonce and signature are verified, so a forged caller reaches a
	// read-only status check and never our mailbox.
	ContactMailbox func(sender string) string
	// OnPeerOnline reports that `sender` dialed us just now, carrying a verified
	// presence hello. Called by ServeProfileHello only AFTER the stamp's freshness
	// and signature are verified; the implementation still owns the trust decision
	// (gate on an accepted contact — a verified signature proves who is calling,
	// not that we want to track them).
	OnPeerOnline func(sender string)
	// AllowMessage gates an inbound message by sender status and may upgrade a
	// pending_out contact to accepted. Called AFTER signature verification, so a
	// forged sender can never change trust state.
	AllowMessage func(sender string) bool
	// Deliver receives a decrypted message from an allowed sender. msgID is the
	// sender-assigned wire ID, shared by both sides — empty for legacy messages
	// sent before payloads carried one. reply carries reply-with-context (zero for
	// a non-reply); its peer-supplied preview/author are already clamped.
	Deliver func(sender, msgID, text string, reply Reply)
	// OnFriendRequest records an inbound request (caps/dedupes pending_in). The
	// inviteToken is the one-time invite code's secret when the requester added us
	// via a single-use code, else "" — the hook enforces/burns it. dialedAccount is
	// the account of OURS the requester dialed (the matched recipient of the signed
	// request) — an alias of ours if they redeemed a rotated code — so the hook can
	// record which of our accounts this contact knows us by (Contact.MyAccountKnown).
	OnFriendRequest func(fromAccount, fromName, reqID, inviteToken, dialedAccount string) error
	// OnFriendAccept accepts iff we have a matching pending_out with this reqID.
	OnFriendAccept func(fromAccount, fromName, reqID string) error
	// OnRelayRequest records an inbound request to relay for this contact.
	OnRelayRequest func(fromAccount, reqID string) error
	// OnRelayAccept applies a relay accept iff we have a matching outbound reqID.
	OnRelayAccept func(fromAccount, reqID string) error
	// OnDeleteMessage removes one message the sender previously sent us. The
	// implementation MUST confirm the message was actually inbound from this
	// sender: the signature only proves who is asking, not what they are
	// entitled to delete.
	OnDeleteMessage func(fromAccount, messageID string) error
	// OnReaction adds or removes one emoji reaction the sender placed on a message
	// in OUR conversation with them. Like OnDeleteMessage the signature proves only
	// WHO is asking; the implementation MUST confirm the target message actually
	// belongs to a conversation with this sender (either direction), so a peer can
	// only react to messages between the two of us.
	OnReaction func(fromAccount, messageID, emoji string, remove bool) error
	// OnGroupInvite records an inbound invitation to join a group. The signature
	// proves the inviter's identity; the implementation decides whether to keep it
	// (caps/dedupes like a friend request).
	OnGroupInvite func(groupID, groupName, inviter, inviterName, reqID string) error
	// OnGroupInviteAccept applies an invitee's acceptance: it carries their DHPub
	// (needed to seal group traffic to them) and echoes the reqID of the invite we
	// sent. The implementation MUST confirm it matches an invite we actually
	// issued before adding them, and add them to the roster on success.
	OnGroupInviteAccept func(groupID, from, fromName string, dhPub []byte, reqID string) error
	// OnAddressRotation applies a verified address rotation for an existing contact.
	// contactAccount is the identity the CHANNEL authenticated (the ratchet
	// session's account, or the contact whose cached DHPub matched a mailbox seal) —
	// NOT any account carried in the rotation payload. The implementation MUST
	// enforce the monotonic-index guard (reject aliasIndex <= the stored
	// Contact.AliasIndex) and migrate the contact's onion to newOnion atomically.
	// Called only after the channel has authenticated the sender.
	OnAddressRotation func(contactAccount, newOnion string, aliasIndex uint32) error
	// OnAddressRotationAck records that `contactAccount` (the identity the ratchet
	// session authenticated) has applied our rotation to alias `ackedIndex`, so the
	// rotator can stop resending and advance the account this contact now knows us
	// by. Like OnAddressRotation, the acking identity is the CHANNEL, never a
	// payload field. Called only after the channel has authenticated the sender.
	OnAddressRotationAck func(contactAccount string, ackedIndex uint32) error
}

// Peer is the receiving side for one unlocked identity.
type Peer struct {
	id    *identity.Identity
	hooks Hooks

	mu     sync.Mutex
	nonces map[string]time.Time

	// hellos remembers the signatures of presence hellos already accepted, until
	// they fall outside helloSkew. It is the replay half of the hello guard: the
	// window bounds how long a captured stamp is valid at all, this stops it being
	// reused inside the window. Guarded by mu, like nonces.
	hellos map[string]time.Time

	// sessionMgr manages Double Ratchet sessions for v2 peers. When nil,
	// the peer falls back to v1 static X25519 encryption. The session
	// manager is injected via SetSessionManager.
	sessionMgr SessionManager

	// localAliases are the live self-alias onion accounts we are currently
	// reachable at BEYOND the primary account (p.id.AccountNumber()), during a
	// rotation grace window. An un-updated contact signs and AAD-binds a message to
	// whichever account they dialed us by (their alias-of-us), so the receive path
	// must recognise any live account, not just the primary. Empty (the default)
	// means only the primary is live and behaviour is identical to pre-rotation.
	// Guarded by mu; set via SetLocalAliasAccounts.
	localAliases []string
}

// SessionManager is the interface the protocol layer uses to interact with
// ratchet sessions. This decouples the protocol package from the session
// package (which imports crypto).
type SessionManager interface {
	// GetOrCreateSession returns an existing session or creates a new one.
	GetOrCreateSession(account string) (RatchetSession, error)
	// SaveSession persists the current session state.
	SaveSession(account string) error
}

// RatchetSession is the interface for a ratchet session. This decouples the
// protocol package from the crypto package's concrete RatchetSession type.
type RatchetSession interface {
	// Encrypt encrypts plaintext using the ratchet. Returns the encrypted
	// message and the ratchet header for the receiver.
	Encrypt(plaintext, aad []byte) (ciphertext []byte, header RatchetHeader, err error)
	// Decrypt decrypts ciphertext using the ratchet. Returns the plaintext.
	Decrypt(ciphertext []byte, header RatchetHeader, aad []byte) (plaintext []byte, err error)
	// IsEstablished reports whether the session has completed initial key agreement.
	IsEstablished() bool
}

// NewPeer builds a receiver wired to the given hooks.
func NewPeer(id *identity.Identity, hooks Hooks) *Peer {
	return &Peer{id: id, hooks: hooks, nonces: map[string]time.Time{}, hellos: map[string]time.Time{}}
}

// SetSessionManager injects the session manager for v2 ratchet support.
// When nil (the default), the peer falls back to v1 static encryption.
func (p *Peer) SetSessionManager(sm SessionManager) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sessionMgr = sm
}

func (p *Peer) account() string { return p.id.AccountNumber() }

// SetLocalAliasAccounts declares the live self-alias onion accounts this peer is
// currently reachable at, beyond its primary account, so the receive path can
// recognise a message an un-updated contact addressed to an alias-of-us during a
// rotation grace window. Passing nil (the default) restores primary-only matching.
// The rotation orchestrator calls this when an alias service starts or stops.
func (p *Peer) SetLocalAliasAccounts(accounts []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.localAliases = append([]string(nil), accounts...)
}

// recipientCandidates returns the accounts a sender might have addressed us by —
// our primary account first, then any live alias. Primary-first keeps the common
// (no-rotation) case a single comparison.
func (p *Peer) recipientCandidates() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, 1+len(p.localAliases))
	out = append(out, p.id.AccountNumber())
	out = append(out, p.localAliases...)
	return out
}

// matchRecipientAccount finds which of our live accounts a sender signed an
// established-session message to, by trying each candidate against the signature.
// The signing blob binds the recipient, so at most one candidate can verify — that
// is the account the sender dialed, and the one whose AAD will open the box. It
// returns ("", false) when none verify (a forged or misaddressed message). The
// cost is one ed25519 verify per live account (one in the common no-rotation case,
// a small handful during a grace window).
func (p *Peer) matchRecipientAccount(senderEd ed25519.PublicKey, sender string, headerBytes, sig []byte) (string, bool) {
	for _, r := range p.recipientCandidates() {
		if ed25519.Verify(senderEd, RatchetMsgSigningBlob(sender, r, headerBytes), sig) {
			return r, true
		}
	}
	return "", false
}

// matchRecipientBlob is the static-verb counterpart of matchRecipientAccount: for
// a request whose signing blob binds the recipient account, it tries each live
// account (primary + aliases) through blobFor and returns the one whose blob the
// signature verifies. At most one can match (the blob binds the recipient), so the
// matched account is the one the sender dialed — used both to accept a message an
// un-updated contact addressed to an alias-of-us during grace and, for the v1
// message path, to derive the symmetric key/AAD under that same account. Returns
// ("", false) when none verify (forged or misaddressed).
func (p *Peer) matchRecipientBlob(senderEd ed25519.PublicKey, sig []byte, blobFor func(recipient string) []byte) (string, bool) {
	for _, r := range p.recipientCandidates() {
		if ed25519.Verify(senderEd, blobFor(r), sig) {
			return r, true
		}
	}
	return "", false
}

// Challenge issues a fresh challenge signed as our primary account. It is the
// default (no-rotation) responder path; ChallengeAs is the rotation-aware form.
func (p *Peer) Challenge() Challenge {
	return p.ChallengeAs(p.account(), p.id.Keys.Signing.Private)
}

// ChallengeAs issues a fresh challenge (nonce + our signed X25519 key) that
// self-identifies as the dialed recipient account, signed with that account's
// private key. During a rotation grace window a request arriving on an alias-of-us
// must answer AS that alias: the client derives our verifying key from the account
// it dialed (an onion IS an ed25519 pubkey), so a challenge signed with the primary
// key over the alias account would fail verification and leak the primary account.
// The X25519 DH key is the stable m/0'/1' key and does NOT rotate — it is the
// durable identity anchor and is the same across every alias by design.
func (p *Peer) ChallengeAs(recipient string, signPriv ed25519.PrivateKey) Challenge {
	nonce := make([]byte, nonceLen)
	_, _ = rand.Read(nonce)
	p.mu.Lock()
	p.pruneLocked()
	p.evictOldestLocked()
	p.nonces[string(nonce)] = time.Now().Add(nonceTTL)
	p.mu.Unlock()

	dh := p.id.Keys.DH.Public
	sig := ed25519.Sign(signPriv,
		signBlob(sigContextFor(protoVerCurrent), []byte("challenge"), []byte(recipient), dh[:]))
	return Challenge{Nonce: nonce, DHPub: dh[:], Sig: sig, Ver: protoVerCurrent}
}

// ProfileCard returns our public signed profile as our primary account. It is the
// default (no-rotation) responder path; ProfileCardAs is the rotation-aware form.
func (p *Peer) ProfileCard() Profile {
	return p.ProfileCardAs(p.account(), p.id.Keys.Signing.Private)
}

// ProfileCardAs returns our public signed profile presenting the dialed recipient
// account, signed with that account's private key — the respond-as-alias form of
// ProfileCard (see ChallengeAs for why the responding account must match the dialed
// onion). The mailbox is deliberately NOT here — it is served to accepted contacts
// only, via ServeContactProfile. NOTE: the DHPub is the stable m/0'/1' key, constant
// across all aliases; serving it here still lets an unaccepted caller who dials two
// different aliases-of-us correlate them by the shared DHPub. Re-signing closes the
// account-string leak, not that correlation channel (a Phase-F/G follow-up).
func (p *Peer) ProfileCardAs(recipient string, signPriv ed25519.PrivateKey) Profile {
	name := clampName(p.hooks.DisplayName())
	avatar := clampAvatarHash(hookOr(p.hooks.AvatarHash))
	dh := p.id.Keys.DH.Public
	sig := ed25519.Sign(signPriv,
		signBlob(sigContextFor(protoVerCurrent), []byte("profile"), []byte(recipient), []byte(name), dh[:], []byte(avatar)))
	return Profile{Account: recipient, DisplayName: name, DHPub: dh[:], AvatarHash: avatar, Sig: sig, Ver: protoVerCurrent}
}

// ServeContactProfile verifies a contact-profile request (one-time nonce + the
// caller's signature over it) and returns the operational fields the hook is
// willing to disclose to that caller. The hook (ContactMailbox) is what enforces
// the accepted-contact gate; this method only proves WHO is asking. Order mirrors
// Receive: consume nonce → verify signature → gate (in the hook) → return.
func (p *Peer) ServeContactProfile(req ContactProfileRequest) (ContactProfile, error) {
	if !p.consumeNonce(req.Nonce) {
		return ContactProfile{}, fmt.Errorf("unknown or expired challenge nonce")
	}
	senderEd, err := identity.AccountNumberFromString(req.From)
	if err != nil {
		return ContactProfile{}, fmt.Errorf("bad sender account: %w", err)
	}
	if _, ok := p.matchRecipientBlob(senderEd, req.Sig, func(r string) []byte {
		return signBlob(sigContextFor(protoVerCurrent), []byte("contact-profile"), req.Nonce, []byte(r))
	}); !ok {
		return ContactProfile{}, fmt.Errorf("signature verification failed")
	}
	// "" unless the hook considers req.From an accepted contact.
	mailbox := clampMailbox(hookOrArg(p.hooks.ContactMailbox, req.From))
	return ContactProfile{MailboxURL: mailbox}, nil
}

// ServeProfileHello verifies a self-stamped "I am online" hello riding the public
// profile GET and, if it checks out, tells the hook that sender is reachable now.
//
// Why this exists: dialing out needs only Dialable, never our own published
// descriptor (see tor.OnionService), and publishing is the slow half — minutes on
// a phone. So a device whose onion is still publishing can announce itself to a
// contact long before that contact could possibly find it by dialing. The stamp
// rides a GET the presence sweep already makes, so it costs no extra round trip.
//
// Returns whether the hello was accepted, but the caller MUST serve the identical
// profile card either way (see handleP2PProfile). The card is public; a response
// that varied with the stamp would turn this endpoint into an oracle for who our
// contacts are.
//
// Checks run freshness -> signature -> replay, the reverse of the gated paths
// (ServeContactProfile consumes its nonce first). There the nonce jar is cheap to
// consult and is the thing under flood pressure; here there is no server-issued
// nonce to consume, and recording an UNVERIFIED stamp would let anyone on Tor
// fill the jar. So the cheap structural checks reject junk, the signature proves
// the sender, and only then does a stamp take a slot.
func (p *Peer) ServeProfileHello(from string, ts int64, sig []byte) bool {
	if from == "" || len(sig) != ed25519.SignatureSize {
		return false
	}
	skew := int64(helloSkew / time.Second)
	now := time.Now().Unix()
	if ts < now-skew || ts > now+skew {
		return false
	}
	senderEd, err := identity.AccountNumberFromString(from)
	if err != nil {
		return false
	}
	// matchRecipientBlob tries the primary and every live alias-of-us, so a hello
	// addressed to an alias we are still reachable at verifies during a rotation
	// grace window — the same tolerance the gated requests get.
	if _, ok := p.matchRecipientBlob(senderEd, sig, func(r string) []byte {
		return HelloSigningBlob(ts, r)
	}); !ok {
		return false
	}
	if !p.recordHello(sig) {
		return false
	}
	if p.hooks.OnPeerOnline != nil {
		p.hooks.OnPeerOnline(from)
	}
	return true
}

// recordHello reports whether sig is a hello we have not already accepted inside
// the freshness window, remembering it if so.
//
// At the cap it DROPS rather than evicting, unlike the nonce jar: evicting a
// remembered hello would re-open it to replay for the rest of its window, while
// dropping costs only a presence upgrade, deferred to the next sweep or settled
// by our own outbound probe. Losing a little latency beats losing the guard.
func (p *Peer) recordHello(sig []byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for seen, exp := range p.hellos {
		if now.After(exp) {
			delete(p.hellos, seen)
		}
	}
	if _, seen := p.hellos[string(sig)]; seen {
		return false
	}
	if len(p.hellos) >= maxHellos {
		return false
	}
	p.hellos[string(sig)] = now.Add(helloSkew)
	return true
}

// ServePrekeyBundle verifies a prekey-bundle request (one-time nonce + the
// caller's signature over it), gates on the caller being an accepted contact,
// and returns a freshly built bundle. Order mirrors ServeContactProfile: consume
// nonce → verify signature → gate → build. `build` consumes a one-time prekey,
// so it runs only after the gate — a stranger can never drain the pool.
func (p *Peer) ServePrekeyBundle(req PrekeyBundleRequest, isAccepted func(string) bool, build func() (crypto.PrekeyBundle, error)) (crypto.PrekeyBundle, error) {
	if !p.consumeNonce(req.Nonce) {
		return crypto.PrekeyBundle{}, fmt.Errorf("unknown or expired challenge nonce")
	}
	senderEd, err := identity.AccountNumberFromString(req.From)
	if err != nil {
		return crypto.PrekeyBundle{}, fmt.Errorf("bad sender account: %w", err)
	}
	if _, ok := p.matchRecipientBlob(senderEd, req.Sig, func(r string) []byte {
		return PrekeyBundleSigningBlob(req.Nonce, r)
	}); !ok {
		return crypto.PrekeyBundle{}, fmt.Errorf("signature verification failed")
	}
	if !isAccepted(req.From) {
		return crypto.PrekeyBundle{}, fmt.Errorf("not an accepted contact")
	}
	return build()
}

// Receive verifies and decrypts an incoming message, delivering it on success.
// Order: consume nonce → verify signature → status gate → decrypt → deliver, so
// an unauthenticated sender can neither be delivered nor mutate trust state.
func (p *Peer) Receive(e Envelope) error {
	if !p.consumeNonce(e.Nonce) {
		return fmt.Errorf("unknown or expired challenge nonce")
	}
	senderEd, err := identity.AccountNumberFromString(e.Sender)
	if err != nil {
		return fmt.Errorf("bad sender account: %w", err)
	}
	if len(e.SenderDHPub) != 32 {
		return fmt.Errorf("bad sender dh key length")
	}
	// The sender signed and AAD-bound this v1 message to whichever of our accounts
	// they dialed (primary, or an alias-of-us during a grace window). Discover which
	// from the signature so the key derivation and AAD below use the SAME account.
	recipient, ok := p.matchRecipientBlob(senderEd, e.Sig, func(r string) []byte {
		return signBlob(sigContextFor(protoVerCurrent), []byte("message"), e.Nonce, []byte(r), e.SenderDHPub)
	})
	if !ok {
		return fmt.Errorf("signature verification failed")
	}
	if !p.hooks.AllowMessage(e.Sender) {
		return fmt.Errorf("sender is not an accepted contact")
	}

	var theirDH [32]byte
	copy(theirDH[:], e.SenderDHPub)
	shared, err := crypto.SharedSecret(p.id.Keys.DH.Private, theirDH)
	if err != nil {
		return err
	}
	key := crypto.DeriveDirectionalKey(shared, msgKeyInfo(e.Sender, recipient))
	pt, err := crypto.OpenMessage(key, e.Box, aad(e.Sender, recipient))
	if err != nil {
		return err
	}
	if len(pt) > maxPlaintext {
		return fmt.Errorf("message too large")
	}
	msgID, text, reply := DecodePayloadFull(pt)
	p.hooks.Deliver(e.Sender, msgID, text, reply)
	return nil
}

// ReceiveRatchet verifies and decrypts an incoming v2 ratchet message.
// This is the v2 counterpart of Receive, using Double Ratchet decryption.
func (p *Peer) ReceiveRatchet(e RatchetEnvelope, sessionMgr SessionManager) error {
	// Verify the signature: sign(sender_Ed, ctx‖"message‖v2"‖sender‖ratchet_header_bytes)
	senderEd, err := identity.AccountNumberFromString(e.Sender)
	if err != nil {
		return fmt.Errorf("bad sender account: %w", err)
	}
	headerBytes := e.Ratchet.HeaderBytes()
	// The sender signed and AAD-bound this message to whichever of our accounts they
	// dialed (the primary, or an alias-of-us during a grace window). Discover which
	// from the signature so the AAD below matches; a message to none of our live
	// accounts is forged or misaddressed and rejected.
	recipient, ok := p.matchRecipientAccount(senderEd, e.Sender, headerBytes, e.Sig)
	if !ok {
		return fmt.Errorf("signature verification failed")
	}
	if !p.hooks.AllowMessage(e.Sender) {
		return fmt.Errorf("sender is not an accepted contact")
	}

	// Get or create session for this sender
	if sessionMgr == nil {
		return fmt.Errorf("v2 message received but no session manager available")
	}
	session, err := sessionMgr.GetOrCreateSession(e.Sender)
	if err != nil {
		return fmt.Errorf("get session: %w", err)
	}

	// The AAD binds the message to sender and the recipient account matched above.
	aadBytes := aad(e.Sender, recipient)

	// Decrypt with ratchet
	pt, err := session.Decrypt(e.Box, e.Ratchet, aadBytes)
	if err != nil {
		return fmt.Errorf("ratchet decrypt: %w", err)
	}
	if len(pt) > maxPlaintext {
		return fmt.Errorf("message too large")
	}

	// The ratchet has advanced on decrypt; persist that state regardless of what
	// the payload turns out to be, so a redelivery of this same message doesn't
	// desync the chain.
	_ = sessionMgr.SaveSession(e.Sender)

	// Address rotation rides the established (OLD-alias) session: the sender's
	// identity is the CHANNEL (e.Sender, already AllowMessage-gated above), never
	// a field in the payload. Dispatch it BEFORE the text path so a rotation is
	// never mis-decoded as an empty message into the thread.
	if r, ok := DecodeRotationPayload(pt); ok {
		if p.hooks.OnAddressRotation == nil {
			return fmt.Errorf("address rotation received but no rotation hook installed")
		}
		return p.hooks.OnAddressRotation(e.Sender, r.NewOnion, r.AliasIndex)
	}

	// A rotation ack rides the same session back to us (the rotator). Dispatch it
	// before the text path so it is never mis-decoded as an empty thread message.
	if ackIdx, ok := DecodeRotationAckPayload(pt); ok {
		if p.hooks.OnAddressRotationAck == nil {
			return fmt.Errorf("rotation ack received but no ack hook installed")
		}
		return p.hooks.OnAddressRotationAck(e.Sender, ackIdx)
	}

	msgID, text, reply := DecodePayloadFull(pt)
	p.hooks.Deliver(e.Sender, msgID, text, reply)

	return nil
}

// ReceiveFriendRequest verifies an inbound friend request and records it.
func (p *Peer) ReceiveFriendRequest(r FriendRequest) error {
	if !p.consumeNonce(r.Nonce) {
		return fmt.Errorf("unknown or expired challenge nonce")
	}
	fromEd, err := identity.AccountNumberFromString(r.From)
	if err != nil {
		return fmt.Errorf("bad account: %w", err)
	}
	dialed, ok := p.matchRecipientBlob(fromEd, r.Sig, func(rcpt string) []byte {
		return signBlob(sigContextFor(protoVerCurrent), []byte("friend-request"), r.Nonce,
			[]byte(rcpt), []byte(r.FromName), []byte(r.ReqID))
	})
	if !ok {
		return fmt.Errorf("signature verification failed")
	}
	return p.hooks.OnFriendRequest(r.From, clampName(r.FromName), r.ReqID, r.InviteToken, dialed)
}

// ReceiveFriendAccept verifies an inbound accept and applies it.
func (p *Peer) ReceiveFriendAccept(a FriendAccept) error {
	if !p.consumeNonce(a.Nonce) {
		return fmt.Errorf("unknown or expired challenge nonce")
	}
	fromEd, err := identity.AccountNumberFromString(a.From)
	if err != nil {
		return fmt.Errorf("bad account: %w", err)
	}
	if _, ok := p.matchRecipientBlob(fromEd, a.Sig, func(rcpt string) []byte {
		return signBlob(sigContextFor(protoVerCurrent), []byte("friend-accept"), a.Nonce,
			[]byte(rcpt), []byte(a.FromName), []byte(a.ReqID))
	}); !ok {
		return fmt.Errorf("signature verification failed")
	}
	return p.hooks.OnFriendAccept(a.From, clampName(a.FromName), a.ReqID)
}

func (p *Peer) consumeNonce(nonce []byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked()
	exp, ok := p.nonces[string(nonce)]
	if !ok || time.Now().After(exp) {
		return false
	}
	delete(p.nonces, string(nonce))
	return true
}

func (p *Peer) pruneLocked() {
	now := time.Now()
	for n, exp := range p.nonces {
		if now.After(exp) {
			delete(p.nonces, n)
		}
	}
}

// evictOldestLocked keeps the jar within maxNonces by dropping the
// soonest-to-expire (i.e. oldest-issued, since every nonce shares nonceTTL)
// entries until there is room for one more. Normally a no-op; it only bites
// under a challenge flood, where it bounds the jar's memory to ~maxNonces.
func (p *Peer) evictOldestLocked() {
	for len(p.nonces) >= maxNonces {
		var oldestKey string
		var oldestExp time.Time
		first := true
		for n, exp := range p.nonces {
			if first || exp.Before(oldestExp) {
				oldestKey, oldestExp, first = n, exp, false
			}
		}
		delete(p.nonces, oldestKey)
	}
}

// sigContextFor returns the signature-domain bytes for a negotiated protocol
// version. It is the first length-prefixed part of every signed blob, so these
// bytes are load-bearing: v1 MUST return exactly sigContext ("onion-chat/v1")
// byte for byte, or a v>=2 build can no longer verify a v1 peer. The commit that
// introduces v2 (a signed-layout change) adds a case here; a build that speaks
// both can then verify either peer by recomputing under the version it used.
func sigContextFor(v uint16) []byte {
	switch v {
	case 1:
		return []byte(sigContext)
	case 2:
		// v2 signature domain, RESERVED. protoVerCurrent is still 1, so neither
		// negotiateVersion nor candidateVersions ever yields 2 in production —
		// this case is unreachable outside the cross-version tests, which use it
		// (and the frozen golden vector for it) to prove that a v2-signed blob is
		// genuinely distinct from a v1 one and that a v1-only verifier rejects it.
		// The commit that ships a real v2 layout raises protoVerCurrent to make it
		// reachable; the domain string is locked now so it cannot drift silently.
		return []byte("onion-chat/v2")
	default:
		// Unreachable once version negotiation (which rejects out-of-range
		// versions up front) lands; kept total so callers never receive nil.
		return []byte(sigContext)
	}
}

// versionSupported reports whether v is a wire version this build speaks.
func versionSupported(v uint16) bool {
	return v >= protoVerMin && v <= protoVerCurrent
}

// legacyVer is what an absent advisory Ver means: a build predating the field,
// i.e. v1 — NOT "whatever our floor happens to be." The distinction is invisible
// today (floor == 1) but load-bearing later: once protoVerMin rises above 1
// (dropping v1 support), a Ver-less peer IS a v1 peer and must be rejected, not
// silently promoted to the floor and handed a version it cannot speak.
const legacyVer uint16 = 1

// negotiate picks the highest version both peers speak, given the other side's
// advertised maximum and our own [ourMin,ourMax] window. A peer that advertises
// 0 — the advisory Ver field absent from an older build's JSON — is read as
// speaking legacyVer (v1). It errors when there is no overlap: the peer's
// maximum sits below our floor, i.e. the peer predates everything we still
// speak. Taking the bounds as arguments (rather than the package consts) keeps
// the reject path testable while protoVerMin == protoVerCurrent == 1, when no
// real advertisement can trip it.
func negotiate(theirMax, ourMin, ourMax uint16) (uint16, error) {
	if theirMax == 0 {
		theirMax = legacyVer
	}
	if theirMax < ourMin {
		return 0, fmt.Errorf("peer protocol version %d below our minimum %d", theirMax, ourMin)
	}
	if theirMax > ourMax {
		return ourMax, nil
	}
	return theirMax, nil
}

// negotiateVersion clamps a peer's advertised maximum to this build's window.
// This is the choke point that turns an unsupported peer into a clean, uniform
// error at handshake time instead of an opaque signature failure later.
func negotiateVersion(theirMax uint16) (uint16, error) {
	return negotiate(theirMax, protoVerMin, protoVerCurrent)
}

// candidateVersions lists the supported wire versions to try, in order, when
// verifying an object whose stamped version is a HINT rather than a negotiated
// fact (a self-signed card carries no handshake to pin it). The hinted version
// goes first when we support it, then the rest highest-first, so a correct hint
// is the fast path and a wrong or absent one still resolves by fallback — a
// flipped Ver on a v1 card must never cause a spurious reject.
func candidateVersions(hint uint16) []uint16 {
	out := make([]uint16, 0, int(protoVerCurrent-protoVerMin)+1)
	if versionSupported(hint) {
		out = append(out, hint)
	}
	for v := protoVerCurrent; v >= protoVerMin; v-- {
		if v != hint {
			out = append(out, v)
		}
		if v == protoVerMin {
			break // guard uint16 underflow when protoVerMin == 0
		}
	}
	return out
}

// RatchetMsgSigningBlob is the signed bytes for an established-session v2 message
// (RatchetEnvelope). It binds sender, recipient, and the ratchet header under a
// domain distinct from v1 "message" so a signature can never be reused across
// protocols. Exported so the api orchestrator signs/verifies identically.
func RatchetMsgSigningBlob(sender, recipient string, headerBytes []byte) []byte {
	return signBlob(sigContextFor(protoVerCurrent), []byte("ratchet-msg"),
		[]byte(sender), []byte(recipient), headerBytes)
}

// RatchetInitSigningBlob is the signed bytes for the first v2 message
// (InitialRatchetEnvelope). It additionally binds the X3DH init fields (which
// carry the initiator's ephemeral and identity keys and the prekey IDs), so a
// tampered handshake breaks the signature.
func RatchetInitSigningBlob(sender, recipient string, init X3DHInit, headerBytes []byte) []byte {
	return signBlob(sigContextFor(protoVerCurrent), []byte("ratchet-init"),
		[]byte(sender), []byte(recipient), init.initBytes(), headerBytes)
}

// RatchetAAD is the AEAD associated data binding a v2 message to its sender and
// recipient. Exported so the api send/establish paths derive the exact bytes the
// receive path (aad) uses; a mismatch would make every message fail to open.
func RatchetAAD(sender, recipient string) []byte {
	return aad(sender, recipient)
}

// signBlob length-prefixes each part so distinct field sequences can never
// collide into the same signed bytes.
func signBlob(parts ...[]byte) []byte {
	var b []byte
	var l [4]byte
	for _, part := range parts {
		binary.BigEndian.PutUint32(l[:], uint32(len(part)))
		b = append(b, l[:]...)
		b = append(b, part...)
	}
	return b
}

// clampName bounds an attacker-controlled display name.
func clampName(s string) string {
	r := []rune(s)
	if len(r) > maxNameRunes {
		r = r[:maxNameRunes]
	}
	return string(r)
}

// clampMailbox bounds an attacker-controlled mailbox address. A peer's profile
// is signed but still peer-supplied, so cap its length before we cache it.
func clampMailbox(s string) string {
	if len(s) > maxMailboxLen {
		return s[:maxMailboxLen]
	}
	return s
}

// clampAvatarHash bounds an attacker-controlled avatar hash from a peer's card.
// It is meant to be a sha256 hex digest; anything longer is junk we truncate
// before caching or using it in a fetch URL.
func clampAvatarHash(s string) string {
	if len(s) > maxAvatarHashLen {
		return s[:maxAvatarHashLen]
	}
	return s
}

// hookOr calls an optional hook, returning "" if it isn't wired.
func hookOr(f func() string) string {
	if f == nil {
		return ""
	}
	return f()
}

// hookOrArg calls an optional one-argument hook, returning "" if it isn't wired.
func hookOrArg(f func(string) string, arg string) string {
	if f == nil {
		return ""
	}
	return f(arg)
}

// msgKeyInfo is the HKDF info string for the directional message key. It uses
// the bare sigContext ON PURPOSE and must NOT be routed through sigContextFor:
// this is an ENCRYPTION-key derivation domain, not a signature domain. Changing
// it with the protocol version would change every derived key and break
// decryption of already-stored offline mail — a data-migration concern (beta
// item #4), not wire-version tolerance. Leave it pinned to v1.
func msgKeyInfo(sender, receiver string) string {
	return sigContext + " msg " + sender + "->" + receiver
}

func aad(sender, receiver string) []byte {
	return []byte(sender + "|" + receiver)
}
