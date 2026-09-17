// Package protocol implements the peer-to-peer exchanges that run over Tor
// between two identities: profile lookup, friend requests, and messaging.
//
// Dialing an onion authenticates the recipient (their Ed25519 identity) but
// never the caller, so every request that asserts an identity is signed by the
// caller's Ed25519 key and bound to a fresh one-time challenge nonce issued by
// the recipient. Messages are additionally encrypted (X25519 ECDH →
// XChaCha20-Poly1305).
//
// SECURITY NOTE — No application-layer forward secrecy: the protocol uses
// static X25519 keys derived from the BIP39 seed. If either party's DH private
// key is compromised, ALL past and future messages between them can be decrypted.
// Tor's rendezvous circuit provides transport-layer forward secrecy, but this
// does not protect against key compromise at the application layer. A future
// version should implement X3DH or a Double Ratchet extension to achieve
// application-layer forward secrecy.
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
	protoVerCurrent uint16 = 1

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
	maxNonces     = 4096
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
)

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

// FriendRequest asks an identity to become a contact.
type FriendRequest struct {
	From     string `json:"from"`      // requester's account
	FromName string `json:"from_name"` // requester's display name
	ReqID    string `json:"req_id"`    // ties this request to its future accept
	Nonce    []byte `json:"nonce"`     // recipient's challenge nonce
	Sig      []byte `json:"sig"`       // Sign(from_Ed, ctx‖"friend-request"‖nonce‖recipient‖from_name‖req_id)
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
	// AllowMessage gates an inbound message by sender status and may upgrade a
	// pending_out contact to accepted. Called AFTER signature verification, so a
	// forged sender can never change trust state.
	AllowMessage func(sender string) bool
	// Deliver receives a decrypted message from an allowed sender. msgID is the
	// sender-assigned wire ID, shared by both sides — empty for legacy messages
	// sent before payloads carried one. reply carries reply-with-context (zero for
	// a non-reply); its peer-supplied preview/author are already clamped.
	Deliver func(sender, msgID, text string, reply Reply)
	// OnFriendRequest records an inbound request (caps/dedupes pending_in).
	OnFriendRequest func(fromAccount, fromName, reqID string) error
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
}

// Peer is the receiving side for one unlocked identity.
type Peer struct {
	id    *identity.Identity
	hooks Hooks

	mu     sync.Mutex
	nonces map[string]time.Time
}

// NewPeer builds a receiver wired to the given hooks.
func NewPeer(id *identity.Identity, hooks Hooks) *Peer {
	return &Peer{id: id, hooks: hooks, nonces: map[string]time.Time{}}
}

func (p *Peer) account() string { return p.id.AccountNumber() }

// Challenge issues a fresh challenge (nonce + our signed X25519 key).
func (p *Peer) Challenge() Challenge {
	nonce := make([]byte, nonceLen)
	_, _ = rand.Read(nonce)
	p.mu.Lock()
	p.pruneLocked()
	p.evictOldestLocked()
	p.nonces[string(nonce)] = time.Now().Add(nonceTTL)
	p.mu.Unlock()

	dh := p.id.Keys.DH.Public
	sig := ed25519.Sign(p.id.Keys.Signing.Private,
		signBlob(sigContextFor(protoVerCurrent), []byte("challenge"), []byte(p.account()), dh[:]))
	return Challenge{Nonce: nonce, DHPub: dh[:], Sig: sig, Ver: protoVerCurrent}
}

// ProfileCard returns our public signed profile. The mailbox is deliberately NOT
// here — it is served to accepted contacts only, via ServeContactProfile.
func (p *Peer) ProfileCard() Profile {
	name := clampName(p.hooks.DisplayName())
	avatar := clampAvatarHash(hookOr(p.hooks.AvatarHash))
	acct := p.account()
	dh := p.id.Keys.DH.Public
	sig := ed25519.Sign(p.id.Keys.Signing.Private,
		signBlob(sigContextFor(protoVerCurrent), []byte("profile"), []byte(acct), []byte(name), dh[:], []byte(avatar)))
	return Profile{Account: acct, DisplayName: name, DHPub: dh[:], AvatarHash: avatar, Sig: sig, Ver: protoVerCurrent}
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
	blob := signBlob(sigContextFor(protoVerCurrent), []byte("contact-profile"), req.Nonce, []byte(p.account()))
	if !ed25519.Verify(senderEd, blob, req.Sig) {
		return ContactProfile{}, fmt.Errorf("signature verification failed")
	}
	// "" unless the hook considers req.From an accepted contact.
	mailbox := clampMailbox(hookOrArg(p.hooks.ContactMailbox, req.From))
	return ContactProfile{MailboxURL: mailbox}, nil
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
	blob := signBlob(sigContextFor(protoVerCurrent), []byte("message"), e.Nonce, []byte(p.account()), e.SenderDHPub)
	if !ed25519.Verify(senderEd, blob, e.Sig) {
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
	key := crypto.DeriveDirectionalKey(shared, msgKeyInfo(e.Sender, p.account()))
	pt, err := crypto.OpenMessage(key, e.Box, aad(e.Sender, p.account()))
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

// ReceiveFriendRequest verifies an inbound friend request and records it.
func (p *Peer) ReceiveFriendRequest(r FriendRequest) error {
	if !p.consumeNonce(r.Nonce) {
		return fmt.Errorf("unknown or expired challenge nonce")
	}
	fromEd, err := identity.AccountNumberFromString(r.From)
	if err != nil {
		return fmt.Errorf("bad account: %w", err)
	}
	blob := signBlob(sigContextFor(protoVerCurrent), []byte("friend-request"), r.Nonce,
		[]byte(p.account()), []byte(r.FromName), []byte(r.ReqID))
	if !ed25519.Verify(fromEd, blob, r.Sig) {
		return fmt.Errorf("signature verification failed")
	}
	return p.hooks.OnFriendRequest(r.From, clampName(r.FromName), r.ReqID)
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
	blob := signBlob(sigContextFor(protoVerCurrent), []byte("friend-accept"), a.Nonce,
		[]byte(p.account()), []byte(a.FromName), []byte(a.ReqID))
	if !ed25519.Verify(fromEd, blob, a.Sig) {
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
