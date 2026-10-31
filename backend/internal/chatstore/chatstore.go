// Package chatstore persists contacts and message history encrypted at rest.
// It is encrypted with AES-256-GCM under a key derived from the identity's seed
// (identity.StoreKey), so the file is readable only while unlocked — who you
// talk to and what you said are protected as strongly as the identity itself.
package chatstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/molepipe/molepipe/backend/internal/crypto"
)

const (
	fileName    = "messages.enc"
	fileVersion = 2
)

// ErrNewerVersion is returned by Load when messages.enc was written by a newer
// build (env.Version > fileVersion). Decided before decryption, so a caller can
// tell it apart from a decrypt failure and must treat it NON-DESTRUCTIVELY: never
// overwrite the file (a Save would wipe the newer data) — the session simply runs
// without persistence until the newer build is reinstalled.
var ErrNewerVersion = errors.New("store file was written by a newer app version")

// Contact status values.
const (
	StatusAccepted   = "accepted"    // mutual; messaging allowed
	StatusPendingOut = "pending_out" // we sent a friend request, awaiting their accept
	StatusPendingIn  = "pending_in"  // they sent us a request, awaiting our accept
	StatusBlocked    = "blocked"     // messages and requests from them are rejected
)

// Group roles and invite policy.
const (
	GroupRoleAdmin  = "admin"
	GroupRoleMember = "member"

	// InvitePolicy* is the per-group switch, set by admins, for who may add new
	// members. Admins (and members granted CanInvite) may always add; this decides
	// whether ordinary members can too.
	InvitePolicyAdmins   = "admins"   // only admins / delegated members may add
	InvitePolicyEveryone = "everyone" // any member may add
)

// Contact is a saved contact.
type Contact struct {
	Account string `json:"account"`
	Name    string `json:"name"`
	// Nickname is the LOCAL label the user has chosen for this contact. It is
	// private: it never goes on the wire (nothing marshals a Contact to a peer —
	// group rosters are built from GroupMember, not from here), and it is never
	// written by an inbound profile update, so a peer renaming themselves cannot
	// disturb it and cannot discover it. Empty = no nickname; use DisplayName to
	// resolve rather than reading either name field directly.
	Nickname string `json:"nickname,omitempty"`
	Status   string `json:"status"`
	// ReqID binds a friend request to its accept: set on the pending_out side to
	// the id we sent, and echoed by the accept we require to match.
	ReqID string `json:"req_id,omitempty"`
	// MailboxURL is the peer's mailbox address (.onion or host:port), learned and
	// cached from their signed profile while they were online, so we can still
	// deliver to them (via the mailbox) after they go offline. Empty = none known.
	MailboxURL string `json:"mailbox_url,omitempty"`
	// DHPub is the peer's cached X25519 public key from their signed profile,
	// needed to encrypt an offline mailbox message (no live handshake to get it).
	// It is also the ROTATION CONTINUITY ANCHOR: the peer's onion (Account) may
	// rotate, but this non-rotating m/0'/1' key is how we recognise a verified
	// AddressRotation as genuinely from this contact. See AliasIndex.
	DHPub []byte `json:"dh_pub,omitempty"`
	// AliasIndex is the highest rotation alias index we have accepted from this
	// contact (the monotonic rollback-replay guard). A received AddressRotation is
	// applied only when its index exceeds this; on apply, Account is migrated to the
	// new onion and this advances. Zero means no rotation seen yet (the contact is
	// at its bootstrap alias). Not sequential — gaps are fine.
	AliasIndex uint32 `json:"alias_index,omitempty"`
	// MyAccountKnown is the account (== onion label) of OUR alias that THIS contact
	// currently knows us by — i.e. the sender identity we must stamp on outbound
	// messages to them so their AllowMessage gate and session lookup resolve. It is
	// the send-side mirror of AliasIndex (which tracks THEIR rotations; this tracks
	// which of OUR aliases they have acked). Empty means the primary account — the
	// correct default for every existing contact, so no migration is needed. It only
	// advances to a rotation alias once the contact acks that we have rotated (see
	// RotationPending / the rotation-delivery ack flow); stamping a not-yet-acked
	// alias would fail their gate, which is why the switch is per-contact and
	// ack-driven rather than global.
	MyAccountKnown string `json:"my_account_known,omitempty"`
	// MyAliasIndexKnown is the alias index MyAccountKnown names — stored (rather than
	// recovered by mapping the account back through RotationState) because the grace
	// sweeper prunes retired aliases from RotationState.History, so a string→index
	// lookup would lose the index exactly when a contact still lags there. It is the
	// no-regress guard for the ack handler: an ack advances MyAccountKnown only when
	// its index strictly exceeds this (or MyAccountKnown is empty — the primary
	// sentinel, since index 0 is itself a real alias). Always written together with
	// MyAccountKnown; meaningless while MyAccountKnown is empty.
	MyAliasIndexKnown uint32 `json:"my_alias_index_known,omitempty"`
	// AvatarHash is the sha256 hex of the peer's avatar, learned from their signed
	// profile card. The bytes are fetched by this hash from their ungated
	// AvatarPath and cached in the local AvatarStore; the UI renders from that
	// cache (initials fallback when empty), never dialing on a render.
	AvatarHash string `json:"avatar_hash,omitempty"`
	// UpdatedAt is the last time we changed this contact locally. Multi-device
	// sync merges contacts last-write-wins on it; a zero value counts as oldest
	// (loses to any device that has explicitly touched the record).
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	// RelayGrant is true when we've approved this contact to use US as a relay:
	// we'll accept relay drop-offs from them and forward to their recipients.
	RelayGrant bool `json:"relay_grant,omitempty"`
	// RelayHolder is true when this contact has approved US to relay through THEM:
	// we may hand them a sealed message to push onward when a peer is unreachable.
	RelayHolder bool `json:"relay_holder,omitempty"`
	// RelayPending is true when this contact has asked to use us as a relay and is
	// awaiting our approval.
	RelayPending bool `json:"relay_pending,omitempty"`
	// RelayReqID binds a relay-request to its accept, like ReqID.
	RelayReqID string `json:"relay_req_id,omitempty"`
	// Muted silences system notifications for this contact's messages. The
	// message still arrives, still lands in the log and still counts as unread —
	// only the notification is suppressed — so muting never costs delivery. It is
	// enforced at the inbound hook, which is the one place that still knows the
	// ACCOUNT: the Android listener is handed a display name only.
	Muted bool `json:"muted,omitempty"`
	// MediaAutoSave overrides Profile.MediaAutoSave for this contact. It is a
	// POINTER so "inherit the global" stays distinguishable from "explicitly
	// off": with a plain bool, a contact the user had deliberately set to off
	// would silently follow the global default back on.
	MediaAutoSave *bool `json:"media_auto_save,omitempty"`
}

// DisplayName is the one rule for how a contact is labelled: the user's own
// nickname wins over the name the peer published for themselves. It returns ""
// when neither is set, leaving the caller to apply its own fallback (usually the
// raw account number) — callers must not reach past this to .Name, or a nickname
// silently fails to apply on that surface.
func (c Contact) DisplayName() string {
	if c.Nickname != "" {
		return c.Nickname
	}
	return c.Name
}

// Profile is the identity's own shareable card.
type Profile struct {
	DisplayName string `json:"display_name"`
	// MailboxURL is our own mailbox address so contacts can drop off mail when
	// we're offline. It is disclosed to accepted contacts via the gated
	// ContactProfilePath (no longer in the public card). Empty = none.
	MailboxURL string `json:"mailbox_url,omitempty"`
	// AvatarHash is the sha256 hex of our own avatar image, advertised in the
	// public card so a stranger can preview our face at add-time. Empty = none.
	// It rides in Profile so the setting syncs to my other devices (LWW).
	AvatarHash string `json:"avatar_hash,omitempty"`
	// AvatarBytes carries our own avatar image itself so it reaches our OTHER
	// devices over /sync (Profile swaps as a whole unit on UpdatedAt, so the bytes
	// and the hash never desync). It is ≤64 KiB (MaxAvatarBytes). A receiving
	// device verifies sha256(AvatarBytes)==AvatarHash and writes it into its own
	// AvatarStore. It is NEVER placed on the friend-facing protocol.Profile (which
	// has no bytes field — contacts fetch by hash from AvatarPath instead), and
	// both /api/profile GET and /api/lookup hand-build subsets, so it never leaks
	// into a UI poll.
	AvatarBytes []byte `json:"avatar_bytes,omitempty"`
	// UpdatedAt drives last-write-wins when merging the profile across devices.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	// GroupImageBackupBytes is the byte budget the user set for durable group-image
	// backups in their OWN mailbox. Zero = disabled (the default). It rides along in
	// Profile so the setting syncs to my other devices; it is stripped from the
	// friend-facing protocol.Profile (see the hook wiring), so contacts never see it.
	GroupImageBackupBytes int64 `json:"group_image_backup_bytes,omitempty"`
	// MediaAutoSave is the GLOBAL default for copying received images out of the
	// encrypted attachment store into the phone's own gallery (Pictures/Molepipe
	// via MediaStore). False — the current behaviour — keeps every image inside
	// the app, where the system gallery, photo pickers and cloud backup cannot
	// see it; that is why this defaults off and is a privacy control rather than
	// a storage one. Per-contact overrides live in Contact.MediaAutoSave. Rides
	// in Profile so the setting syncs to my other devices, and is stripped from
	// the friend-facing protocol.Profile like GroupImageBackupBytes above.
	MediaAutoSave bool `json:"media_auto_save,omitempty"`
}

// Device is a linked device authorized to sync this identity's data. The private
// key never leaves the device; only PubKey is shared/synced. Enrollment adds a
// device here, gated by a pairing secret (physical access to an existing device)
// — not merely by holding the recovery phrase — so a stolen phrase recovers the
// account but not the message history.
type Device struct {
	PubKey  []byte    `json:"pub_key"` // Ed25519 device public key
	Name    string    `json:"name,omitempty"`
	AddedAt time.Time `json:"added_at"`
}

// GroupMember is one member of a group's roster, as carried in the signed roster
// distributed by admins: their account, the X25519 key needed to seal group
// messages to them, their role, and whether they've been delegated the right to
// invite others (a non-admin CanInvite).
type GroupMember struct {
	Account   string `json:"account"`
	DHPub     []byte `json:"dh_pub,omitempty"` // X25519 key to seal group messages to them
	Role      string `json:"role"`             // GroupRoleAdmin | GroupRoleMember
	CanInvite bool   `json:"can_invite,omitempty"`
	Name      string `json:"name,omitempty"`
}

// Group is a group conversation this device belongs to. The roster (Name,
// Policy, Members) is distributed as an epoch-versioned, committer-signed blob;
// Epoch increases on every roster change and the best roster wins on reconcile
// (see RosterBeats). Roster AUTHORITY (that the committer was entitled to make
// the change — admins for anything, members only for a constrained add or their
// own removal) is checked when a roster is received from a group peer, before it
// is ever stored — so Merge, which only ever sees rosters from our own trusted
// devices, can treat epoch/signature as authoritative.
type Group struct {
	ID      string        `json:"id"`
	Name    string        `json:"name"`
	Epoch   uint64        `json:"epoch"`  // roster version; higher wins on reconcile
	Policy  string        `json:"policy"` // InvitePolicy*
	Members []GroupMember `json:"members"`
	// Signer and Sig are the committer account and their signature over the
	// canonical roster (see protocol.SignedRoster). They are STORED, not just
	// verified-and-discarded, so any member can re-emit the roster it holds to
	// another member with the original signature intact — membership replicates
	// the same "everyone relays" way group messages do (Message.AuthorSig).
	Signer string `json:"signer,omitempty"`
	Sig    []byte `json:"sig,omitempty"`
}

// RosterBeats reports whether roster a should win over b when the same group is
// reconciled from two sources. Higher epoch wins; at an equal epoch a
// deterministic signature-byte comparison breaks the tie, so every member and
// device converges on the SAME roster after a concurrent admin edit instead of
// keeping whichever it happened to see first.
func RosterBeats(a, b Group) bool {
	if a.Epoch != b.Epoch {
		return a.Epoch > b.Epoch
	}
	return bytes.Compare(a.Sig, b.Sig) > 0
}

// GroupInvite is an invitation to join a group that WE received. It is persisted
// so it survives restart, synced across our devices, and — once Accepted — it
// both arms the bootstrap CONSENT anchor for that group (the only thing that
// lets a first roster in: see the api acceptance gate) and drives the
// accept-retry until we actually hold a roster that lists us.
type GroupInvite struct {
	GroupID  string    `json:"group_id"`
	Name     string    `json:"name,omitempty"`
	Inviter  string    `json:"inviter"`
	ReqID    string    `json:"req_id"`
	Accepted bool      `json:"accepted,omitempty"`
	At       time.Time `json:"at"`
	LastTry  time.Time `json:"last_try,omitempty"`
	Refusals int       `json:"refusals,omitempty"`
}

// SentGroupInvite records an invite WE sent, so we only ever commit an
// invite-accept that matches one we actually issued — a stranger cannot get
// themselves added to a group by pushing an unsolicited "accept".
type SentGroupInvite struct {
	GroupID string    `json:"group_id"`
	Account string    `json:"account"`
	ReqID   string    `json:"req_id"`
	At      time.Time `json:"at"`
}

// Message is one stored message.
type Message struct {
	Direction string    `json:"direction"` // "in" or "out"
	Peer      string    `json:"peer"`      // other party's account number
	Text      string    `json:"text"`
	At        time.Time `json:"at"`
	// ID identifies a message for multi-device sync de-duplication. It is a
	// deterministic content hash (see MessageID), so two devices that hold the
	// same message independently derive the same ID and the union merge collapses
	// them into one instead of duplicating.
	ID string `json:"id"`
	// Delivery is "" once the message is delivered (and always, for inbound
	// messages), "pending" while an outbox entry is still trying, or "failed"
	// once trying has stopped. It sits immediately after ID because api's
	// chatMessage is converted to this type directly, which requires identical
	// field order — see TestMessageStructsConvertCleanly.
	Delivery string `json:"delivery,omitempty"`
	// GroupID is set for a group message and empty for a 1:1 message. INVARIANT:
	// a group message has Peer=="" (it belongs to a group, never to a contact) and
	// is keyed by GroupID everywhere; code that filters 1:1 conversations by Peer
	// therefore never picks it up. Author names the original sender; Direction is
	// still local ("out" if we authored it, "in" otherwise). Kept last so the
	// chatMessage⇄Message conversion order stays stable.
	GroupID string `json:"group_id,omitempty"`
	Author  string `json:"author,omitempty"` // original sender, for a group message
	// AuthorSig is the original author's signature over a group message's content
	// (see protocol.GroupMessage). Retained so ANY member can re-seal and forward
	// the message during gossip while its authorship still verifies — the courier
	// never re-signs. Not part of the message id (which hashes content), and
	// deterministic (Ed25519), so every member stores identical bytes.
	AuthorSig []byte `json:"author_sig,omitempty"`
	// Kind is "" for an ordinary text message and "image" for an image
	// attachment. An image message carries no Text; its bytes live OUT of this log
	// in the encrypted AttachmentStore, keyed by AttachID (= the wire message id),
	// so message.enc and every /api/messages poll stay small. Mime and Size are
	// the attachment's type and byte length. Kept last so the chatMessage⇄Message
	// conversion order stays stable.
	Kind     string `json:"kind,omitempty"`
	AttachID string `json:"attach_id,omitempty"`
	Mime     string `json:"mime,omitempty"`
	Size     int    `json:"size,omitempty"`
	// GROUP image only. A group image shows a small blurry thumbnail (stored under
	// ThumbID) immediately, and the full image (AttachID, Mime, Size above) is
	// fetched on demand and verified against FullHash — which is part of the
	// author's signature and of the group-image sync id, so it can't be forged or
	// collide. Empty for 1:1 images and text.
	ThumbID   string `json:"thumb_id,omitempty"`
	ThumbMime string `json:"thumb_mime,omitempty"`
	FullHash  []byte `json:"full_hash,omitempty"`
	// Reactions and the Reply* fields are NOT part of MessageID (which hashes only
	// direction/peer/text/at), so adding or changing a reaction never re-identifies
	// a message and the sync union still collapses the two devices' copies by id.
	// Kept last so the chatMessage⇄Message conversion order stays stable.
	//
	// Reactions is the raw per-reactor set ([]{emoji, by}); the client aggregates
	// it into counts. The sync Merge unions these by (emoji, by) — see Merge — so a
	// reaction placed on one device survives a merge with the other.
	Reactions []MessageReaction `json:"reactions,omitempty"`
	// Reply* is reply-with-context: the quoted message's shared wire id, plus a
	// preview/author kept only as a fallback for a quote this device never saw
	// (normally the client resolves the quote locally by ReplyID). All peer-supplied
	// text here is clamped at the protocol trust boundary before it reaches here.
	ReplyID      string `json:"reply_id,omitempty"`
	ReplyPreview string `json:"reply_preview,omitempty"`
	ReplyAuthor  string `json:"reply_author,omitempty"`
}

// MessageReaction is one emoji reaction placed by one account. Stored raw (not
// pre-aggregated) so multi-device sync can union two devices' reaction sets by
// (Emoji, By) without a count ever being double-added.
//
// At/Removed/Sig exist only for GROUP reactions (build 4). A group reaction is a
// self-contained signed event that gossips like a group message, so a member who
// was offline when someone un-reacted must not resurrect the stale add. That is
// solved per (Emoji, By): the reactor By is the SOLE authorized writer of that
// key, so "keep the highest At By signed" totally orders their own add/remove
// events — no cross-writer conflict, no CRDT. Removed is a tombstone (an un-react
// kept as a dated marker so a re-gossiped older add loses to it). Sig is By's
// signature over the group-reaction event, retained so any member can re-serve it
// to a lagging member and that member still verifies it came from By.
//
// 1:1 reactions leave all three zero: At uses omitempty (int64, not time.Time,
// precisely so a zero omits), Removed/Sig omit too, keeping the 1:1 wire/stored
// form byte-for-byte what it was before build 4. A zero At sorts as oldest, and
// 1:1 rows never carry a tombstone (RemoveReaction deletes the entry), so a legacy
// add can never be erased by LWW.
type MessageReaction struct {
	Emoji   string `json:"emoji"`
	By      string `json:"by"`                // reactor's account number
	At      int64  `json:"at,omitempty"`      // group only: event time (unix-nanos); 0 = 1:1/legacy add, treated as oldest
	Removed bool   `json:"removed,omitempty"` // group only: tombstone from an un-react
	Sig     []byte `json:"sig,omitempty"`     // group only: reactor's signature over the event, for verified gossip re-serve
}

// HasReaction reports whether (emoji, by) is present as a LIVE reaction (a group
// tombstone reads as absent).
func HasReaction(rs []MessageReaction, emoji, by string) bool {
	for _, r := range rs {
		if r.Emoji == emoji && r.By == by {
			return !r.Removed
		}
	}
	return false
}

// AddReaction returns rs with (emoji, by) present, adding it only if absent so a
// repeated add is idempotent. Used by the 1:1 path (no At/Sig); a group reaction
// goes through ApplyGroupReaction instead. If a match exists but is a group
// tombstone (Removed), it is revived in place rather than appending a duplicate
// key — appending would leave two entries under one (emoji, by) and break the
// single-entry invariant ApplyGroupReaction relies on.
func AddReaction(rs []MessageReaction, emoji, by string) []MessageReaction {
	for i := range rs {
		if rs[i].Emoji == emoji && rs[i].By == by {
			if rs[i].Removed {
				rs[i] = MessageReaction{Emoji: emoji, By: by}
			}
			return rs
		}
	}
	return append(rs, MessageReaction{Emoji: emoji, By: by})
}

// RemoveReaction returns rs without (emoji, by). Used by the 1:1 path, where a
// removal is a physical delete (no tombstone needed — 1:1 removals sync to the
// peer directly, not by gossip).
func RemoveReaction(rs []MessageReaction, emoji, by string) []MessageReaction {
	out := rs[:0:0]
	for _, r := range rs {
		if r.Emoji == emoji && r.By == by {
			continue
		}
		out = append(out, r)
	}
	return out
}

// ApplyGroupReaction upserts one signed group-reaction event into rs using
// per-(emoji, by) last-writer-wins. Because By is the only authorized writer of
// its own (emoji, by) key, this is a single-writer register, not a merge across
// competing writers: the event replaces the stored entry only when it is strictly
// newer (or ties and is the tombstone, so a remove wins a same-instant race
// deterministically). A re-gossiped stale add is therefore silently dropped
// rather than resurrecting a newer un-react. Returns the new slice and whether it
// changed.
func ApplyGroupReaction(rs []MessageReaction, ev MessageReaction) ([]MessageReaction, bool) {
	for i := range rs {
		if rs[i].Emoji == ev.Emoji && rs[i].By == ev.By {
			if ev.At > rs[i].At || (ev.At == rs[i].At && ev.Removed && !rs[i].Removed) {
				rs[i] = ev
				return rs, true
			}
			return rs, false
		}
	}
	return append(rs, ev), true
}

// LiveReactions returns only the non-tombstone reactions — what the client renders
// and what the per-message cap counts.
func LiveReactions(rs []MessageReaction) []MessageReaction {
	out := make([]MessageReaction, 0, len(rs))
	for _, r := range rs {
		if !r.Removed {
			out = append(out, r)
		}
	}
	return out
}

// unionReactions merges two reaction sets by (emoji, by) using the same LWW rule
// as ApplyGroupReaction. For 1:1 rows (no tombstones, zero At) this degrades to
// the old add-wins union: two identical adds collapse to one, and a present
// reaction is never dropped. For group rows it converges add/remove correctly
// regardless of merge order.
func unionReactions(a, b []MessageReaction) []MessageReaction {
	out := append([]MessageReaction(nil), a...)
	for _, r := range b {
		out, _ = ApplyGroupReaction(out, r)
	}
	return out
}

// Message kinds.
const (
	KindText  = "" // ordinary text (default)
	KindImage = "image"
)

// Delivery states for Message.Delivery.
const (
	DeliveryPending = "pending"
	DeliveryFailed  = "failed"
)

// MessageID derives the deterministic sync ID for a message from its content.
// Deterministic (not random) so a message backfilled independently on two
// already-synced devices gets the same ID on both; the nanosecond timestamp
// makes accidental collisions between genuinely distinct messages implausible.
func MessageID(direction, peer, text string, at time.Time) string {
	h := sha256.New()
	// Length-prefix each field so distinct field boundaries can't alias.
	for _, part := range []string{direction, peer, text, at.UTC().Format(time.RFC3339Nano)} {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(part)))
		h.Write(l[:])
		h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// GroupMessageID derives the deterministic sync id for a GROUP message. Unlike
// MessageID it must be identical for EVERY member regardless of who they are, so
// it hashes only group-wide, author-attributed content — never Direction or a
// per-recipient Peer, both of which differ between the author and each recipient.
// The "group" domain tag keeps it from ever colliding with a 1:1 MessageID.
func GroupMessageID(groupID, author, text string, at time.Time) string {
	h := sha256.New()
	for _, part := range []string{"group", groupID, author, text, at.UTC().Format(time.RFC3339Nano)} {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(part)))
		h.Write(l[:])
		h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// GroupImageMessageID is GroupMessageID for a group IMAGE message. A group image
// carries no text, so hashing text would collide every image from one author at
// one instant — and could collide an image with a text message. It hashes the
// full image's content hash (fullHash) instead, under a distinct domain tag so it
// can never collide with a text GroupMessageID.
func GroupImageMessageID(groupID, author string, at time.Time, fullHash []byte) string {
	h := sha256.New()
	for _, part := range [][]byte{[]byte("group-image"), []byte(groupID), []byte(author), []byte(at.UTC().Format(time.RFC3339Nano)), fullHash} {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(part)))
		h.Write(l[:])
		h.Write(part)
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// syncID is a message's deterministic dedup id: a group message hashes its
// group-wide, author-attributed content; a 1:1 message hashes direction+peer.
func (m Message) syncID() string {
	if m.GroupID != "" {
		if m.Kind == KindImage {
			return GroupImageMessageID(m.GroupID, m.Author, m.At, m.FullHash)
		}
		return GroupMessageID(m.GroupID, m.Author, m.Text, m.At)
	}
	return MessageID(m.Direction, m.Peer, m.Text, m.At)
}

// StoredSignedPrekey is a signed X25519 prekey persisted in the encrypted store.
// The private key is needed for DH ratchet operations when establishing new
// sessions. Old prekeys are retained during a grace period for delayed messages,
// then permanently retired and their private keys deleted.
type StoredSignedPrekey struct {
	ID         uint32     `json:"id"`                   // monotonic prekey ID
	PublicKey  []byte     `json:"public_key"`           // 32-byte X25519 public key
	PrivateKey []byte     `json:"private_key"`          // 32-byte X25519 private key (sensitive)
	Signature  []byte     `json:"signature"`            // Ed25519 signature binding to identity
	CreatedAt  time.Time  `json:"created_at"`           // when this prekey was generated
	RetiredAt  *time.Time `json:"retired_at,omitempty"` // when retired (nil = current)
	Status     string     `json:"status"`               // "current", "retired", "expired"
}

// StoredOneTimePrekey is a single-use X25519 prekey for asynchronous session
// establishment. Once consumed by a peer, the private key is deleted.
type StoredOneTimePrekey struct {
	ID         uint32    `json:"id"`          // unique prekey ID
	PublicKey  []byte    `json:"public_key"`  // 32-byte X25519 public key
	PrivateKey []byte    `json:"private_key"` // 32-byte X25519 private key (sensitive)
	CreatedAt  time.Time `json:"created_at"`  // when generated
	// Reserved marks an OTP already handed out in a bundle: it must not be put
	// in another bundle (each one-time prekey is used at most once), but its
	// private key is retained until the referencing handshake actually arrives.
	Reserved bool `json:"reserved,omitempty"`
	Consumed bool `json:"consumed"` // true once a peer's handshake used it; private deleted
}

// PrekeyState holds the cryptographic prekey material for the v2 protocol.
// Signed prekeys are rotated automatically; one-time prekeys are consumed
// once and deleted.
type PrekeyState struct {
	// SignedPrekeys holds the current and recently retired signed prekeys.
	// The current one is the last element with Status == "current".
	SignedPrekeys []StoredSignedPrekey `json:"signed_prekeys,omitempty"`

	// OneTimePrekeys holds the pool of unused one-time prekeys.
	OneTimePrekeys []StoredOneTimePrekey `json:"one_time_prekeys,omitempty"`

	// NextPrekeyID is the monotonic counter for generating unique prekey IDs.
	// Incremented on every new signed or one-time prekey generation.
	NextPrekeyID uint32 `json:"next_prekey_id"`

	// PrekeyRotationAt is when the next automatic signed prekey rotation is due.
	PrekeyRotationAt time.Time `json:"prekey_rotation_at,omitempty"`
}

// Data is everything persisted.
type Data struct {
	Profile  Profile   `json:"profile"`
	Contacts []Contact `json:"contacts"`
	Messages []Message `json:"messages"`
	Groups   []Group   `json:"groups,omitempty"` // group conversations we belong to
	// GroupInvites are invitations we've received (and whether we've accepted);
	// SentGroupInvites are invitations we've issued, kept so we only commit an
	// accept that matches one.
	GroupInvites     []GroupInvite        `json:"group_invites,omitempty"`
	SentGroupInvites []SentGroupInvite    `json:"sent_group_invites,omitempty"`
	Reads            map[string]time.Time `json:"reads"`   // account -> last-read time (unread tracking)
	Devices          []Device             `json:"devices"` // linked devices authorized to sync
	// PendingAccepts are friend-accepts we still owe a requester.
	PendingAccepts []PendingAccept `json:"pending_accepts,omitempty"`
	// Outbox holds messages this device has accepted but not yet delivered.
	// Sending is asynchronous: the UI must not block for the 25-90s a Tor
	// circuit can take, and a message must survive the app being closed
	// mid-send.
	Outbox []OutboxItem `json:"outbox,omitempty"`
	// Deleted are tombstones for messages removed by "delete for everyone",
	// held as message IDs. They are REQUIRED, not an optimisation: Merge never
	// deletes, so without a tombstone a message deleted on one device would be
	// resurrected by the next sync with any device that still held it, and the
	// deletion would silently undo itself.
	Deleted []string `json:"deleted,omitempty"`

	// Prekeys holds the v2 protocol prekey material: signed prekeys for
	// session establishment and one-time prekeys for asynchronous/offline
	// session setup. Nil/empty on v1 upgrades until first unlock generates
	// the initial prekey material.
	Prekeys *PrekeyState `json:"prekeys,omitempty"`

	// RatchetSessions persists established Double Ratchet sessions, keyed by peer
	// account, each value a JSON-serialized session.SessionState. Held opaquely
	// here (as bytes) so chatstore need not import the session package. Persisting
	// the advanced sending-chain state BEFORE a message goes on the wire is what
	// prevents ratchet-key reuse across a crash/restart.
	RatchetSessions map[string][]byte `json:"ratchet_sessions,omitempty"`

	// PendingInits records, per peer account, an X3DH initial (handshake) envelope
	// whose delivery has not yet been acknowledged. Held opaquely as bytes (a JSON
	// blob owned by the api layer). Until the init is acked, the initiator MUST
	// resend this exact envelope rather than mint a fresh one — reissuing would
	// reserve a new one-time prekey and could leave the two sides on forked
	// sessions if a resend races the original. Cleared once the peer acks.
	PendingInits map[string][]byte `json:"pending_inits,omitempty"`

	// ProcessedInits records, per peer account, the signature of the last X3DH
	// init we successfully processed from that peer. An initiator resends the
	// byte-identical init until we ack it, so a second init bearing a signature
	// we've already recorded is an ack-lost resend — we ack it idempotently
	// instead of re-establishing. Keyed on the signature (not the one-time
	// prekey) so it survives one-time-prekey cleanup and a restart.
	ProcessedInits map[string][]byte `json:"processed_inits,omitempty"`

	// Rotation is the state of the rotating account identity: which alias index
	// (m/0'/2'/N') is currently published as our address, when the next automatic
	// refresh is due, and recently-retired aliases still live within their grace
	// window. Nil until the first alias is minted. The durable identity (the
	// m/0'/0' signing key / AccountNumber and the m/0'/1' DH key) never rotates;
	// only the externally-visible onion address does. See RotationState.
	Rotation *RotationState `json:"rotation,omitempty"`
	// PendingRotations is the ack-driven, resend-until-acked set of our own
	// rotations a contact has not yet acknowledged (mirrors PendingInits). Keyed by
	// the contact's CURRENT account; the value is the rotation we owe them. Cleared
	// on their ack, on contact removal, or when the alias retires past its grace
	// window. Device-local delivery bookkeeping — persisted but not CRDT-merged, the
	// same treatment as PendingInits/ProcessedInits.
	PendingRotations map[string]RotationPending `json:"pending_rotations,omitempty"`
	// PeerAliases maps a contact's now-retired account (an alias they rotated away
	// from) to the account we currently know that same contact by. It is the
	// receive-side counterpart of PendingRotations: after we apply a contact's
	// AddressRotation and migrate their per-peer state to the new onion, an
	// ack-lost RESEND of that announcement still arrives addressed from the OLD
	// alias (the sender keeps resending over the old-alias channel until we ack).
	// Resolving that old alias back to the current account lets the gate, the
	// session lookup and the idempotent apply recognise the resend instead of
	// rejecting it as an unknown sender with no session. The on-wire Sender is left
	// untouched, so message AAD stays symmetric. Device-local bookkeeping —
	// persisted (so tolerance survives a restart mid-grace) but not CRDT-merged,
	// the same treatment as PendingRotations/RatchetSessions.
	PeerAliases map[string]string `json:"peer_aliases,omitempty"`

	// AutoRefresh controls how the always-on invite code behaves after it is used.
	// The shareable friend code always carries InviteToken now, and a friend request
	// must present the CURRENT token to be admitted — a tokenless (bare account) or
	// stale request is refused, so the account is not addable without a live code.
	// When AutoRefresh is on, a successful redemption rotates the token (the code
	// works once, then a fresh one appears); when off, the current code stays valid
	// and reusable until the user manually refreshes it. Off by default. The JSON
	// tag stays one_time_invite for on-disk continuity with the earlier single-use
	// feature (an existing false value is a sensible default here). Device-local:
	// inbound friend requests land on the publishing (primary) device, which mints,
	// shows and rotates the token, so both fields are preserved from the local device
	// on merge and never imported from a peer (see Merge).
	AutoRefresh bool `json:"one_time_invite,omitempty"`
	// InviteToken is the live invite secret carried by the current friend code (see
	// AutoRefresh). Always present once an account has unlocked at least once (minted
	// on first unlock if absent). Device-local admission bookkeeping, like
	// PeerAliases above.
	InviteToken string `json:"invite_token,omitempty"`
}

// RotationState persists the rotating-account-identity feature's state. The
// current alias is the onion address we publish and hand out (as a refreshable
// code); history holds aliases we've rotated away from but keep alive during a
// grace window so contacts mid-handoff (and offline contacts) can still reach
// the old address until they ack the new one.
type RotationState struct {
	// CurrentIndex is the alias index (m/0'/2'/CurrentIndex') currently published.
	CurrentIndex uint32 `json:"current_index"`
	// CurrentAccount is the account number (== onion label) of the current alias,
	// cached so the UI/plumbing need not re-derive it every read.
	CurrentAccount string `json:"current_account"`
	// NextRefreshAt is when time-based auto-refresh becomes due (long-overlap /
	// infrequent by default). Zero = no auto-refresh scheduled yet.
	NextRefreshAt time.Time `json:"next_refresh_at,omitempty"`
	// History holds aliases rotated away from but still within their grace window.
	History []AliasRecord `json:"history,omitempty"`
}

// AliasRecord is a previously-current alias kept live during its grace window.
type AliasRecord struct {
	// Index is the alias index (m/0'/2'/Index').
	Index uint32 `json:"index"`
	// Account is the alias's account number / onion label.
	Account string `json:"account"`
	// RetireAt is the hard deadline to tear this alias's onion down (the end of
	// its grace window), independent of whether every contact has acked.
	RetireAt time.Time `json:"retire_at"`
}

// RotationPending is one contact's outstanding acknowledgement of a rotation we
// pushed to them: the new alias we announced and its monotonic index (self-
// contained so a resend needs no live RotationState lookup), plus when we queued
// it. Resent until the contact acks, then removed.
type RotationPending struct {
	// NewOnion is the alias onion we announced (our current alias at queue time).
	NewOnion string `json:"new_onion"`
	// AliasIndex is that alias's monotonic index, echoed by the contact's ack.
	AliasIndex uint32 `json:"alias_index"`
	// QueuedAt is when we first enqueued this rotation for the contact.
	QueuedAt time.Time `json:"queued_at"`
}

// PendingAccept is a friend-accept whose push has not landed yet: we accepted
// someone's request, but the message telling them so never reached them (their
// onion descriptor may not have propagated, or they were briefly offline).
//
// It has to be persisted rather than kept in memory, because the requester
// cannot fix this from their side: their client is stuck at pending_out, and
// the one repair path the protocol has — an inbound message upgrading
// pending_out to accepted — only fires in the direction they cannot send.
type PendingAccept struct {
	Account  string    `json:"account"` // the requester we owe an accept
	ReqID    string    `json:"req_id"`  // binds the accept to the request they sent
	QueuedAt time.Time `json:"queued_at"`
	LastTry  time.Time `json:"last_try,omitempty"`
	// Refusals counts consecutive times the peer answered and rejected the
	// accept. The peer returns a deliberately opaque 400 for every reason —
	// including transient ones, since its challenge nonces live in memory and
	// are wiped by any lock or restart — so a single refusal must not be read
	// as final. Several in a row means the debt really is settled.
	Refusals int `json:"refusals,omitempty"`
}

// OutboxItem is one undelivered outbound message.
//
// It is kept even after delivery stops being attempted, rather than removed,
// so the failure reason and the retry affordance have somewhere to live and so
// a retry re-arms this entry instead of appending a second copy of the message.
type OutboxItem struct {
	ID       string    `json:"id"` // wire message ID; matches Message.ID
	To       string    `json:"to"`
	Text     string    `json:"text"`
	QueuedAt time.Time `json:"queued_at"`
	LastTry  time.Time `json:"last_try,omitempty"`
	Attempts int       `json:"attempts,omitempty"`
	// Failed stops further automatic attempts; a manual retry clears it.
	Failed bool `json:"failed,omitempty"`
	// LastError is shown to the sender, so "not delivered" can say why.
	LastError string `json:"last_error,omitempty"`
	// Reply* carries reply-with-context so a queued reply keeps its quote when it
	// is finally delivered (direct or via the mailbox), not just in the local copy.
	ReplyID      string `json:"reply_id,omitempty"`
	ReplyPreview string `json:"reply_preview,omitempty"`
	ReplyAuthor  string `json:"reply_author,omitempty"`
}

// normalize upgrades legacy records: a contact with no status was added in
// Phase 4 by mutual manual add, so it is accepted.
func (d *Data) normalize() {
	for i := range d.Contacts {
		if d.Contacts[i].Status == "" {
			d.Contacts[i].Status = StatusAccepted
		}
	}
	// Backfill sync IDs for messages stored before the field existed. Idempotent
	// and deterministic, so two devices backfill identical IDs for the same message.
	for i := range d.Messages {
		if d.Messages[i].ID == "" {
			d.Messages[i].ID = d.Messages[i].syncID()
		}
	}
	d.applyTombstones()
}

// applyTombstones drops any message whose ID has been deleted. Run on every
// load and merge, so a message cannot come back by arriving from a device that
// had not heard about the deletion yet.
func (d *Data) applyTombstones() {
	if len(d.Deleted) == 0 {
		return
	}
	gone := make(map[string]bool, len(d.Deleted))
	for _, id := range d.Deleted {
		gone[id] = true
	}
	kept := d.Messages[:0]
	for _, m := range d.Messages {
		if !gone[m.ID] {
			kept = append(kept, m)
		}
	}
	d.Messages = kept
	// A message deleted for everyone must also stop being sent.
	keptOut := d.Outbox[:0]
	for _, it := range d.Outbox {
		if !gone[it.ID] {
			keptOut = append(keptOut, it)
		}
	}
	d.Outbox = keptOut
}

// --- Prekey management methods ---

// EnsurePrekeys initializes the prekey state if nil (first v2 unlock).
// Does not generate keys — that requires the identity seed and belongs in
// the crypto/session layer. This just ensures the struct exists.
func (d *Data) EnsurePrekeys() {
	if d.Prekeys == nil {
		d.Prekeys = &PrekeyState{}
	}
}

// GetCurrentSignedPrekey returns the active signed prekey, or nil if none exists.
func (d *Data) GetCurrentSignedPrekey() *StoredSignedPrekey {
	if d.Prekeys == nil {
		return nil
	}
	for i := len(d.Prekeys.SignedPrekeys) - 1; i >= 0; i-- {
		if d.Prekeys.SignedPrekeys[i].Status == "current" {
			return &d.Prekeys.SignedPrekeys[i]
		}
	}
	return nil
}

// AddSignedPrekey appends a new signed prekey and marks it as current.
// The previous current prekey is marked as "retired" with a grace period.
func (d *Data) AddSignedPrekey(sp StoredSignedPrekey) {
	d.EnsurePrekeys()
	sp.Status = "current"
	sp.ID = d.Prekeys.NextPrekeyID
	d.Prekeys.NextPrekeyID++
	// Retire the previous current prekey
	for i := range d.Prekeys.SignedPrekeys {
		if d.Prekeys.SignedPrekeys[i].Status == "current" {
			now := time.Now()
			d.Prekeys.SignedPrekeys[i].Status = "retired"
			d.Prekeys.SignedPrekeys[i].RetiredAt = &now
		}
	}
	d.Prekeys.SignedPrekeys = append(d.Prekeys.SignedPrekeys, sp)
}

// GetExpiredSignedPrekeys returns signed prekeys whose grace period has expired
// and whose private keys should be deleted.
func (d *Data) GetExpiredSignedPrekeys(gracePeriod time.Duration) []StoredSignedPrekey {
	if d.Prekeys == nil {
		return nil
	}
	var expired []StoredSignedPrekey
	for _, sp := range d.Prekeys.SignedPrekeys {
		if sp.Status == "retired" && sp.RetiredAt != nil &&
			time.Since(*sp.RetiredAt) > gracePeriod {
			expired = append(expired, sp)
		}
	}
	return expired
}

// DeleteExpiredSignedPrekeys removes retired prekeys past their grace period
// and zeros their private keys.
func (d *Data) DeleteExpiredSignedPrekeys(gracePeriod time.Duration) {
	if d.Prekeys == nil {
		return
	}
	expired := d.GetExpiredSignedPrekeys(gracePeriod)
	if len(expired) == 0 {
		return
	}
	expIDs := make(map[uint32]bool, len(expired))
	for _, sp := range expired {
		expIDs[sp.ID] = true
		// Zero the private key before discarding
		for i := range sp.PrivateKey {
			sp.PrivateKey[i] = 0
		}
	}
	kept := d.Prekeys.SignedPrekeys[:0]
	for _, sp := range d.Prekeys.SignedPrekeys {
		if !expIDs[sp.ID] {
			kept = append(kept, sp)
		}
	}
	d.Prekeys.SignedPrekeys = kept
}

// AddOneTimePrekeys appends a batch of one-time prekeys to the pool.
func (d *Data) AddOneTimePrekeys(prekeys []StoredOneTimePrekey) {
	d.EnsurePrekeys()
	for _, otp := range prekeys {
		otp.ID = d.Prekeys.NextPrekeyID
		d.Prekeys.NextPrekeyID++
		d.Prekeys.OneTimePrekeys = append(d.Prekeys.OneTimePrekeys, otp)
	}
}

// ConsumeOneTimePrekey marks a prekey as consumed and returns its private key.
// Returns nil if the prekey was already consumed or not found. The caller
// must use the returned key immediately and not store it.
func (d *Data) ConsumeOneTimePrekey(id uint32) []byte {
	if d.Prekeys == nil {
		return nil
	}
	for i := range d.Prekeys.OneTimePrekeys {
		if d.Prekeys.OneTimePrekeys[i].ID == id && !d.Prekeys.OneTimePrekeys[i].Consumed {
			d.Prekeys.OneTimePrekeys[i].Consumed = true
			priv := d.Prekeys.OneTimePrekeys[i].PrivateKey
			// Zero the stored private key before discarding — defense in depth.
			for j := range d.Prekeys.OneTimePrekeys[i].PrivateKey {
				d.Prekeys.OneTimePrekeys[i].PrivateKey[j] = 0
			}
			d.Prekeys.OneTimePrekeys[i].PrivateKey = nil
			return priv
		}
	}
	return nil
}

// CleanupConsumedOneTimePrekeys removes consumed one-time prekeys from the pool.
func (d *Data) CleanupConsumedOneTimePrekeys() {
	if d.Prekeys == nil {
		return
	}
	kept := d.Prekeys.OneTimePrekeys[:0]
	for _, otp := range d.Prekeys.OneTimePrekeys {
		if !otp.Consumed {
			kept = append(kept, otp)
		}
	}
	d.Prekeys.OneTimePrekeys = kept
}

// UnusedOneTimePrekeys returns the count of unconsumed one-time prekeys.
func (d *Data) UnusedOneTimePrekeys() int {
	if d.Prekeys == nil {
		return 0
	}
	n := 0
	for _, otp := range d.Prekeys.OneTimePrekeys {
		if !otp.Consumed {
			n++
		}
	}
	return n
}

// Merge combines two devices' state into one, deterministically and
// idempotently (Merge(a,b) then Merge with anything already merged changes
// nothing new). It never deletes: sync only adds/updates, so a message or
// contact present on either side survives.
//
//   - Messages: union by ID (deterministic content hash), sorted by time.
//   - Contacts: last-write-wins per account on UpdatedAt (zero = oldest).
//   - Profile: last-write-wins on UpdatedAt.
//   - Reads: MAX per account (never un-read something read on another device).
//   - Devices: union by public key.
func Merge(a, b *Data) *Data {
	a.normalize()
	b.normalize()
	out := &Data{}

	// Messages: union by ID. The first copy of an id wins for the message body,
	// but reactions are UNIONED across both copies (by emoji+account), so a
	// reaction placed on one device is never dropped just because the other
	// device's copy of the message was enumerated first. Union is add-wins: a
	// reaction removed on one device but still present on the other reappears
	// after a merge — an accepted, low-stakes limitation for an ephemeral nicety.
	seen := make(map[string]int) // id -> index in out.Messages
	for _, src := range [][]Message{a.Messages, b.Messages} {
		for _, m := range src {
			if m.ID == "" {
				m.ID = m.syncID()
			}
			if idx, ok := seen[m.ID]; ok {
				out.Messages[idx].Reactions = unionReactions(out.Messages[idx].Reactions, m.Reactions)
				continue
			}
			seen[m.ID] = len(out.Messages)
			out.Messages = append(out.Messages, m)
		}
	}
	sort.SliceStable(out.Messages, func(i, j int) bool { return out.Messages[i].At.Before(out.Messages[j].At) })

	// Contacts: last-write-wins per account.
	byAcct := make(map[string]Contact)
	order := []string{}
	for _, src := range [][]Contact{a.Contacts, b.Contacts} {
		for _, c := range src {
			ex, ok := byAcct[c.Account]
			if !ok {
				order = append(order, c.Account)
				byAcct[c.Account] = c
			} else if c.UpdatedAt.After(ex.UpdatedAt) {
				byAcct[c.Account] = c
			}
		}
	}
	for _, acct := range order {
		out.Contacts = append(out.Contacts, byAcct[acct])
	}

	// Profile: last-write-wins.
	if b.Profile.UpdatedAt.After(a.Profile.UpdatedAt) {
		out.Profile = b.Profile
	} else {
		out.Profile = a.Profile
	}

	// Groups: union by id, best roster wins (highest epoch, signature-byte
	// tiebreak at equal epoch — see RosterBeats). Roster AUTHENTICITY (that the
	// change was authorised) is verified when a roster arrives from a group peer,
	// before it is ever stored, so it never reaches Merge unverified; the only
	// rosters Merge sees come from our OWN enrolled devices over the trusted /sync
	// channel, each already vetted on that device. So Merge may treat the stored
	// epoch/signature as authoritative and needs no signature check of its own.
	byGroup := make(map[string]Group)
	groupOrder := []string{}
	for _, src := range [][]Group{a.Groups, b.Groups} {
		for _, g := range src {
			ex, ok := byGroup[g.ID]
			if !ok {
				groupOrder = append(groupOrder, g.ID)
				byGroup[g.ID] = g
			} else if RosterBeats(g, ex) {
				byGroup[g.ID] = g
			}
		}
	}
	for _, gid := range groupOrder {
		out.Groups = append(out.Groups, byGroup[gid])
	}

	// Group invites received: union by group, preferring an Accepted record and
	// the earliest arrival (so the retry TTL runs from when the invite actually
	// came in). A device that has already joined drops the invite; a merge can
	// resurrect it from a device that hasn't, which costs at most one redundant
	// accept push — the same cheap-redundancy trade as PendingAccepts.
	byInvite := make(map[string]GroupInvite)
	inviteOrder := []string{}
	for _, src := range [][]GroupInvite{a.GroupInvites, b.GroupInvites} {
		for _, gi := range src {
			ex, ok := byInvite[gi.GroupID]
			if !ok {
				inviteOrder = append(inviteOrder, gi.GroupID)
				byInvite[gi.GroupID] = gi
				continue
			}
			if (gi.Accepted && !ex.Accepted) || (gi.Accepted == ex.Accepted && gi.At.Before(ex.At)) {
				byInvite[gi.GroupID] = gi
			}
		}
	}
	for _, gid := range inviteOrder {
		out.GroupInvites = append(out.GroupInvites, byInvite[gid])
	}

	// Sent invites: union by (group, account, req id).
	seenSent := make(map[string]bool)
	for _, src := range [][]SentGroupInvite{a.SentGroupInvites, b.SentGroupInvites} {
		for _, si := range src {
			k := si.GroupID + "|" + si.Account + "|" + si.ReqID
			if !seenSent[k] {
				seenSent[k] = true
				out.SentGroupInvites = append(out.SentGroupInvites, si)
			}
		}
	}

	// Reads: max per account (reading on one device must not un-read on another).
	out.Reads = make(map[string]time.Time)
	for _, src := range []map[string]time.Time{a.Reads, b.Reads} {
		for acct, t := range src {
			if ex, ok := out.Reads[acct]; !ok || t.After(ex) {
				out.Reads[acct] = t
			}
		}
	}

	// Devices: union by public key.
	byKey := make(map[string]Device)
	devOrder := []string{}
	for _, src := range [][]Device{a.Devices, b.Devices} {
		for _, d := range src {
			k := hex.EncodeToString(d.PubKey)
			if _, ok := byKey[k]; !ok {
				devOrder = append(devOrder, k)
				byKey[k] = d
			}
		}
	}
	for _, k := range devOrder {
		out.Devices = append(out.Devices, byKey[k])
	}

	// Pending accepts: union by account, keeping the earliest queue time so the
	// TTL is measured from when the debt was actually incurred. A device that
	// has already delivered one drops it, and a merge can resurrect it from a
	// device that hasn't — that costs one redundant push, which the recipient
	// refuses outright, and the retry loop then drops it for good. Losing the
	// entry silently would be the worse failure, since the requester on the
	// other end has no way to repair the state themselves.
	byAccept := make(map[string]PendingAccept)
	acceptOrder := []string{}
	for _, src := range [][]PendingAccept{a.PendingAccepts, b.PendingAccepts} {
		for _, p := range src {
			ex, ok := byAccept[p.Account]
			if !ok {
				acceptOrder = append(acceptOrder, p.Account)
				byAccept[p.Account] = p
			} else if p.QueuedAt.Before(ex.QueuedAt) {
				byAccept[p.Account] = p
			}
		}
	}
	for _, acct := range acceptOrder {
		out.PendingAccepts = append(out.PendingAccepts, byAccept[acct])
	}

	// Deletion tombstones: union, then apply. Union because a deletion known to
	// either device is a deletion; apply afterwards because the message union
	// above may have re-added the very message one side had already dropped.
	seenDel := make(map[string]bool)
	for _, src := range [][]string{a.Deleted, b.Deleted} {
		for _, id := range src {
			if !seenDel[id] {
				seenDel[id] = true
				out.Deleted = append(out.Deleted, id)
			}
		}
	}
	// Outbox: union by message ID, keeping the earliest queue time. Union is
	// safe even though it can leave two devices both trying to deliver the same
	// message, because the recipient de-duplicates on the wire ID — a redundant
	// delivery costs one wasted circuit, whereas dropping an entry would lose a
	// message the user believes is on its way.
	seenOut := make(map[string]bool)
	for _, src := range [][]OutboxItem{a.Outbox, b.Outbox} {
		for _, it := range src {
			if ex, ok := seenOut[it.ID]; !ok || !ex {
				seenOut[it.ID] = true
				out.Outbox = append(out.Outbox, it)
			}
		}
	}
	out.Rotation = mergeRotation(a.Rotation, b.Rotation)

	// Device-local crypto/delivery state is preserved from `a` (the local device —
	// both call sites pass s.snapshotLocked() first) and `b`'s copy is NEVER
	// imported. These are per-device: another device's ratchet sessions, prekeys,
	// unacked inits and rotation-delivery bookkeeping belong to ITS ratchets, and
	// adopting them here would fork sessions or reserve the wrong one-time prekeys.
	// The result of Merge is adopted wholesale (sync.go), so without this the adopt
	// would WIPE the local device's live sessions and the peer-alias tolerance map
	// on every sync — Merge writes none of these otherwise. Rotation (above) is the
	// exception: it IS cross-device state (which alias index is current) and merges.
	out.Prekeys = a.Prekeys
	out.RatchetSessions = a.RatchetSessions
	out.PendingInits = a.PendingInits
	out.ProcessedInits = a.ProcessedInits
	out.PendingRotations = a.PendingRotations
	out.PeerAliases = a.PeerAliases
	// Invite-code state is device-local too: friend requests land on the publishing
	// device, so a secondary's stale (or empty) token must never clobber the live one
	// the primary is handing out and rotating.
	out.AutoRefresh = a.AutoRefresh
	out.InviteToken = a.InviteToken

	out.applyTombstones()
	return out
}

// mergeRotation reconciles rotation state across two devices. Rotation is
// forward-only (the index only ever increases), so the higher CurrentIndex wins
// as the current alias; alias histories are unioned by index (keeping the later
// RetireAt) so no still-live old alias is dropped just because the other device
// hadn't recorded it. Returns nil only when neither side has rotated yet.
func mergeRotation(a, b *RotationState) *RotationState {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	cur, other := a, b
	if b.CurrentIndex > a.CurrentIndex {
		cur, other = b, a
	}
	out := &RotationState{
		CurrentIndex:   cur.CurrentIndex,
		CurrentAccount: cur.CurrentAccount,
		NextRefreshAt:  cur.NextRefreshAt,
	}
	byIdx := map[uint32]AliasRecord{}
	for _, src := range [][]AliasRecord{a.History, b.History} {
		for _, r := range src {
			if ex, ok := byIdx[r.Index]; !ok || r.RetireAt.After(ex.RetireAt) {
				byIdx[r.Index] = r
			}
		}
	}
	// The loser's current alias is, from the winner's view, a retired alias still
	// in play — fold it into history so it isn't lost.
	if other.CurrentIndex != cur.CurrentIndex && other.CurrentAccount != "" {
		if _, ok := byIdx[other.CurrentIndex]; !ok {
			byIdx[other.CurrentIndex] = AliasRecord{Index: other.CurrentIndex, Account: other.CurrentAccount}
		}
	}
	for idx, r := range byIdx {
		if idx == out.CurrentIndex {
			continue // the current alias is not "history"
		}
		out.History = append(out.History, r)
	}
	sort.SliceStable(out.History, func(i, j int) bool { return out.History[i].Index < out.History[j].Index })
	return out
}

// envelope is the on-disk JSON. The plaintext (contacts + messages) is inside
// the ciphertext; only the nonce and version are in the clear.
type envelope struct {
	Version    int    `json:"version"`
	Nonce      string `json:"nonce"`      // base64
	Ciphertext string `json:"ciphertext"` // base64
}

// Store reads and writes the encrypted messages file in a data directory.
type Store struct {
	path string
	key  []byte // 32-byte AES key (identity.StoreKey)
}

// New returns a store for dir, encrypting under key.
func New(dir string, key []byte) *Store {
	return &Store{path: filepath.Join(dir, fileName), key: key}
}

// aad is the AES-GCM additional data for the local store. Unlike identity's aad
// (internal/identity/store.go), this is a FROZEN constant that must NEVER track
// fileVersion. Binding it to the version would move the AAD on a fileVersion bump,
// and a newer build could then no longer decrypt an older messages.enc in order
// to migrate it. Keeping it constant is exactly what makes the store migratable:
// decrypt under the frozen AAD regardless of version, THEN migrate the plaintext.
// (This asymmetry with identity is deliberate, not an oversight.)
func aad() []byte { return []byte("onion-chat/v1 local-store") }

// Load decrypts the stored data. A missing file yields empty Data (first run).
func (s *Store) Load() (*Data, error) {
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return &Data{}, nil
	}
	// (loaded data is normalized before returning, below)
	if err != nil {
		return nil, fmt.Errorf("read store: %w", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("parse store: %w", err)
	}
	if env.Version > fileVersion {
		return nil, fmt.Errorf("%w: file is version %d, this build supports up to %d", ErrNewerVersion, env.Version, fileVersion)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	pt, err := crypto.Open(s.key, nonce, ct, aad())
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(pt)
	var d Data
	if err := json.Unmarshal(pt, &d); err != nil {
		return nil, fmt.Errorf("parse decrypted store: %w", err)
	}
	// migrate (cross-version, bumps format) runs BEFORE normalize (within-version
	// field backfill). No-op at v1; the seam is where a future format bump hangs
	// its transform, and where an unknown lower version fails closed. The ceiling is
	// fileVersion — the shipped window — so at v1 the loop body never runs; a test
	// can pass a higher ceiling to exercise a reserved step without shipping it.
	if err := migrate(env.Version, fileVersion, &d); err != nil {
		return nil, err
	}
	d.normalize()
	return &d, nil
}

// migrate walks an older store payload from format version `from` up to `to`,
// applying one step per version. Production passes to=fileVersion (the shipped
// window), so at v1 the loop body never runs. `to` is a parameter — not the const —
// so a test can drive a reserved step (case 1 below) up to a version this build
// does not yet ship, exactly as protocol's verifyProfileSigUnder takes a candidate
// list while protoVerCurrent stays 1. Any lower/unknown version has no step and
// fails CLOSED — because chatstore's AAD is frozen, a corrupt-to-lower version DOES
// decrypt, so without this the plaintext would load as if current. A newer version
// never reaches here (Load returns ErrNewerVersion first).
func migrate(from, to int, d *Data) error {
	for v := from; v < to; v++ {
		switch v {
		case 1:
			migrate1to2(d)
		default:
			return fmt.Errorf("no store migration from format version %d", v)
		}
	}
	return nil
}

// migrate1to2 transitions the store from v1 to v2. The v2 format adds the
// Prekeys field for the Double Ratchet protocol. On upgrade from v1:
//   - Tombstones are canonicalized by sorting (existing behavior).
//   - Prekeys is left nil/empty — the application layer generates the initial
//     signed prekey and one-time prekey pool on first unlock after upgrade.
//     This is deliberate: the BIP39 seed is needed for key generation, which
//     is only available at unlock time, not during store migration.
func migrate1to2(d *Data) {
	sort.Strings(d.Deleted)
	// Prekeys field is nil by default after unmarshal; the app layer detects
	// nil and generates initial prekey material on first v2 unlock.
}

// Save encrypts and atomically writes the data with owner-only permissions.
func (s *Store) Save(d *Data) error {
	pt, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("marshal store: %w", err)
	}
	defer crypto.Zero(pt)
	nonce, ct, err := crypto.Seal(s.key, pt, aad())
	if err != nil {
		return err
	}
	env := envelope{
		Version:    fileVersion,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	return atomicWrite(s.path, data, 0o600)
}

func atomicWrite(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".messages-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
