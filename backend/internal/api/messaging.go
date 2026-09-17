package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	mathrand "math/rand"
	"net/http"
	"sort"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/device"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/pin"
	"github.com/molepipe/molepipe/backend/internal/protocol"
	"github.com/molepipe/molepipe/backend/internal/unlockguard"
)

// handleQR returns a PNG QR code of the account number (base64, so the UI can
// use a data: URL). Generated in-process — no external calls.
func (s *Server) handleQR(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	png, err := qrcode.Encode(id.AccountNumber(), qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"png": base64.StdEncoding.EncodeToString(png)})
}

const maxPendingIn = 200 // cap inbound friend requests (anti-spam)

// chatMessage is one message in the conversation log. Field-identical to
// chatstore.Message so the two convert directly.
type chatMessage struct {
	Direction string    `json:"direction"` // "in" or "out"
	Peer      string    `json:"peer"`      // the other party's account number
	Text      string    `json:"text"`
	At        time.Time `json:"at"`
	ID        string    `json:"id"`                 // deterministic sync id (chatstore.MessageID)
	Delivery  string    `json:"delivery,omitempty"` // "", "pending" or "failed"
	// Group fields — kept last and in this order so the direct chatMessage⇄
	// chatstore.Message conversion stays valid (see TestMessageStructsConvertCleanly).
	GroupID   string `json:"group_id,omitempty"`
	Author    string `json:"author,omitempty"`
	AuthorSig []byte `json:"author_sig,omitempty"`
	// Attachment fields (image messages). Same order as chatstore.Message.
	Kind     string `json:"kind,omitempty"`
	AttachID string `json:"attach_id,omitempty"`
	Mime     string `json:"mime,omitempty"`
	Size     int    `json:"size,omitempty"`
	// Group-image only (blurry thumbnail + on-demand full). Same order as
	// chatstore.Message.
	ThumbID   string `json:"thumb_id,omitempty"`
	ThumbMime string `json:"thumb_mime,omitempty"`
	FullHash  []byte `json:"full_hash,omitempty"`
	// Reactions + Reply* — kept last and in this exact order so the direct
	// chatMessage⇄chatstore.Message conversion stays valid (see
	// TestMessageStructsConvertCleanly). The client aggregates the raw Reactions
	// into counts and resolves the reply quote locally by ReplyID.
	Reactions    []chatstore.MessageReaction `json:"reactions,omitempty"`
	ReplyID      string                      `json:"reply_id,omitempty"`
	ReplyPreview string                      `json:"reply_preview,omitempty"`
	ReplyAuthor  string                      `json:"reply_author,omitempty"`
}

// replyToInput is the client's reply_to object on a send ({id, preview, author},
// or null for a non-reply). The preview/author it sends are only a hint: the
// authoritative copy is re-derived on the recipient from ReplyID, and both ends
// clamp the peer-supplied text on receive.
type replyToInput struct {
	ID      string `json:"id"`
	Preview string `json:"preview"`
	Author  string `json:"author"`
}

// toReply converts the client input to a protocol.Reply, treating a nil (absent)
// reply_to as "no reply".
func (r *replyToInput) toReply() protocol.Reply {
	if r == nil || r.ID == "" {
		return protocol.Reply{}
	}
	return protocol.Reply{ID: r.ID, Preview: r.Preview, Author: r.Author}
}

// newChatMessage stamps a message with its sync ID at creation. msgID is the
// sender-assigned wire ID, shared by both ends of the conversation, which is
// what lets "delete for everyone" name the same message on both sides. When it
// is empty (a legacy peer that sent bare text) we fall back to the deterministic
// content hash, which is still a fine local/sync identifier — such a message
// simply cannot be deleted remotely. An optional Reply attaches reply-with-context.
func newChatMessage(direction, peer, msgID, text string, at time.Time, reply ...protocol.Reply) chatMessage {
	if msgID == "" {
		msgID = chatstore.MessageID(direction, peer, text, at)
	}
	m := chatMessage{Direction: direction, Peer: peer, Text: text, At: at, ID: msgID}
	if len(reply) > 0 {
		m.ReplyID = reply[0].ID
		m.ReplyPreview = reply[0].Preview
		m.ReplyAuthor = reply[0].Author
	}
	return m
}

// --- session lifecycle ---

func (s *Server) startSession(id *identity.Identity) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	s.sessID = id
	s.myAccount = id.AccountNumber()
	s.contacts = map[string]chatstore.Contact{}
	s.messages = nil
	s.groups = map[string]chatstore.Group{}
	s.groupInvites = map[string]chatstore.GroupInvite{}
	s.sentGroupInvites = map[string]chatstore.SentGroupInvite{}
	s.reads = map[string]time.Time{}
	s.presence = map[string]string{}
	s.mailboxCheckedAt = map[string]time.Time{}
	s.attachNeed = nil
	s.displayName = ""
	s.mailboxURL = ""
	s.avatarHash = ""
	s.avatarBytesOwn = nil
	s.peer = protocol.NewPeer(id, protocol.Hooks{
		DisplayName:         s.hookDisplayName,
		AvatarHash:          s.hookAvatarHash,
		ContactMailbox:      s.hookContactMailbox,
		AllowMessage:        s.hookAllowMessage,
		Deliver:             s.deliverMessage,
		OnFriendRequest:     s.hookOnFriendRequest,
		OnFriendAccept:      s.hookOnFriendAccept,
		OnRelayRequest:      s.hookOnRelayRequest,
		OnRelayAccept:       s.hookOnRelayAccept,
		OnDeleteMessage:     s.hookOnDeleteMessage,
		OnReaction:          s.hookOnReaction,
		OnGroupInvite:       s.hookOnGroupInvite,
		OnGroupInviteAccept: s.hookOnGroupInviteAccept,
	})
	// The prober's first sweep blocks on sessMu until this function returns, so
	// it always sees the fully-loaded contact set below regardless of start order.
	s.startSessionLoops(id)

	key, err := id.StoreKey()
	if err != nil {
		log.Printf("derive store key: %v (data will not persist this session)", err)
		s.chat = nil
		return
	}
	s.chat = chatstore.New(s.store.Dir, key)
	s.attach = chatstore.NewAttachmentStore(s.store.Dir, key)
	s.avatarStore = chatstore.NewAvatarStore(s.store.Dir, key)
	data, err := s.chat.Load()
	if err != nil {
		if errors.Is(err, chatstore.ErrNewerVersion) {
			// The on-disk store was written by a newer build. Do NOT start empty —
			// adopting empty state and then persisting would overwrite (destroy) the
			// newer data. Instead refuse to persist this session, exactly like the
			// store-key-derivation failure above: s.chat == nil makes persistLocked a
			// no-op, so the newer file is left untouched until that build runs again.
			log.Printf("load store: %v — running without persistence to protect newer on-disk data", err)
			s.chat = nil
			return
		}
		log.Printf("load store: %v (starting empty)", err)
		data = &chatstore.Data{}
	}
	s.adoptDataLocked(data)
	// Only when the load succeeded is s.messages authoritative enough to sweep
	// orphaned blobs against; the "starting empty" fallback must never sweep, or
	// a transient load error would delete every attachment on disk.
	if err == nil {
		s.sweepOrphanAttachmentsLocked()
		s.sweepOrphanAvatarsLocked() // reclaim avatars orphaned by picture changes since last run
	}
	s.enrollSelfLocked(id) // ensure this device is in the linked-devices list
}

// adoptDataLocked replaces live session state with the given Data. Caller holds
// sessMu. Used on session start and after a sync merge.
func (s *Server) adoptDataLocked(data *chatstore.Data) {
	s.displayName = data.Profile.DisplayName
	s.mailboxURL = data.Profile.MailboxURL
	s.avatarHash = data.Profile.AvatarHash
	// Own-avatar bytes arrive here two ways: loaded from our own messages.enc on
	// unlock, or merged in from another of our devices over /sync. Either way, keep
	// them in memory (for re-sync) and mirror them into the avatar store keyed by
	// hash IF they are consistent — so this device can serve/render our own face by
	// hash. A mismatched or oversized blob is dropped (Put verifies both); a whole-
	// struct Profile swap on UpdatedAt keeps hash and bytes together, so this is
	// belt-and-suspenders, not load-bearing.
	s.avatarBytesOwn = data.Profile.AvatarBytes
	if s.avatarStore != nil && s.avatarHash != "" && len(s.avatarBytesOwn) > 0 && !s.avatarStore.Has(s.avatarHash) {
		if err := s.avatarStore.Put(s.avatarHash, s.avatarBytesOwn); err != nil {
			log.Printf("adopt own avatar: %v", err)
		}
	}
	s.profileAt = data.Profile.UpdatedAt
	s.backupBudget = data.Profile.GroupImageBackupBytes
	s.contacts = map[string]chatstore.Contact{}
	for _, c := range data.Contacts {
		s.contacts[c.Account] = c
	}
	s.messages = nil
	for _, m := range data.Messages {
		s.messages = append(s.messages, chatMessage(m))
	}
	// A direct image send still "pending" at load can never resolve: its delivery
	// goroutine died with the previous process and images have no outbox to retry
	// from. Mark such rows failed so the bubble doesn't read as "sending…" forever.
	for i := range s.messages {
		if s.messages[i].Kind == chatstore.KindImage && s.messages[i].Direction == "out" && s.messages[i].Delivery == chatstore.DeliveryPending {
			s.messages[i].Delivery = chatstore.DeliveryFailed
		}
	}
	s.groups = map[string]chatstore.Group{}
	for _, g := range data.Groups {
		s.groups[g.ID] = g
	}
	s.groupInvites = map[string]chatstore.GroupInvite{}
	for _, gi := range data.GroupInvites {
		s.groupInvites[gi.GroupID] = gi
	}
	s.sentGroupInvites = map[string]chatstore.SentGroupInvite{}
	for _, si := range data.SentGroupInvites {
		s.sentGroupInvites[sentInviteKey(si.GroupID, si.Account)] = si
	}
	s.reads = map[string]time.Time{}
	for acct, t := range data.Reads {
		s.reads[acct] = t
	}
	s.devices = append([]chatstore.Device(nil), data.Devices...)
	s.pendingAccepts = map[string]chatstore.PendingAccept{}
	for _, p := range data.PendingAccepts {
		s.pendingAccepts[p.Account] = p
	}
	s.deleted = append([]string(nil), data.Deleted...)
	// A tombstone that arrived via a sync merge (rather than a local delete, which
	// goes through deleteTombstone) must also drop any blob this device still
	// holds for it. Cheap: Delete is a stat+remove and a no-op for missing files.
	if s.attach != nil {
		for _, id := range s.deleted {
			s.attach.Delete(id)
		}
	}
	s.outbox = map[string]chatstore.OutboxItem{}
	for _, it := range data.Outbox {
		s.outbox[it.ID] = it
	}
}

// enrollSelfLocked adds this device to the linked-devices list if it isn't
// already there, so the primary is always an enrolled device. Caller holds sessMu.
func (s *Server) enrollSelfLocked(id *identity.Identity) {
	d := s.currentDevice()
	if d == nil {
		return
	}
	self := d.PublicKey()
	for _, d := range s.devices {
		if bytes.Equal(d.PubKey, self) {
			return
		}
	}
	s.devices = append(s.devices, chatstore.Device{PubKey: self, AddedAt: time.Now()})
	s.persistLocked()
}

// snapshotLocked builds a chatstore.Data from live session state. Caller holds sessMu.
func (s *Server) snapshotLocked() *chatstore.Data {
	data := &chatstore.Data{
		Profile: chatstore.Profile{DisplayName: s.displayName, MailboxURL: s.mailboxURL, AvatarHash: s.avatarHash, AvatarBytes: s.avatarBytesOwn, UpdatedAt: s.profileAt, GroupImageBackupBytes: s.backupBudget},
		Reads:   s.reads,
		Devices: append([]chatstore.Device(nil), s.devices...),
	}
	for _, c := range s.contacts {
		data.Contacts = append(data.Contacts, c)
	}
	for _, m := range s.messages {
		data.Messages = append(data.Messages, chatstore.Message(m))
	}
	for _, g := range s.groups {
		data.Groups = append(data.Groups, g)
	}
	for _, gi := range s.groupInvites {
		data.GroupInvites = append(data.GroupInvites, gi)
	}
	for _, si := range s.sentGroupInvites {
		data.SentGroupInvites = append(data.SentGroupInvites, si)
	}
	for _, p := range s.pendingAccepts {
		data.PendingAccepts = append(data.PendingAccepts, p)
	}
	data.Deleted = s.snapshotDeleted()
	data.Outbox = s.outboxSnapshotLocked()
	return data
}

func (s *Server) clearSession() {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	s.stopSessionLoops()
	s.cancelPublishWatchdog()
	s.sessID = nil
	s.myAccount = ""
	s.contacts = nil
	s.messages = nil
	s.groups = nil
	s.groupInvites = nil
	s.sentGroupInvites = nil
	s.reads = nil
	s.presence = nil
	s.mailboxCheckedAt = nil
	s.devices = nil
	s.displayName = ""
	s.mailboxURL = ""
	s.avatarHash = ""
	s.avatarBytesOwn = nil
	s.profileAt = time.Time{}
	s.peer = nil
	s.chat = nil
	s.attach = nil
	s.avatarStore = nil
	s.pendingAccepts = nil
	s.deleted = nil
	s.outbox = nil
	s.attachNeed = nil
}

// persistLocked writes the full session snapshot. Caller holds sessMu.
func (s *Server) persistLocked() {
	if s.chat == nil {
		return
	}
	if err := s.chat.Save(s.snapshotLocked()); err != nil {
		log.Printf("persist store: %v", err)
	}
}

func (s *Server) currentPeer() *protocol.Peer {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	return s.peer
}

// currentDevice/currentPin/currentGuard read the per-device pointers under devMu.
// reloadDeviceState swaps all three on a wipe, so every reader must snapshot them
// here rather than touch the fields directly. Each returned value has its own
// internal locking, so it is safe to use after the snapshot.
func (s *Server) currentDevice() *device.Config {
	s.devMu.RLock()
	defer s.devMu.RUnlock()
	return s.device
}

func (s *Server) currentPin() *pin.Store {
	s.devMu.RLock()
	defer s.devMu.RUnlock()
	return s.pin
}

func (s *Server) currentGuard() *unlockguard.Store {
	s.devMu.RLock()
	defer s.devMu.RUnlock()
	return s.guard
}

// --- protocol hooks (called by Peer, all after signature verification) ---

func (s *Server) hookDisplayName() string {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	return s.displayName
}

func (s *Server) hookAvatarHash() string {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	return s.avatarHash
}

// hookContactMailbox returns our mailbox URL to disclose to `sender` — but ONLY
// if sender is a fully accepted contact. This is a strict read-only status check:
// it must NOT reuse allowMessageLocked, which upgrades a pending_out contact to
// accepted (a trust-state mutation) and returns true for pending_out — either
// would leak our mailbox to someone who has merely sent us a friend request. A
// stranger or a pending contact gets "".
func (s *Server) hookContactMailbox(sender string) string {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	c, ok := s.contacts[sender]
	if !ok || c.Status != chatstore.StatusAccepted {
		return ""
	}
	return s.mailboxURL
}

// hookAllowMessage gates an inbound message and upgrades pending_out→accepted
// (an inbound message from someone we've requested means they accepted us).
func (s *Server) hookAllowMessage(sender string) bool {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	return s.allowMessageLocked(sender)
}

// allowMessageLocked gates an inbound message and upgrades pending_out→accepted.
// Caller holds sessMu. Shared by the direct-message hook and the mailbox pickup
// loop, so both apply identical contacts-only gating.
func (s *Server) allowMessageLocked(sender string) bool {
	c, ok := s.contacts[sender]
	if !ok {
		return false
	}
	switch c.Status {
	case chatstore.StatusAccepted:
		return true
	case chatstore.StatusPendingOut:
		c.Status = chatstore.StatusAccepted
		c.ReqID = ""
		s.putContactLocked(c)
		s.persistLocked()
		return true
	default: // pending_in: we haven't accepted them yet
		return false
	}
}

// putContactLocked stores a contact and stamps its UpdatedAt so multi-device
// sync can last-write-wins it. Caller holds sessMu. Use this for every contact
// mutation (not the session-load path, which must preserve synced timestamps).
func (s *Server) putContactLocked(c chatstore.Contact) {
	c.UpdatedAt = time.Now()
	s.contacts[c.Account] = c
}

func (s *Server) deliverMessage(sender, msgID, text string, reply protocol.Reply) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if s.deliverInboundLocked(sender, msgID, text, time.Now(), reply) {
		s.persistLocked()
	}
}

// deliverInboundLocked appends an inbound message unless one with the same
// content id already exists (de-dup by chatstore.MessageID). Returns true if it
// was newly added. Caller holds sessMu. This is what makes mailbox re-pickup
// (when a delete confirmation was lost) idempotent instead of duplicating.
func (s *Server) deliverInboundLocked(sender, msgID, text string, at time.Time, reply protocol.Reply) bool {
	m := newChatMessage("in", sender, msgID, text, at, reply)
	for i := range s.messages {
		if s.messages[i].ID == m.ID {
			return false
		}
	}
	// A message we already deleted must not reappear because it was redelivered
	// through the mailbox or a relay after the delete request landed.
	for _, id := range s.deleted {
		if id == m.ID {
			return false
		}
	}
	s.messages = append(s.messages, m)
	if s.onInbound != nil {
		name := sender
		avatarHash := ""
		if c, ok := s.contacts[sender]; ok {
			if c.Name != "" {
				name = c.Name
			}
			avatarHash = c.AvatarHash
		}
		// Async: a listener that hops the JNI boundary into the Android shell must
		// never block delivery or re-enter sessMu (which the caller holds).
		go s.onInbound(name, text, at.UnixMilli(), avatarHash)
	}
	return true
}

// SetInboundHook registers a callback fired asynchronously for every newly
// delivered inbound message (direct, mailbox or relay). Set once before Start;
// the Android shell uses it to raise a system notification while the window is
// closed. Passing nil clears it. Desktop leaves it unset.
func (s *Server) SetInboundHook(fn func(fromName, preview string, atMillis int64, avatarHash string)) {
	s.onInbound = fn
}

// SetFriendRequestHook registers a callback for inbound friend requests.
func (s *Server) SetFriendRequestHook(fn func(fromName string)) {
	s.onFriendRequest = fn
}

// SetGroupInviteHook registers a callback for inbound group invites.
func (s *Server) SetGroupInviteHook(fn func(inviterName, groupName string)) {
	s.onGroupInvite = fn
}

func (s *Server) hookOnFriendRequest(from, name, reqID string) error {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if existing, ok := s.contacts[from]; ok {
		switch existing.Status {
		case chatstore.StatusBlocked:
			return fmt.Errorf("blocked") // silently reject requests from blocked accounts
		case chatstore.StatusAccepted:
			return nil // already friends
		case chatstore.StatusPendingOut:
			// Cross request: we each requested the other → mutual, accept.
			existing.Status = chatstore.StatusAccepted
			existing.ReqID = ""
			if existing.Name == "" {
				existing.Name = name
			}
			s.putContactLocked(existing)
			s.persistLocked()
			return nil
		}
		// pending_in already: refresh it below (dedupe, no growth).
	} else if s.countPendingInLocked() >= maxPendingIn {
		return fmt.Errorf("too many pending requests")
	}
	s.putContactLocked(chatstore.Contact{Account: from, Name: name, Status: chatstore.StatusPendingIn, ReqID: reqID})
	s.persistLocked()
	// Notify the Android shell so it can post a system notification.
	if fn := s.onFriendRequest; fn != nil {
		go fn(name)
	}
	return nil
}

func (s *Server) hookOnFriendAccept(from, name, reqID string) error {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	c, ok := s.contacts[from]
	if !ok || c.Status != chatstore.StatusPendingOut || c.ReqID == "" || c.ReqID != reqID {
		return fmt.Errorf("no matching pending request")
	}
	c.Status = chatstore.StatusAccepted
	c.ReqID = ""
	if c.Name == "" {
		c.Name = name
	}
	s.putContactLocked(c)
	s.persistLocked()
	return nil
}

func (s *Server) countPendingInLocked() int {
	n := 0
	for _, c := range s.contacts {
		if c.Status == chatstore.StatusPendingIn {
			n++
		}
	}
	return n
}

// --- peer-facing handlers (onion listener) ---

func (s *Server) handleP2PChallenge(w http.ResponseWriter, r *http.Request) {
	peer := s.currentPeer()
	if peer == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, peer.Challenge())
}

func (s *Server) handleP2PProfile(w http.ResponseWriter, r *http.Request) {
	peer := s.currentPeer()
	if peer == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, peer.ProfileCard())
}

// handleP2PContactProfile serves the operational profile fields (mailbox URL)
// that are kept OUT of the public card, to an accepted contact who proves their
// identity. ServeContactProfile verifies the one-time nonce + signature; the
// hookContactMailbox gate returns "" for anyone who isn't a fully accepted
// contact. The response is uniform (mailbox or "") so it is not an oracle.
func (s *Server) handleP2PContactProfile(w http.ResponseWriter, r *http.Request) {
	peer := s.currentPeer()
	if peer == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	var req protocol.ContactProfileRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	cp, err := peer.ServeContactProfile(req)
	if err != nil {
		http.Error(w, "rejected", http.StatusBadRequest) // generic; don't leak which check failed
		return
	}
	writeJSON(w, http.StatusOK, cp)
}

func (s *Server) handleP2PMessage(w http.ResponseWriter, r *http.Request) {
	peer := s.currentPeer()
	if peer == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	var e protocol.Envelope
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&e); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := peer.Receive(e); err != nil {
		http.Error(w, "rejected", http.StatusBadRequest) // generic; don't leak which check failed
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleP2PFriendRequest(w http.ResponseWriter, r *http.Request) {
	peer := s.currentPeer()
	if peer == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	var req protocol.FriendRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := peer.ReceiveFriendRequest(req); err != nil {
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleP2PFriendAccept(w http.ResponseWriter, r *http.Request) {
	peer := s.currentPeer()
	if peer == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	var acc protocol.FriendAccept
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&acc); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := peer.ReceiveFriendAccept(acc); err != nil {
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// --- control API: profile ---

func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	s.sessMu.Lock()
	name, mailbox, budget, avatar := s.displayName, s.mailboxURL, s.backupBudget, s.avatarHash
	s.sessMu.Unlock()
	// Hand-built subset (never marshals chatstore.Profile), so the own-avatar bytes
	// that ride in Profile for /sync never leak into this UI poll — only the hash.
	writeJSON(w, http.StatusOK, map[string]any{"account": id.AccountNumber(), "display_name": name, "mailbox_url": mailbox, "group_image_backup_bytes": budget, "avatar_hash": avatar})
}

func (s *Server) handleSetProfile(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	// Pointer fields distinguish "field omitted" (leave unchanged) from "set to
	// empty", so the display-name form and the mailbox form don't clobber each other.
	var req struct {
		DisplayName           *string `json:"display_name"`
		MailboxURL            *string `json:"mailbox_url"`
		GroupImageBackupBytes *int64  `json:"group_image_backup_bytes"`
		// Avatar is the base64 (std) of a client-cropped square image, or "" to
		// clear. nil = leave unchanged, like the other pointer fields. The client
		// does all image work (crop/downscale) — the Go backend is gomobile-
		// portable, so it never decodes/resizes; it only validates type+size and
		// stores the bytes.
		Avatar *string `json:"avatar"`
	}
	// The body cap allows one base64 avatar (~88 KB for a 64 KiB image) plus the
	// small text fields. Without an avatar the request is a few hundred bytes; the
	// larger ceiling is only reached when a picture is actually being set.
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*protocol.MaxAvatarBytes+1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Decode + validate the avatar OUTSIDE the session lock (base64 decode + a
	// content sniff shouldn't hold sessMu). A parse/validation failure is reported
	// before any state changes.
	var (
		setAvatar   bool
		avatarHash  string
		avatarBytes []byte
	)
	if req.Avatar != nil {
		if *req.Avatar == "" {
			setAvatar = true // clear
		} else {
			data, err := base64.StdEncoding.DecodeString(*req.Avatar)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "avatar is not valid base64"})
				return
			}
			if len(data) == 0 || len(data) > protocol.MaxAvatarBytes {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "avatar too large"})
				return
			}
			if _, ok := avatarContentType(data); !ok {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "avatar must be a JPEG, PNG, WebP, or GIF image"})
				return
			}
			setAvatar, avatarBytes = true, data
			avatarHash = chatstore.AvatarHashBytes(data)
		}
	}
	s.sessMu.Lock()
	if setAvatar {
		if len(avatarBytes) == 0 {
			s.avatarHash, s.avatarBytesOwn = "", nil // clear
		} else if s.avatarStore != nil {
			if err := s.avatarStore.Put(avatarHash, avatarBytes); err != nil {
				s.sessMu.Unlock()
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store avatar"})
				return
			}
			s.avatarHash, s.avatarBytesOwn = avatarHash, avatarBytes
		}
	}
	if req.DisplayName != nil {
		cleaned, err := validateDisplayName(*req.DisplayName)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		s.displayName = cleaned
	}
	if req.MailboxURL != nil {
		mailbox, err := normalizeMailboxURL(*req.MailboxURL)
		if err != nil {
			s.sessMu.Unlock()
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		s.mailboxURL = mailbox
	}
	// Turning the budget off (nonzero -> 0) purges the backups we already stashed in
	// our own mailbox, so "off" actually reclaims the space rather than just halting
	// new drop-offs. The purge runs off the request path (it dials our onion).
	turnedOff := false
	if req.GroupImageBackupBytes != nil {
		b := *req.GroupImageBackupBytes
		if b < 0 {
			b = 0
		}
		turnedOff = s.backupBudget > 0 && b == 0
		s.backupBudget = b
	}
	s.profileAt = time.Now() // for multi-device sync LWW
	name, mailbox, budget, avatar := s.displayName, s.mailboxURL, s.backupBudget, s.avatarHash
	if setAvatar {
		// Changing or clearing our own picture orphans the previous own-avatar bytes
		// (no contact references them); reclaim now so a long unlocked session can't
		// wall off the store one picture-change at a time.
		s.sweepOrphanAvatarsLocked()
	}
	s.persistLocked()
	s.sessMu.Unlock()
	if turnedOff {
		go s.purgeGroupImageBackups() // dials our onion; keep it off the request path
	}
	writeJSON(w, http.StatusOK, map[string]any{"display_name": name, "mailbox_url": mailbox, "group_image_backup_bytes": budget, "avatar_hash": avatar})
}

// handleRestoreGroupImages nudges an immediate restore of full group images from
// our own durable mailbox backups (the mailbox loop also does this on its own,
// but a user who just restored a device wants it now, not on the next tick). The
// restore dials our onion and pulls blobs one at a time, so it runs off the
// request path; the row's thumbnails/full images light up as blobs land.
func (s *Server) handleRestoreGroupImages(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	s.sessMu.Lock()
	mailbox := s.mailboxURL
	s.sessMu.Unlock()
	if mailbox == "" || s.onion == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no mailbox is configured, or Tor is disabled"})
		return
	}
	go func() {
		if n, err := s.restoreGroupImageBackups(context.Background(), id, true); err != nil {
			log.Printf("group-image backup restore (manual): %v", err)
		} else {
			log.Printf("manual restore recovered %d group image(s) from backup", n)
		}
	}()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "started"})
}

// --- control API: lookup + friend requests ---

func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	var req struct {
		Account string `json:"account"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if _, err := identity.AccountNumberFromString(req.Account); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid account number"})
		return
	}
	if s.onion == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Tor is disabled"})
		return
	}
	// Deliberately NOT r.Context()+90s. A lookup dials a peer onion, which is
	// inherently flaky: intro points drop, descriptors go stale, and a mobile
	// peer can take 20-40s to reach even when it IS online — so one attempt fails
	// far more often than the peer is actually unreachable. Retry against a fresh
	// circuit until an overall budget expires, on a background context so a
	// browser hiccup can't cancel the dial mid-flight (the send path's lesson).
	ctx, cancel := deliveryContext(lookupTotalTimeout)
	defer cancel()
	var pr protocol.Profile
	err := reachRetry(ctx, lookupAttemptTimeout, lookupRetryGap, func(actx context.Context) error {
		var e error
		pr, e = protocol.FetchProfile(actx, s.onion.Dialer(), req.Account)
		return e
	})
	if err != nil {
		// The only prior record of a failed lookup was a bare status code, which
		// made "why can't I reach anyone" undiagnosable without a packet capture.
		log.Printf("lookup of %s failed after retries: %v", req.Account, err)
		status, reason, msg := reachFailure(err, s.onion.Dialable(), "reach that account")
		writeJSON(w, status, map[string]string{"error": msg, "reason": reason})
		return
	}
	// Best-effort avatar preview at add-time: the card carries the hash; pull the
	// bytes from the peer's ungated AvatarPath and cache them so the UI can render
	// the face by hash. A failure here never fails the lookup — the name+account
	// still return, just without a picture. This is one of only two places that
	// fetch avatar bytes (the other is the presence sweep); both already dial the
	// peer, so no render ever triggers a dial.
	if pr.AvatarHash != "" {
		if data, aerr := protocol.FetchAvatar(ctx, s.onion.Dialer(), req.Account, pr.AvatarHash); aerr == nil {
			s.sessMu.Lock()
			if s.avatarStore != nil {
				_ = s.avatarStore.Put(pr.AvatarHash, data)
				// If this account is already a contact (re-lookup, or a pending
				// request), record the hash on the row under the SAME lock as the Put
				// so the orphan sweep's keep-set protects these bytes — and so the row
				// renders the face immediately instead of waiting for the first
				// post-accept presence sweep (a previously known gap). A PURE STRANGER
				// has no row to anchor to: their preview bytes are deliberately
				// best-effort and may be reclaimed by a later sweep; the frontend
				// fetches them into an object URL right after this returns, and a
				// re-lookup re-caches them, so the add-time face still does its job.
				if c, ok := s.contacts[req.Account]; ok && c.AvatarHash != pr.AvatarHash {
					c.AvatarHash = pr.AvatarHash
					s.contacts[req.Account] = c
					s.persistLocked()
				}
			}
			s.sessMu.Unlock()
		} else {
			log.Printf("lookup avatar fetch for %s failed: %v", req.Account, aerr)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"account": pr.Account, "display_name": pr.DisplayName, "reachable": true, "avatar_hash": pr.AvatarHash})
}

func (s *Server) handleSendRequest(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		Account string `json:"account"`
		Name    string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if _, err := identity.AccountNumberFromString(req.Account); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid account number"})
		return
	}
	if req.Account == id.AccountNumber() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "that's your own account"})
		return
	}
	s.sessMu.Lock()
	existing, ok := s.contacts[req.Account]
	name, dial := s.displayName, s.onion
	s.sessMu.Unlock()
	if ok && existing.Status == chatstore.StatusAccepted {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "already a contact"})
		return
	}
	if ok && existing.Status == chatstore.StatusPendingIn {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "they already sent you a request — accept it instead"})
		return
	}
	if ok && existing.Status == chatstore.StatusBlocked {
		// You blocked them; a friend request would silently un-block by intent.
		// Refuse so blocking isn't quietly undone — e.g. from the group member list,
		// where a blocked account still appears as a co-member.
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "you have blocked this account — unblock it first"})
		return
	}
	if dial == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Tor is disabled"})
		return
	}

	// One reqID across all retries: a retry re-sends the SAME request (the peer
	// dedups pending_in by account), so an attempt that landed but whose reply was
	// lost isn't turned into a second distinct request.
	reqID := randomID()
	ctx, cancel := deliveryContext(lookupTotalTimeout)
	defer cancel()
	err := reachRetry(ctx, lookupAttemptTimeout, lookupRetryGap, func(actx context.Context) error {
		return protocol.SendFriendRequest(actx, dial.Dialer(), id, name, reqID, req.Account)
	})
	if err != nil {
		// Never surface err.Error() to the UI: a StatusError carries the peer's own
		// response body (peer-controlled bytes). Log it; show only our own copy.
		log.Printf("friend request to %s failed after retries: %v", req.Account, err)
		status, reason, msg := reachFailure(err, dial.Dialable(), "send the request")
		writeJSON(w, status, map[string]string{"error": msg, "reason": reason})
		return
	}
	s.sessMu.Lock()
	s.putContactLocked(chatstore.Contact{Account: req.Account, Name: req.Name, Status: chatstore.StatusPendingOut, ReqID: reqID})
	s.persistLocked()
	s.sessMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "requested"})
}

func (s *Server) handleAcceptRequest(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		Account string `json:"account"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.sessMu.Lock()
	c, ok := s.contacts[req.Account]
	name, dial := s.displayName, s.onion
	if !ok || c.Status != chatstore.StatusPendingIn {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no such pending request"})
		return
	}
	reqID := c.ReqID
	c.Status = chatstore.StatusAccepted
	c.ReqID = ""
	s.putContactLocked(c)
	// Queue the accept BEFORE attempting to push it. If the push succeeds we
	// dequeue immediately below; if the process dies mid-push, the queue is
	// already on disk. Getting this order wrong is what stranded requesters:
	// they cannot repair the state from their side, so the debt must survive.
	s.queueAcceptLocked(req.Account, reqID)
	s.persistLocked()
	s.sessMu.Unlock()

	notified := false
	if dial != nil {
		ctx, cancel := deliveryContext(2 * time.Minute)
		defer cancel()
		if err := protocol.SendFriendAccept(ctx, dial.Dialer(), id, name, reqID, req.Account); err != nil {
			log.Printf("friend-accept push to %s failed, queued for retry: %v", req.Account, err)
		} else {
			notified = true
			s.sessMu.Lock()
			s.dequeueAcceptLocked(req.Account)
			s.persistLocked()
			s.sessMu.Unlock()
		}
	}
	// Report honestly whether the other side actually heard about it. Until they
	// do, they stay stuck at "pending" and cannot message us.
	writeJSON(w, http.StatusOK, map[string]any{"status": "accepted", "notified": notified})
}

func (s *Server) handleDeclineRequest(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	var req struct {
		Account string `json:"account"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.sessMu.Lock()
	if c, ok := s.contacts[req.Account]; ok && c.Status == chatstore.StatusPendingIn {
		delete(s.contacts, req.Account)
		s.persistLocked()
	}
	s.sessMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "declined"})
}

func (s *Server) handleListRequests(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	s.sessMu.Lock()
	out := []map[string]string{}
	for _, c := range s.contacts {
		if c.Status == chatstore.StatusPendingIn {
			out = append(out, map[string]string{"account": c.Account, "name": c.Name})
		}
	}
	s.sessMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"requests": out})
}

// --- control API: contacts + messages ---

// handleAddContact directly adds an accepted contact (unilateral). The friend
// request flow is preferred; this remains for power users / tooling.
func (s *Server) handleAddContact(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	var req struct {
		Account string `json:"account"`
		Name    string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if _, err := identity.AccountNumberFromString(req.Account); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid account number"})
		return
	}
	s.sessMu.Lock()
	s.putContactLocked(chatstore.Contact{Account: req.Account, Name: req.Name, Status: chatstore.StatusAccepted})
	s.persistLocked()
	s.sessMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "added"})
}

// handleDeleteContact removes a contact (and any conversation state stays, but
// the contact disappears from the list). Also usable to remove a pending_out.
func (s *Server) handleDeleteContact(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	acct := s.decodeAccount(w, r)
	if acct == "" {
		return
	}
	s.sessMu.Lock()
	delete(s.contacts, acct)
	s.persistLocked()
	s.sessMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleBlockContact marks an account blocked: their messages and friend
// requests are rejected, and they no longer appear in the contact list.
func (s *Server) handleBlockContact(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	acct := s.decodeAccount(w, r)
	if acct == "" {
		return
	}
	s.sessMu.Lock()
	c := s.contacts[acct]
	c.Account = acct
	c.Status = chatstore.StatusBlocked
	c.ReqID = ""
	s.putContactLocked(c)
	s.persistLocked()
	s.sessMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "blocked"})
}

// decodeAccount reads {account} and validates it; writes an error and returns ""
// on failure.
func (s *Server) decodeAccount(w http.ResponseWriter, r *http.Request) string {
	var req struct {
		Account string `json:"account"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return ""
	}
	if _, err := identity.AccountNumberFromString(req.Account); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid account number"})
		return ""
	}
	return req.Account
}

func (s *Server) handleListContacts(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	s.sessMu.Lock()
	_, haveRelay := s.firstRelayHolderLocked()
	out := []map[string]any{}
	for _, c := range s.contacts {
		if c.Status != chatstore.StatusAccepted && c.Status != chatstore.StatusPendingOut {
			continue
		}
		unread := 0
		if c.Status == chatstore.StatusAccepted {
			last := s.reads[c.Account]
			for _, m := range s.messages {
				if m.Peer == c.Account && m.Direction == "in" && m.At.After(last) {
					unread++
				}
			}
		}
		presence := s.presence[c.Account]
		if presence == "" {
			presence = presenceUnknown
		}
		out = append(out, map[string]any{
			"account": c.Account, "name": c.Name, "status": c.Status,
			"unread": unread, "presence": presence, "mailbox_url": c.MailboxURL,
			// The contact's avatar hash; the UI renders it via GET /api/avatar?h=…
			// from the local cache, falling back to initials when absent/uncached.
			"avatar_hash":   c.AvatarHash,
			"relay_pending": c.RelayPending, "relay_grant": c.RelayGrant, "relay_holder": c.RelayHolder,
			// True when routing to them through a friend-relay is actually possible
			// right now: we hold at least one approved relay-holder AND we have their
			// encryption key to seal the envelope. The offline-send popup keys off
			// this so it never offers a relay it cannot use.
			"relay_available": haveRelay && len(c.DHPub) == 32,
			// True while we've accepted them but the accept push hasn't landed:
			// they still see us as pending and can't message us yet.
			"awaiting_accept": s.awaitingAcceptLocked(c.Account),
		})
	}
	s.sessMu.Unlock()
	// Map iteration order is randomised per call; return a stable order so no
	// consumer sees the list reshuffle between polls. The frontend re-sorts by
	// recency for display; this just guarantees a deterministic baseline.
	sort.Slice(out, func(i, j int) bool {
		return out[i]["account"].(string) < out[j]["account"].(string)
	})
	writeJSON(w, http.StatusOK, map[string]any{"contacts": out})
}

// handleMarkRead marks a conversation read up to now.
func (s *Server) handleMarkRead(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	acct := s.decodeAccount(w, r)
	if acct == "" {
		return
	}
	s.sessMu.Lock()
	if s.reads == nil {
		s.reads = map[string]time.Time{}
	}
	s.reads[acct] = time.Now()
	s.persistLocked()
	s.sessMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "read"})
}

func (s *Server) handleListMessages(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	s.sessMu.Lock()
	_, haveRelay := s.firstRelayHolderLocked()
	out := make([]map[string]any, 0, len(s.messages))
	for _, m := range s.messages {
		row := map[string]any{
			"direction": m.Direction, "peer": m.Peer, "text": m.Text,
			"at": m.At, "id": m.ID,
		}
		// Group messages carry their group + original author so the UI can render
		// them in the group conversation with the sender's name (Peer is "" for
		// them — see the chatstore.Message invariant).
		if m.GroupID != "" {
			row["group_id"] = m.GroupID
			row["author"] = m.Author
			row["author_name"] = s.groupAuthorNameLocked(m.GroupID, m.Author)
		}
		// Image messages carry no text; the UI renders the blob from
		// GET /api/attachment?id=<id> using kind+mime.
		if m.Kind == chatstore.KindImage {
			row["kind"] = m.Kind
			row["mime"] = m.Mime
			// A GROUP image shows a blurry thumbnail (thumb_id) and downloads the full
			// (attach_id) on demand; has_full says whether the full is already local.
			// A 1:1 image renders by its row id, so it needs none of these.
			if m.GroupID != "" && m.ThumbID != "" {
				row["thumb_id"] = m.ThumbID
				row["attach_id"] = m.AttachID
				row["has_full"] = s.attach != nil && s.attach.Has(m.AttachID)
			}
		}
		if m.Delivery != "" {
			row["delivery"] = m.Delivery
		}
		// Reply-with-context: the client renders the quote and resolves the author
		// label locally by this id (the author on the wire is direction-relative, so
		// it is never trusted for display). Present only on 1:1 messages today.
		if m.ReplyID != "" {
			row["reply_to"] = map[string]any{"id": m.ReplyID, "preview": m.ReplyPreview, "author": m.ReplyAuthor}
		}
		// Reactions ride raw ({emoji, by}); the client aggregates into chips and
		// marks its own by matching `by` against the account number.
		if len(m.Reactions) > 0 {
			row["reactions"] = m.Reactions
		}
		// A failed send carries the reason and whether a friend-relay is an
		// option. These used to ride on the send response, which no longer
		// exists now that sending is asynchronous, so they live here instead —
		// otherwise the retry and relay affordances lose their inputs.
		if it, ok := s.outbox[m.ID]; ok && it.Failed {
			row["error"] = it.LastError
			c := s.contacts[m.Peer]
			row["relay_available"] = haveRelay && len(c.DHPub) == 32
		}
		out = append(out, row)
	}
	s.sessMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"messages": out})
}

func (s *Server) handleSendMessage(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		To      string        `json:"to"`
		Text    string        `json:"text"`
		ReplyTo *replyToInput `json:"reply_to"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.sessMu.Lock()
	c, ok := s.contacts[req.To]
	s.sessMu.Unlock()
	if !ok || c.Status != chatstore.StatusAccepted {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "recipient is not an accepted contact"})
		return
	}
	if s.onion == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Tor is disabled"})
		return
	}

	// One ID for this message, minted here and carried on the wire, so both
	// sides name it identically if it is later deleted for everyone.
	msgID := randomID()
	reply := req.ReplyTo.toReply()

	// Accept, persist, acknowledge. Delivery happens off the request path: a
	// Tor circuit takes seconds at best, and blocking the compose box for that
	// made the app feel broken while also losing the message whenever the one
	// attempt failed.
	s.sessMu.Lock()
	s.enqueueSendLocked(req.To, msgID, req.Text, reply)
	item := s.outbox[msgID]
	s.sessMu.Unlock()
	s.deliverNow(id, item)

	writeJSON(w, http.StatusOK, map[string]any{"status": "queued", "id": msgID})
}

// handleRetryMessage re-arms a failed send. It re-uses the existing queue entry
// rather than creating one, so a retry can never append a second copy of a
// message that is already in the conversation.
func (s *Server) handleRetryMessage(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.sessMu.Lock()
	it, ok := s.outbox[req.ID]
	if !ok {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "that message is not waiting to be sent"})
		return
	}
	it.Failed = false
	it.Attempts = 0
	it.LastError = ""
	it.QueuedAt = time.Now()
	s.outbox[req.ID] = it
	s.setDeliveryLocked(req.ID, chatstore.DeliveryPending)
	s.persistLocked()
	s.sessMu.Unlock()

	s.deliverNow(id, it)
	writeJSON(w, http.StatusOK, map[string]any{"status": "queued", "id": req.ID})
}

// Delivery timeouts. These are separate budgets, not slices of one, because
// sharing a single deadline is what made the mailbox fallback unreachable on
// live Tor: a 90s direct attempt against a 120s budget left the drop-off ~30s,
// which is not enough to reach a cold onion, so it failed every time.
const (
	// sendDirectTimeout applies when there is nowhere else to go, so it is
	// worth waiting out a slow circuit.
	sendDirectTimeout = 90 * time.Second
	// sendDirectProbeTimeout applies when a mailbox fallback exists. A healthy
	// direct send lands in a few seconds (3.4s measured over real Tor), so this
	// is generous for the success case while failing fast enough to leave the
	// fallback a real budget. Falling back early costs the recipient a little
	// latency; failing to fall back costs them the message.
	sendDirectProbeTimeout = 25 * time.Second
	// mailboxDropTimeout is a full budget of its own — the mailbox onion is
	// typically cold, having never been dialled before.
	mailboxDropTimeout = 90 * time.Second
)

// deliveryContext returns a context for an outbound Tor operation that must not
// be abandoned because the browser gave up. Deliberately NOT derived from
// r.Context(): a tab closing mid-send otherwise cancels the write in flight,
// which we watched truncate a mailbox drop-off on live Tor ("context canceled"
// partway through the POST). Reads the user is actively waiting on — a profile
// lookup — keep the request context, since cancelling those costs nothing.
func deliveryContext(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// Reach budgets for interactive peer lookups / friend requests. A cold onion is
// ~24s and a flaky mobile peer often needs a second or third circuit, so the
// per-attempt budget is generous and the overall budget allows a few tries.
const (
	lookupTotalTimeout   = 2 * time.Minute
	lookupAttemptTimeout = 40 * time.Second
	lookupRetryGap       = 3 * time.Second
)

// reachFailure turns a failed peer op into an honest, class-driven message for
// the UI plus a machine reason code (the "why did the dial fail" signal), and
// the HTTP status to answer with. action names the attempted verb ("reach that
// account") so the transient copy reads naturally at each call site.
//
// The "you're offline" overlay is applied ONLY on the transient branch. A
// Protocol or Rejected class PROVES we reached the peer — their answer came back
// and failed our verification, or they refused it — so blaming our own transport
// there, even if Dialable() has momentarily flapped false right after a
// successful round-trip, would resurrect the exact undiagnosable-error problem
// the taxonomy exists to end. Only a transient miss (we never got a good answer)
// can honestly be "maybe us, maybe them", and there Dialable() breaks the tie.
//
// It never renders a peer-controlled StatusError.Body: the caller logs the raw
// error; the user sees only our own copy (and, at most, an HTTP code).
func reachFailure(err error, dialable bool, action string) (status int, reason, msg string) {
	switch protocol.Classify(err) {
	case protocol.ClassProtocol:
		return http.StatusBadGateway, "protocol",
			"Reached them, but their app's reply didn't verify — they may be running an incompatible version."
	case protocol.ClassPeerRejected:
		return http.StatusBadGateway, "rejected",
			"They're reachable but refused the request."
	default:
		if !dialable {
			return http.StatusServiceUnavailable, "offline",
				"You're not connected to Tor yet — still connecting. Give it a moment, then try again."
		}
		return http.StatusBadGateway, "unreachable",
			"Couldn't " + action + ". They may be offline — a phone can take a minute to become reachable. Check the number and try again."
	}
}

// reachRetry runs a Tor operation against a peer onion repeatedly until it
// succeeds or ctx expires, pausing gap between attempts and bounding each
// attempt to attemptTimeout. Onion-service connections are flaky — intro points
// come and go, descriptors go stale, mobile peers are slow to reach — so a
// retry against a fresh circuit succeeds far more often than a single attempt,
// which is what made peers seem unreachable "even when online". Returns the last
// error if the budget runs out.
func reachRetry(ctx context.Context, attemptTimeout, gap time.Duration, op func(context.Context) error) error {
	var lastErr error
	for attempt := 0; ; attempt++ {
		actx, cancel := context.WithTimeout(ctx, attemptTimeout)
		err := op(actx)
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		// A TERMINAL failure fails identically on every retry — the peer answered
		// and refused (4xx), its answer failed our verification (fixed key), or the
		// caller canceled — so keep looping only on the transient classes
		// (unreachable / timeout). Before this, a signature-invalid peer or a hard
		// refusal burned the full multi-minute budget on a retry that could never
		// succeed, which read to the user as a long hang.
		if !protocol.Classify(err).Retryable() {
			return lastErr
		}
		select {
		case <-ctx.Done():
			return lastErr
		case <-time.After(reachBackoff(gap, attempt)):
		}
	}
}

// reachBackoff spaces retries with full-jitter exponential backoff off base
// (gap * 2^attempt, saturated at a cap), then a uniform random point in [0, that]).
// Backing off rather than hammering a fixed interval eases a briefly-overloaded
// peer, and the jitter keeps concurrent retries to different peers from aligning
// into bursts. The cap keeps a single gap well under the overall budget so a late
// attempt still fits. Onion reach is dominated by the per-attempt timeout, not the
// gap, so this is a modest but correct improvement over the old fixed pause.
func reachBackoff(base time.Duration, attempt int) time.Duration {
	if base <= 0 {
		return 0
	}
	const capGap = 30 * time.Second
	d := base
	for i := 0; i < attempt && d < capGap; i++ {
		d *= 2
	}
	if d > capGap {
		d = capGap
	}
	return time.Duration(mathrand.Int63n(int64(d) + 1))
}

// canMailbox reports whether we hold what a mailbox drop-off needs: the
// recipient's mailbox address and the X25519 key to encrypt to, both cached
// from a signed profile while they were online.
func canMailbox(c chatstore.Contact) bool {
	return c.MailboxURL != "" && len(c.DHPub) == 32
}

// tryMailboxDropoff seals the message and drops it at the recipient's cached
// mailbox. Returns true on success. Branches on the cached data (not the 45s
// presence label, which is stale at send time).
func (s *Server) tryMailboxDropoff(ctx context.Context, id *identity.Identity, c chatstore.Contact, msgID, text string, reply ...protocol.Reply) bool {
	if !canMailbox(c) {
		return false
	}
	var dh [32]byte
	copy(dh[:], c.DHPub)
	env, err := protocol.SealMailEnvelope(id, c.Account, dh, msgID, text, time.Now(), reply...)
	if err != nil {
		log.Printf("seal mailbox message: %v", err)
		return false
	}
	if err := protocol.MailboxDropOff(ctx, s.onion.Dialer(), env, c.MailboxURL); err != nil {
		log.Printf("mailbox drop-off to %s: %v", c.MailboxURL, err)
		return false
	}
	return true
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// validateDisplayName trims whitespace, enforces a maximum length, and rejects
// empty names. Returns the cleaned name or an error.
func validateDisplayName(raw string) (string, error) {
	name := []rune(strings.TrimSpace(raw))
	if len(name) == 0 {
		return "", fmt.Errorf("display name must not be empty")
	}
	if len(name) > 64 {
		name = name[:64]
	}
	return string(name), nil
}
