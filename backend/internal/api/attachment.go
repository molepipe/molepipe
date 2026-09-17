package api

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// imageSendTimeout bounds a single direct image transfer over Tor. There is NO
// retry/outbox for images: they are direct-only (both peers online), so a
// failure just means "not reachable now" and shows as a failed bubble.
const imageSendTimeout = 90 * time.Second

// primaryFetchTimeout bounds the secondary→own-primary fallback fetch for a group
// image full (handleDownloadGroupImage). It is one self-onion hop that either
// connects or doesn't, so it gets a shorter budget than a full peer transfer —
// keeping the two-legs-in-series worst case well under imageSendTimeout×2.
const primaryFetchTimeout = 45 * time.Second

// attachBodyCap bounds an image request/response body: base64 of a 3 MiB image
// is ~4 MiB, plus JSON overhead. This is the DoS ceiling on both the control
// send endpoint and the onion receive endpoint.
const attachBodyCap = 2*protocol.MaxAttachmentBytes + 1<<16

// handleSendImage accepts an image for a 1:1 contact, stores it in the encrypted
// attachment store, files an "out" image message, and delivers it DIRECT only —
// never friend-relay (would overload friends) and never mailbox (it caps blobs
// far below an image). Best-effort + asynchronous, like text sends.
func (s *Server) handleSendImage(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		To   string `json:"to"`
		Mime string `json:"mime"`
		Data string `json:"data"` // base64 image bytes
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, attachBodyCap)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !protocol.AllowedImageMIME(req.Mime) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported image type"})
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil || len(data) == 0 || len(data) > protocol.MaxAttachmentBytes {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "image is missing or too large"})
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

	msgID := randomID() // shared wire id, also the attachment id
	s.sessMu.Lock()
	if s.attach == nil {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage unavailable"})
		return
	}
	if err := s.attach.Put(msgID, data); err != nil {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusInsufficientStorage, map[string]string{"error": err.Error()})
		return
	}
	s.messages = append(s.messages, chatMessage{
		Direction: "out", Peer: req.To, At: time.Now(), ID: msgID, Delivery: chatstore.DeliveryPending,
		Kind: chatstore.KindImage, AttachID: msgID, Mime: req.Mime, Size: len(data),
	})
	s.persistLocked()
	s.sessMu.Unlock()

	go s.deliverImageDirect(id, req.To, msgID, req.Mime)
	writeJSON(w, http.StatusOK, map[string]any{"status": "queued", "id": msgID})
}

// deliverImageDirect makes a single direct attempt and reflects the outcome on
// the message's delivery state. No retry/outbox — direct-only. It re-reads the
// image from the store rather than holding the (multi-MB) bytes in a goroutine
// that can live up to imageSendTimeout — the stored copy is authoritative.
func (s *Server) deliverImageDirect(id *identity.Identity, to, msgID, mime string) {
	s.sessMu.Lock()
	store := s.attach
	s.sessMu.Unlock()
	fail := func() {
		s.sessMu.Lock()
		s.setDeliveryLocked(msgID, chatstore.DeliveryFailed)
		s.persistLocked()
		s.sessMu.Unlock()
	}
	if store == nil {
		fail()
		return
	}
	data, err := store.Get(msgID)
	if err != nil {
		fail()
		return
	}
	ctx, cancel := deliveryContext(imageSendTimeout)
	defer cancel()
	if err := protocol.SendAttachment(ctx, s.onion.Dialer(), id, to, msgID, mime, data); err != nil {
		// Direct failed — they may be offline. Fall back to their OWN mailbox if
		// they have one that accepts an image this size. Still no friend-relay and
		// no retry queue: one mailbox attempt, then it waits until they're online.
		if s.tryMailboxImageDropoff(id, to, msgID, mime, data) {
			s.sessMu.Lock()
			s.setDeliveryLocked(msgID, "") // handed to their mailbox
			s.persistLocked()
			s.sessMu.Unlock()
			return
		}
		log.Printf("image send to %s failed (direct + mailbox): %v", to, err)
		fail()
		return
	}
	s.sessMu.Lock()
	s.setDeliveryLocked(msgID, "")
	s.persistLocked()
	s.sessMu.Unlock()
}

// tryMailboxImageDropoff leaves an image at the recipient's OWN mailbox when a
// direct send failed. Returns true only if the mailbox accepted it: a box whose
// per-blob cap is smaller than the image (the operator has not opted into images)
// answers 507, and the image then waits until the recipient is online, exactly
// as before. NEVER a friend-relay — images go only to the recipient's own box, so
// the "can't overload a friend" rule holds.
func (s *Server) tryMailboxImageDropoff(id *identity.Identity, to, msgID, mime string, data []byte) bool {
	s.sessMu.Lock()
	c, ok := s.contacts[to]
	s.sessMu.Unlock()
	if !ok || c.Status != chatstore.StatusAccepted || !canMailbox(c) {
		return false
	}
	var dh [32]byte
	copy(dh[:], c.DHPub)
	env, err := protocol.SealMailImageEnvelope(id, to, dh, msgID, mime, data, time.Now())
	if err != nil {
		log.Printf("seal mailbox image for %s: %v", to, err)
		return false
	}
	ctx, cancel := deliveryContext(mailboxDropTimeout)
	defer cancel()
	if err := protocol.MailboxDropOff(ctx, s.onion.Dialer(), env, c.MailboxURL); err != nil {
		log.Printf("mailbox image drop-off to %s: %v", c.MailboxURL, err)
		return false
	}
	return true
}

// deliverInboundImageLocked stores an image blob delivered through the mailbox and
// files an inbound image row, deduped by id (and refusing a tombstoned id, so a
// deleted photo can't reappear via a late pickup). Returns true if newly stored.
// Mirrors handleP2PAttachment's storage for the offline path. Caller holds sessMu.
func (s *Server) deliverInboundImageLocked(sender, msgID, mime string, data []byte, at time.Time) bool {
	if s.attach == nil {
		return false
	}
	for i := range s.messages {
		if s.messages[i].ID == msgID {
			return false // already have it (direct delivery or a prior pickup)
		}
	}
	for _, d := range s.deleted {
		if d == msgID {
			return false
		}
	}
	if err := s.attach.Put(msgID, data); err != nil {
		log.Printf("mailbox image store %s: %v", shortID(msgID), err)
		return false
	}
	s.messages = append(s.messages, chatMessage{
		Direction: "in", Peer: sender, At: at, ID: msgID,
		Kind: chatstore.KindImage, AttachID: msgID, Mime: mime, Size: len(data),
	})
	if s.onInbound != nil {
		name := sender
		avatarHash := ""
		if c, ok := s.contacts[sender]; ok {
			if c.Name != "" {
				name = c.Name
			}
			avatarHash = c.AvatarHash
		}
		go s.onInbound(name, "📷 Photo", at.UnixMilli(), avatarHash)
	}
	return true
}

// handleP2PAttachment receives an image from a contact: verify + decrypt (the
// contacts-only gate and cap live in ReceiveAttachment), store the blob, and
// file an inbound image message. De-duped by id so a resend doesn't duplicate.
func (s *Server) handleP2PAttachment(w http.ResponseWriter, r *http.Request) {
	peer := s.currentPeer()
	if peer == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	var env protocol.AttachmentEnvelope
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, attachBodyCap)).Decode(&env); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	msgID, mime, data, err := peer.ReceiveAttachment(env)
	if err != nil {
		http.Error(w, "rejected", http.StatusBadRequest) // generic; don't leak which check failed
		return
	}
	// Hold sessMu across the whole check-then-Put below: that is what makes the
	// dedup atomic against a concurrent resend of the same id. Do NOT release it
	// around Put "because the write is slow" — that reintroduces a duplicate-write
	// race.
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if s.attach == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	for i := range s.messages {
		if s.messages[i].ID == msgID {
			w.WriteHeader(http.StatusOK) // already have it
			return
		}
	}
	for _, d := range s.deleted {
		if d == msgID {
			w.WriteHeader(http.StatusOK) // deleted; don't resurrect
			return
		}
	}
	if err := s.attach.Put(msgID, data); err != nil {
		http.Error(w, "storage full", http.StatusInsufficientStorage)
		return
	}
	s.messages = append(s.messages, chatMessage{
		Direction: "in", Peer: env.Sender, At: time.Now(), ID: msgID,
		Kind: chatstore.KindImage, AttachID: msgID, Mime: mime, Size: len(data),
	})
	s.persistLocked()
	if s.onInbound != nil {
		name := env.Sender
		avatarHash := ""
		if cc, ok := s.contacts[env.Sender]; ok {
			if cc.Name != "" {
				name = cc.Name
			}
			avatarHash = cc.AvatarHash
		}
		go s.onInbound(name, "📷 Photo", time.Now().UnixMilli(), avatarHash)
	}
	w.WriteHeader(http.StatusOK)
}

// handleGetAttachment streams a stored image, decrypted, to the local UI. Authed
// (session token) and same-origin only; the id is validated by the store. The
// MIME was allowlisted to a real image type on receipt, and nosniff stops the
// browser second-guessing it — together they keep a stored blob from ever being
// interpreted as anything but the image it claims to be.
func (s *Server) handleGetAttachment(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	id := r.URL.Query().Get("id")
	s.sessMu.Lock()
	store := s.attach
	var mime string
	// An id names an image row's blob: for a 1:1 image ID==AttachID; for a group
	// image AttachID is the full image and ThumbID the blurry preview, each with
	// its own MIME. Looking the id up in a held row (not serving any blob by id)
	// is what stops an arbitrary blob being pulled.
	for i := range s.messages {
		m := s.messages[i]
		if m.Kind != chatstore.KindImage {
			continue
		}
		if m.ID == id || m.AttachID == id {
			mime = m.Mime
			break
		}
		if m.ThumbID == id {
			mime = m.ThumbMime
			break
		}
	}
	s.sessMu.Unlock()
	if store == nil || mime == "" || !protocol.AllowedImageMIME(mime) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	data, err := store.Get(id)
	if err != nil {
		// Missing blob: not on this device YET. A secondary backfills it from the
		// primary in the background (handleAttachmentSync); until then the UI
		// renders a placeholder for the 404 and retries on its next poll.
		http.Error(w, "not available on this device", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}
