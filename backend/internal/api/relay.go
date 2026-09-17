package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/mailbox"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

const (
	relayStartDelay  = 25 * time.Second
	relayInterval    = 45 * time.Second // how often we retry forwarding held blobs
	relayOpTimeout   = 60 * time.Second
	relayWorkers     = 4 // cap concurrent outbound dials while forwarding
	relayMaxBodyByte = 64 << 10

	// Per-sender relay limits to prevent a granted sender from flooding the
	// relay store. These are in-memory and reset on restart, which is
	// acceptable because the TTL-bound blobs also reset.
	relayMaxPerSender     = 10   // max blobs held per sender
	relayMaxBytesPerSender = 5 << 20 // 5 MiB per sender
)

// relaySenderQuota tracks per-sender blob count and bytes for abuse prevention.
type relaySenderQuota struct {
	mu      sync.Mutex
	senders map[string]struct{ count int; bytes int64 }
}

func newRelaySenderQuota() *relaySenderQuota {
	return &relaySenderQuota{senders: make(map[string]struct{ count int; bytes int64 })}
}

func (q *relaySenderQuota) check(sender string, blobLen int) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.evictLocked()
	s := q.senders[sender]
	if s.count >= relayMaxPerSender || s.bytes+int64(blobLen) > relayMaxBytesPerSender {
		return false
	}
	s.count++
	s.bytes += int64(blobLen)
	q.senders[sender] = s
	return true
}

// evictLocked removes senders with expired quotas (simple TTL-based eviction).
func (q *relaySenderQuota) evictLocked() {
	// No-op for now; quotas reset on restart. Could add TTL-based eviction later.
}

// --- onion: relay drop-off (we are the relay-holder, "Bob") ---

// handleRelayDropOff accepts a sealed envelope from a friend who has us as an
// approved relay-holder, to hold-and-forward to a third party. We can't read it.
func (s *Server) handleRelayDropOff(w http.ResponseWriter, r *http.Request) {
	if s.currentPeer() == nil || s.relay == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Envelope protocol.MailEnvelope `json:"envelope"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, relayMaxBodyByte)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// The sender must have signed it, and must be someone we've approved to relay.
	// All rejection paths return the same response to prevent oracle attacks on
	// contact/relay relationships.
	if !req.Envelope.VerifySignature() {
		http.Error(w, "rejected", http.StatusForbidden)
		return
	}
	s.sessMu.Lock()
	c, ok := s.contacts[req.Envelope.Sender]
	granted := ok && c.RelayGrant && c.Status == chatstore.StatusAccepted
	s.sessMu.Unlock()
	if !granted {
		http.Error(w, "rejected", http.StatusForbidden)
		return
	}
	blob, err := json.Marshal(req.Envelope)
	if err != nil {
		http.Error(w, "rejected", http.StatusForbidden)
		return
	}
	// Enforce per-sender quota to prevent relay store exhaustion.
	if s.relayQuota != nil && !s.relayQuota.check(req.Envelope.Sender, len(blob)) {
		http.Error(w, "rejected", http.StatusForbidden)
		return
	}
	if err := s.relay.DropOff(req.Envelope.Recipient, req.Envelope.ID(), blob); err != nil {
		http.Error(w, "rejected", http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "held"})
}

// --- onion: relay deliver (we are the recipient, "Carol") ---

// handleRelayDeliver receives a relayed message pushed by an untrusted relay
// courier. Security: the courier is NOT authenticated; protection is the inner
// signature (by the real sender) plus our contacts-only gate. Every rejection
// returns an IDENTICAL status so this endpoint can't be used as an oracle for
// whether a given account is one of our contacts, and we return 200 ONLY when the
// message is actually stored (so the courier keeps retrying otherwise).
func (s *Server) handleRelayDeliver(w http.ResponseWriter, r *http.Request) {
	peer := s.currentPeer()
	if peer == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable) // locked: retry later
		return
	}
	var req struct {
		Envelope protocol.MailEnvelope `json:"envelope"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, relayMaxBodyByte)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Cheap-reject order: verify signature (no decrypt) → contact gate → decrypt.
	if !req.Envelope.VerifySignature() {
		relayReject(w)
		return
	}
	s.sessMu.Lock()
	allowed := s.allowMessageLocked(req.Envelope.Sender)
	s.sessMu.Unlock()
	if !allowed {
		relayReject(w)
		return
	}
	c, err := peer.OpenMailContent(req.Envelope)
	if err != nil {
		relayReject(w)
		return
	}
	s.sessMu.Lock()
	if s.deliverInboundLocked(c.Sender, c.MsgID, c.Text, c.SentAt, c.Reply) {
		s.persistLocked()
	}
	s.sessMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "delivered"})
}

// relayReject is the single response for every relay-deliver failure, so the
// endpoint reveals nothing about why (bad signature vs. not-a-contact).
func relayReject(w http.ResponseWriter) {
	http.Error(w, "not accepted", http.StatusForbidden)
}

// --- relay forward loop (we are the relay-holder pushing to recipients) ---

func (s *Server) relayForwardLoop(ctx context.Context) {
	t := time.NewTimer(relayStartDelay)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.relayForwardTick(ctx)
			t.Reset(relayInterval)
		}
	}
}

func (s *Server) relayForwardTick(ctx context.Context) {
	if s.onion == nil || s.relay == nil {
		return
	}
	_ = s.relay.Sweep() // expire blobs past TTL and clean delivered tenancies
	recipients, err := s.relay.Recipients()
	if err != nil || len(recipients) == 0 {
		return
	}
	sem := make(chan struct{}, relayWorkers)
	var wg sync.WaitGroup
	for _, rcpt := range recipients {
		items, err := s.relay.Pickup(rcpt)
		if err != nil || len(items) == 0 {
			continue
		}
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(rcpt string, items []mailbox.Item) {
			defer wg.Done()
			defer func() { <-sem }()
			s.forwardTo(ctx, rcpt, items)
		}(rcpt, items)
	}
	wg.Wait()
}

// forwardTo tries to deliver each held blob to one recipient, deleting only the
// ones that were actually accepted (HTTP 200). The rest stay for the next tick,
// bounded by the store's TTL.
func (s *Server) forwardTo(ctx context.Context, rcpt string, items []mailbox.Item) {
	var delivered []string
	for _, it := range items {
		var env protocol.MailEnvelope
		if err := json.Unmarshal(it.Blob, &env); err != nil {
			delivered = append(delivered, it.ID) // corrupt blob: drop it
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, relayOpTimeout)
		err := protocol.RelayDeliver(cctx, s.onion.Dialer(), env, rcpt)
		cancel()
		if err == nil {
			delivered = append(delivered, it.ID)
		}
	}
	if len(delivered) > 0 {
		if err := s.relay.Delete(rcpt, delivered); err != nil {
			log.Printf("relay delete: %v", err)
		}
	}
}

// --- relay-request handshake (mirrors friend requests) ---

// hookOnRelayRequest records an inbound request to relay for a contact.
func (s *Server) hookOnRelayRequest(from, reqID string) error {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	c, ok := s.contacts[from]
	if !ok || c.Status != chatstore.StatusAccepted {
		return fmt.Errorf("relay request from a non-contact")
	}
	c.RelayPending = true
	c.RelayReqID = reqID
	s.putContactLocked(c)
	s.persistLocked()
	return nil
}

// hookOnRelayAccept applies a relay accept iff it matches a request we sent.
func (s *Server) hookOnRelayAccept(from, reqID string) error {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	c, ok := s.contacts[from]
	if !ok || c.RelayReqID == "" || c.RelayReqID != reqID {
		return fmt.Errorf("no matching relay request")
	}
	c.RelayHolder = true
	c.RelayReqID = ""
	s.putContactLocked(c)
	s.persistLocked()
	return nil
}

func (s *Server) handleP2PRelayRequest(w http.ResponseWriter, r *http.Request) {
	peer := s.currentPeer()
	if peer == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	var req protocol.RelayRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := peer.ReceiveRelayRequest(req); err != nil {
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleP2PRelayAccept(w http.ResponseWriter, r *http.Request) {
	peer := s.currentPeer()
	if peer == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	var acc protocol.RelayAccept
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&acc); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := peer.ReceiveRelayAccept(acc); err != nil {
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// --- control API: relay-request management ---

// handleRequestRelay: we ask an accepted contact to relay for us.
func (s *Server) handleRequestRelay(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	acct := s.decodeAccount(w, r)
	if acct == "" {
		return
	}
	if s.onion == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Tor is disabled"})
		return
	}
	s.sessMu.Lock()
	c, ok := s.contacts[acct]
	if !ok || c.Status != chatstore.StatusAccepted {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "must be an accepted contact"})
		return
	}
	reqID := randomID()
	c.RelayReqID = reqID
	s.putContactLocked(c)
	s.persistLocked()
	s.sessMu.Unlock()

	ctx, cancel := deliveryContext(relayOpTimeout)
	defer cancel()
	if err := protocol.SendRelayRequest(ctx, s.onion.Dialer(), id, reqID, acct); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not reach them: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "requested"})
}

// handleApproveRelay: we approve a contact's request to relay through us.
func (s *Server) handleApproveRelay(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	acct := s.decodeAccount(w, r)
	if acct == "" {
		return
	}
	s.sessMu.Lock()
	c, ok := s.contacts[acct]
	if !ok || !c.RelayPending {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no such relay request"})
		return
	}
	reqID := c.RelayReqID
	c.RelayGrant = true
	c.RelayPending = false
	c.RelayReqID = ""
	s.putContactLocked(c)
	s.persistLocked()
	s.sessMu.Unlock()

	ctx, cancel := deliveryContext(relayOpTimeout)
	defer cancel()
	if err := protocol.SendRelayAccept(ctx, s.onion.Dialer(), id, reqID, acct); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "approved locally, but could not reach them: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
}

// handleDeclineRelay: we decline a contact's relay request.
func (s *Server) handleDeclineRelay(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	acct := s.decodeAccount(w, r)
	if acct == "" {
		return
	}
	s.sessMu.Lock()
	if c, ok := s.contacts[acct]; ok {
		c.RelayPending = false
		c.RelayReqID = ""
		s.putContactLocked(c)
		s.persistLocked()
	}
	s.sessMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "declined"})
}

// handleRelayMessage: send a message via a relay-holder (per-message consent on
// the UI side). Seals for the recipient and drops off at an approved relay.
func (s *Server) handleRelayMessage(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	// Takes the id of an already-queued message: relaying is an alternative
	// route for a send that is already in the conversation, not a second send.
	var req struct {
		ID string `json:"id"`
		// Holder optionally names which approved relay-holder should carry this
		// message (the user picks one in the offline-send popup). Empty means
		// "any", and we fall back to the first available.
		Holder string `json:"holder"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.sessMu.Lock()
	item, queued := s.outbox[req.ID]
	c, ok := s.contacts[item.To]
	holder, haveHolder := s.relayHolderLocked(req.Holder)
	s.sessMu.Unlock()
	if !queued {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "that message is not waiting to be sent"})
		return
	}
	if !ok || c.Status != chatstore.StatusAccepted {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "recipient is not an accepted contact"})
		return
	}
	if len(c.DHPub) != 32 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no encryption key for them yet — connect once while they're online"})
		return
	}
	if !haveHolder {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "you have no relay set up"})
		return
	}
	if s.onion == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Tor is disabled"})
		return
	}
	var dh [32]byte
	copy(dh[:], c.DHPub)
	env, err := protocol.SealMailEnvelope(id, item.To, dh, item.ID, item.Text, time.Now(), replyOf(item))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ctx, cancel := deliveryContext(relayOpTimeout)
	defer cancel()
	if err := protocol.RelayDropOff(ctx, s.onion.Dialer(), env, holder.Account); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not reach your relay: " + err.Error()})
		return
	}
	// Handed to the relay: the message is on its way, so it leaves the queue and
	// stops showing as failed. It is already in the conversation.
	s.markDelivered(item.ID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent", "via": "relay"})
}

// firstRelayHolderLocked returns an approved relay-holder to use, if any. Caller
// holds sessMu.
func (s *Server) firstRelayHolderLocked() (chatstore.Contact, bool) {
	for _, c := range s.contacts {
		if c.RelayHolder && c.Status == chatstore.StatusAccepted {
			return c, true
		}
	}
	return chatstore.Contact{}, false
}

// relayHolderLocked returns the approved relay-holder named by account, or the
// first available one if account is empty. It refuses an account that is not an
// approved relay-holder, so the caller can never be steered to drop a message at
// an arbitrary contact. Caller holds sessMu.
func (s *Server) relayHolderLocked(account string) (chatstore.Contact, bool) {
	if account == "" {
		return s.firstRelayHolderLocked()
	}
	c, ok := s.contacts[account]
	if ok && c.RelayHolder && c.Status == chatstore.StatusAccepted {
		return c, true
	}
	return chatstore.Contact{}, false
}
