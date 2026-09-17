package api

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// Asynchronous sending.
//
// Delivery over Tor takes seconds when everything is warm and tens of seconds
// when it is not — a live run measured 3.4s to an online peer and 15s via a
// mailbox, with a 25s ceiling on the direct probe. Blocking the UI for that was
// wrong in both directions: the user stared at a spinner on the happy path, and
// a transient failure lost the message outright because nothing tried again.
//
// A send is now accepted, persisted and acknowledged immediately; a background
// loop delivers it. The queue survives restarts because it lives in the
// chatstore, so closing the app mid-send no longer drops the message.
const (
	outboxStartDelay = 5 * time.Second
	outboxInterval   = 20 * time.Second
	// outboxWorkers bounds concurrent delivery so one unreachable recipient
	// cannot hold up everyone else's messages behind it.
	outboxWorkers = 3
	// outboxMaxAttempts and outboxTTL bound automatic retrying. After either,
	// the message is marked failed and left alone until the user asks again —
	// retrying forever would be dishonest about a recipient who is simply gone.
	outboxMaxAttempts = 8
	outboxTTL         = 24 * time.Hour
)

// enqueueSendLocked records an outbound message and the work to deliver it.
// Caller holds sessMu.
func (s *Server) enqueueSendLocked(to, msgID, text string, reply ...protocol.Reply) {
	if s.outbox == nil {
		s.outbox = map[string]chatstore.OutboxItem{}
	}
	it := chatstore.OutboxItem{ID: msgID, To: to, Text: text, QueuedAt: time.Now()}
	if len(reply) > 0 {
		it.ReplyID = reply[0].ID
		it.ReplyPreview = reply[0].Preview
		it.ReplyAuthor = reply[0].Author
	}
	s.outbox[msgID] = it
	m := newChatMessage("out", to, msgID, text, time.Now(), reply...)
	m.Delivery = chatstore.DeliveryPending
	s.messages = append(s.messages, m)
	s.persistLocked()
}

// replyOf reconstructs the protocol.Reply carried on an outbox item.
func replyOf(it chatstore.OutboxItem) protocol.Reply {
	return protocol.Reply{ID: it.ReplyID, Preview: it.ReplyPreview, Author: it.ReplyAuthor}
}

// setDeliveryLocked updates a message's delivery state. Caller holds sessMu.
func (s *Server) setDeliveryLocked(msgID, state string) {
	for i := range s.messages {
		if s.messages[i].ID == msgID {
			s.messages[i].Delivery = state
			return
		}
	}
}

// markDelivered clears the queue entry and the pending marker.
func (s *Server) markDelivered(msgID string) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	delete(s.outbox, msgID)
	s.setDeliveryLocked(msgID, "")
	s.persistLocked()
}

// recordAttempt stores the outcome of one failed delivery attempt, marking the
// message failed once automatic retrying has run out.
func (s *Server) recordAttempt(item chatstore.OutboxItem, cause string) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	cur, ok := s.outbox[item.ID]
	if !ok {
		return // delivered or deleted while we were trying
	}
	cur.Attempts++
	cur.LastTry = time.Now()
	cur.LastError = cause
	if cur.Attempts >= outboxMaxAttempts || time.Since(cur.QueuedAt) > outboxTTL {
		cur.Failed = true
		s.setDeliveryLocked(cur.ID, chatstore.DeliveryFailed)
	}
	s.outbox[cur.ID] = cur
	s.persistLocked()
}

// outboxLoop drains the queue in the background for the life of the session.
func (s *Server) outboxLoop(ctx context.Context, id *identity.Identity) {
	t := time.NewTimer(outboxStartDelay)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.outboxTick(ctx, id)
			t.Reset(outboxInterval)
		}
	}
}

func (s *Server) outboxTick(ctx context.Context, id *identity.Identity) {
	if s.onion == nil {
		return
	}
	s.sessMu.Lock()
	var due []chatstore.OutboxItem
	for _, it := range s.outbox {
		if !it.Failed {
			due = append(due, it)
		}
	}
	s.sessMu.Unlock()
	if len(due) == 0 {
		return
	}

	sem := make(chan struct{}, outboxWorkers)
	var wg sync.WaitGroup
	for _, it := range due {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(it chatstore.OutboxItem) {
			defer wg.Done()
			defer func() { <-sem }()
			s.deliverOutboxItem(ctx, id, it)
		}(it)
	}
	wg.Wait()
}

// deliverOutboxItem makes one delivery attempt: direct first, then the
// recipient's mailbox if we hold one. Friend-relay is deliberately NOT tried
// here — relaying through a friend is a per-message decision the sender makes
// explicitly, not something a background loop should start doing on its own.
func (s *Server) deliverOutboxItem(ctx context.Context, id *identity.Identity, it chatstore.OutboxItem) {
	s.sessMu.Lock()
	c, known := s.contacts[it.To]
	s.sessMu.Unlock()
	if !known || c.Status != chatstore.StatusAccepted {
		s.recordAttempt(it, "they are no longer an accepted contact")
		return
	}

	budget := sendDirectTimeout
	if canMailbox(c) {
		budget = sendDirectProbeTimeout
	}
	reply := replyOf(it)
	dctx, dcancel := context.WithTimeout(ctx, budget)
	err := protocol.SendMessage(dctx, s.onion.Dialer(), id, it.To, it.ID, it.Text, reply)
	dcancel()
	if err == nil {
		s.markDelivered(it.ID)
		return
	}

	mctx, mcancel := context.WithTimeout(ctx, mailboxDropTimeout)
	ok := s.tryMailboxDropoff(mctx, id, c, it.ID, it.Text, reply)
	mcancel()
	if ok {
		s.markDelivered(it.ID)
		return
	}
	s.recordAttempt(it, friendlySendError(err))
	log.Printf("outbox: %s to %s still undelivered: %v", it.ID, it.To, err)
}

// deliverNow makes one immediate attempt off the request path, so an ordinary
// send to an online contact completes in the seconds it actually takes rather
// than waiting for the next tick.
func (s *Server) deliverNow(id *identity.Identity, it chatstore.OutboxItem) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), sendDirectTimeout+mailboxDropTimeout)
		defer cancel()
		s.deliverOutboxItem(ctx, id, it)
	}()
}

// friendlySendError turns a transport error into something worth showing a
// sender, without pretending to know more than we do.
func friendlySendError(err error) string {
	if err == nil {
		return "could not be delivered"
	}
	return "couldn't reach them"
}

// outboxSnapshotLocked copies the queue for persistence. Caller holds sessMu.
func (s *Server) outboxSnapshotLocked() []chatstore.OutboxItem {
	out := make([]chatstore.OutboxItem, 0, len(s.outbox))
	for _, it := range s.outbox {
		out = append(out, it)
	}
	return out
}
