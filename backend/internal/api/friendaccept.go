package api

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// Friend-accept retry. When we accept someone's request we owe them a push
// telling them so, and until it lands they are stuck: their client shows
// "pending" and refuses to send us anything. The protocol's one repair path —
// an inbound message upgrading pending_out to accepted — only works in the
// direction they cannot use, so a single best-effort push left them stranded
// permanently whenever their onion descriptor hadn't propagated yet.
const (
	acceptRetryStartDelay = 15 * time.Second
	acceptRetryInterval   = 60 * time.Second
	// acceptRetryTTL is how long we keep trying. Generous, because the cost of
	// giving up early is a contact pair that silently never works.
	acceptRetryTTL = 7 * 24 * time.Hour
	// maxAcceptRefusals is how many consecutive peer refusals we tolerate before
	// concluding the debt is genuinely settled rather than transiently rejected.
	maxAcceptRefusals = 5
)

// queueAcceptLocked records that we owe account an accept. Caller holds sessMu.
func (s *Server) queueAcceptLocked(account, reqID string) {
	if s.pendingAccepts == nil {
		s.pendingAccepts = map[string]chatstore.PendingAccept{}
	}
	// Keep the original QueuedAt if we already owe this account, so re-accepting
	// can't extend the TTL indefinitely.
	queued := time.Now()
	if ex, ok := s.pendingAccepts[account]; ok {
		queued = ex.QueuedAt
	}
	s.pendingAccepts[account] = chatstore.PendingAccept{Account: account, ReqID: reqID, QueuedAt: queued}
}

// dequeueAcceptLocked clears the debt. Caller holds sessMu.
func (s *Server) dequeueAcceptLocked(account string) { delete(s.pendingAccepts, account) }

func (s *Server) acceptRetryLoop(ctx context.Context, id *identity.Identity) {
	t := time.NewTimer(acceptRetryStartDelay)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.acceptRetryTick(ctx, id)
			t.Reset(acceptRetryInterval)
		}
	}
}

func (s *Server) acceptRetryTick(ctx context.Context, id *identity.Identity) {
	if s.onion == nil {
		return
	}
	s.sessMu.Lock()
	name := s.displayName
	var due []chatstore.PendingAccept
	var expired []string
	for acct, p := range s.pendingAccepts {
		if time.Since(p.QueuedAt) > acceptRetryTTL {
			expired = append(expired, acct)
			continue
		}
		due = append(due, p)
	}
	for _, acct := range expired {
		delete(s.pendingAccepts, acct)
		log.Printf("friend-accept to %s gave up after %s", acct, acceptRetryTTL)
	}
	if len(expired) > 0 {
		s.persistLocked()
	}
	s.sessMu.Unlock()

	for _, p := range due {
		select {
		case <-ctx.Done():
			return
		default:
		}
		err := protocol.SendFriendAccept(ctx, s.onion.Dialer(), id, name, p.ReqID, p.Account)
		if err == nil {
			log.Printf("friend-accept to %s delivered on retry", p.Account)
			s.clearPendingAccept(p.Account)
			continue
		}
		// A peer that answers and refuses MIGHT be final — they already have us
		// accepted, so the debt is settled. But the refusal is an opaque 400
		// that also covers transient causes (their challenge nonces are in
		// memory and are wiped by any lock or restart), so one refusal proves
		// nothing. Only give up after several in a row. A transport error means
		// we never reached them at all, which resets the count.
		var se *protocol.StatusError
		refused := errors.As(err, &se) && se.Code == http.StatusBadRequest

		s.sessMu.Lock()
		cur, ok := s.pendingAccepts[p.Account]
		if ok {
			cur.LastTry = time.Now()
			if refused {
				cur.Refusals++
			} else {
				cur.Refusals = 0
			}
			s.pendingAccepts[p.Account] = cur
			if cur.Refusals >= maxAcceptRefusals {
				delete(s.pendingAccepts, p.Account)
				log.Printf("friend-accept to %s refused %d times, dropping: %v", p.Account, cur.Refusals, err)
			} else {
				log.Printf("friend-accept to %s still undelivered (refusals=%d): %v", p.Account, cur.Refusals, err)
			}
			s.persistLocked()
		}
		s.sessMu.Unlock()
	}
}

func (s *Server) clearPendingAccept(account string) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	s.dequeueAcceptLocked(account)
	s.persistLocked()
}

// awaitingAcceptLocked reports whether we still owe this contact an accept, so
// the UI can say "they haven't been told yet" instead of implying it's done.
// Caller holds sessMu.
func (s *Server) awaitingAcceptLocked(account string) bool {
	_, ok := s.pendingAccepts[account]
	return ok
}
