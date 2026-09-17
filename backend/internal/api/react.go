package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// Emoji reactions (build 2, 1:1 only).
//
// Like "delete for everyone" (delete.go) a reaction is a signed per-message
// courtesy: a peer asks us to add or remove one emoji on a message in our shared
// conversation, and our client chooses to honour it. Group reactions are NOT
// handled here — they need the group gossip path and are deliberately deferred,
// so both the control endpoint and the peer hook reject anything with a GroupID.

// maxReactionsPerMessage bounds how many raw reactions one message may carry, so
// a peer cannot grow our store without limit by piling on distinct glyphs.
const maxReactionsPerMessage = 100

// hookOnReaction applies a verified reaction from a peer.
//
// The signature (checked in ReceiveReactionRequest) proves WHO is reacting; it
// says nothing about what they may touch. That check is here: a peer may only
// react to a message in the 1:1 conversation between the two of us — either
// direction, unlike delete, because reacting to something we said is normal.
// The reactor is recorded as `from`, so a later sync unions cleanly by (emoji, by).
func (s *Server) hookOnReaction(from, messageID, emoji string, remove bool) error {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()

	for i := range s.messages {
		m := &s.messages[i]
		if m.ID != messageID {
			continue
		}
		// 1:1 only, and only within our conversation with `from`. For a 1:1 message
		// Peer is always the other party (both directions), so Peer == from is
		// exactly "a message we exchanged with this reactor".
		if m.GroupID != "" || m.Peer != from {
			// Not something they may react to. Report success either way: whether we
			// hold a given message is not something a peer gets to probe by watching
			// which requests fail (same reasoning as delete).
			return nil
		}
		if remove {
			m.Reactions = chatstore.RemoveReaction(m.Reactions, emoji, from)
		} else {
			// Cap peer-driven growth: a reaction is a single glyph, but nothing stops a
			// peer from adding unbounded DISTINCT ones, all persisted and rendered. Bound
			// the per-message set, consistent with maxPendingIn / the reply-text clamps.
			if len(m.Reactions) >= maxReactionsPerMessage && !chatstore.HasReaction(m.Reactions, emoji, from) {
				return nil
			}
			m.Reactions = chatstore.AddReaction(m.Reactions, emoji, from)
		}
		s.persistLocked()
		return nil
	}
	// Nothing to react to (already deleted, never arrived); succeed silently.
	return nil
}

// handleP2PReactMessage is the peer-facing endpoint.
func (s *Server) handleP2PReactMessage(w http.ResponseWriter, r *http.Request) {
	peer := s.currentPeer()
	if peer == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	var req protocol.ReactionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := peer.ReceiveReactionRequest(req); err != nil {
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleReactMessage is the sender-side control API: toggle our own reaction on
// one 1:1 message, locally and on the peer's device. It is a toggle — if we
// already placed this emoji we remove it, otherwise we add it — so the UI can
// bind a single tap to it.
func (s *Server) handleReactMessage(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		ID    string `json:"id"`
		Emoji string `json:"emoji"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Emoji == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no emoji"})
		return
	}

	s.sessMu.Lock()
	var found *chatMessage
	for i := range s.messages {
		if s.messages[i].ID == req.ID {
			found = &s.messages[i]
			break
		}
	}
	if found == nil {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no such message"})
		return
	}
	if found.GroupID != "" {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "reactions are not available in group chats yet"})
		return
	}
	peerAccount := found.Peer
	// Toggle against our own reaction. Apply locally right away so the chip lights
	// up without waiting on Tor; the peer request rides a background goroutine.
	remove := chatstore.HasReaction(found.Reactions, req.Emoji, s.myAccount)
	if remove {
		found.Reactions = chatstore.RemoveReaction(found.Reactions, req.Emoji, s.myAccount)
	} else {
		found.Reactions = chatstore.AddReaction(found.Reactions, req.Emoji, s.myAccount)
	}
	s.persistLocked()
	s.sessMu.Unlock()

	// Tell the peer off the request path. A reaction is a courtesy; if the send
	// fails the local state still stands and a later manual re-tap re-sends it.
	if s.onion != nil {
		go func() {
			ctx, cancel := deliveryContext(2 * time.Minute)
			defer cancel()
			if err := protocol.SendReaction(ctx, s.onion.Dialer(), id, req.ID, peerAccount, req.Emoji, remove); err != nil {
				// Best-effort: nothing to unwind, the local reaction stays.
				return
			}
		}()
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "removed": remove})
}
