package api

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// Group emoji reactions (build 4). Unlike a 1:1 reaction (react.go), which is a
// live nonce-bound request to the single peer, a group reaction is a
// self-contained signed EVENT that fans out to every member and gossips like a
// group message — a courier isn't the recipient, so the 1:1 nonce model can't
// apply. Convergence is per (target, emoji, by): the reactor is the sole writer of
// their own key, so last-writer-wins by the event's timestamp totally orders their
// add/remove events and a re-gossiped stale add can never resurrect a newer
// un-react (see chatstore.ApplyGroupReaction).

// applyGroupReactionLocked upserts one verified group-reaction event onto its
// target message using LWW. It does NOT persist — the caller batches that, exactly
// like deliverGroupInboundLocked. Returns whether anything changed. Caller holds
// sessMu.
func (s *Server) applyGroupReactionLocked(gr protocol.GroupReaction) bool {
	for i := range s.messages {
		m := &s.messages[i]
		if m.ID != gr.Target || m.GroupID != gr.GroupID {
			continue
		}
		// Cap peer-driven growth: only a brand-new live glyph counts against the
		// per-message ceiling (a remove or an update to an existing key never grows
		// the live set). LiveReactions/HasReaction ignore tombstones, so a group that
		// churns reactions can't wedge the message at the cap with dead entries.
		if !gr.Remove && !chatstore.HasReaction(m.Reactions, gr.Emoji, gr.By) &&
			len(chatstore.LiveReactions(m.Reactions)) >= maxReactionsPerMessage {
			return false
		}
		ev := chatstore.MessageReaction{Emoji: gr.Emoji, By: gr.By, At: gr.AtNanos, Removed: gr.Remove, Sig: gr.Sig}
		next, changed := chatstore.ApplyGroupReaction(m.Reactions, ev)
		m.Reactions = next
		return changed
	}
	// No such message (never arrived, or already deleted): nothing to react to.
	return false
}

// groupReactionsFromRowLocked rebuilds the signed GroupReaction events stored on a
// message row, so gossip can re-serve them to a lagging member. Only group
// reactions carry a signature (1:1 reactions don't), so entries without one are
// skipped. Caller holds sessMu.
func (s *Server) groupReactionsFromRowLocked(m chatMessage) []protocol.GroupReaction {
	if m.GroupID == "" || len(m.Reactions) == 0 {
		return nil
	}
	var out []protocol.GroupReaction
	for _, r := range m.Reactions {
		if len(r.Sig) == 0 {
			continue
		}
		out = append(out, protocol.GroupReaction{
			GroupID: m.GroupID, Target: m.ID, Emoji: r.Emoji, By: r.By,
			Remove: r.Removed, AtNanos: r.At, Sig: r.Sig,
		})
	}
	return out
}

// handleP2PGroupReact receives a sealed group reaction from the reactor or any
// forwarding member, decrypts+verifies it, gates it to the roster, and applies it.
// Self-authenticating (inner reactor signature), so like a group message there is
// no live challenge — the same reason any member can relay it.
//
// A reaction that arrives before its target message has no row to attach to and is
// dropped here (applyGroupReactionLocked returns false); it is not retried. That is
// safe because the wholesale reaction re-serve in handleP2PGroupSync repairs it
// within a sync interval once the message lands.
func (s *Server) handleP2PGroupReact(w http.ResponseWriter, r *http.Request) {
	peer := s.currentPeer()
	if peer == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Envelope protocol.GroupReactionEnvelope `json:"envelope"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, groupMaxBodyByte)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	gr, err := peer.OpenGroupReaction(req.Envelope)
	if err != nil {
		groupReject(w)
		return
	}
	s.sessMu.Lock()
	g, ok := s.groups[gr.GroupID]
	// Accept a LIVE reaction only if we still belong AND the reactor is a current
	// member — the same gate as a live group message. (Gossip catch-up applies past
	// reactions without this gate, mirroring message backfill.)
	accept := ok && groupHasMember(g, s.myAccount) && groupHasMember(g, gr.By)
	if accept && s.applyGroupReactionLocked(gr) {
		s.persistLocked()
	}
	s.sessMu.Unlock()
	if !accept {
		groupReject(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "delivered"})
}

// handleGroupReact is the sender-side control API: toggle our own reaction on one
// GROUP message, locally and to every other member best-effort. A toggle, like the
// 1:1 path, so the UI binds a single tap to it. Offline members are caught up by
// gossip, so this does not retry.
func (s *Server) handleGroupReact(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		Group string `json:"group"`
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
	if s.onion == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Tor is disabled"})
		return
	}

	s.sessMu.Lock()
	g, gok := s.groups[req.Group]
	if !gok || !groupHasMember(g, s.myAccount) {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "you are not a member of this group"})
		return
	}
	// The target must be a message we hold IN THIS group — scope it exactly like the
	// group reply path, so a stray 1:1 or foreign-group id can't be signed and fanned
	// out to this group's members.
	var found *chatMessage
	for i := range s.messages {
		if s.messages[i].ID == req.ID && s.messages[i].GroupID == req.Group {
			found = &s.messages[i]
			break
		}
	}
	if found == nil {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no such message"})
		return
	}
	// Toggle against our own LIVE reaction.
	remove := chatstore.HasReaction(found.Reactions, req.Emoji, s.myAccount)
	gr, err := protocol.NewGroupReaction(id, req.Group, req.ID, req.Emoji, remove, time.Now())
	if err != nil {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// Apply locally right away so the chip lights up without waiting on Tor. Our own
	// event carries the newest timestamp, so it wins the LWW.
	if s.applyGroupReactionLocked(gr) {
		s.persistLocked()
	}
	s.sessMu.Unlock()

	go s.groupReactionFanOut(id, g, gr)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "removed": remove})
}

// groupReactionFanOut seals the reaction for each other member (using their roster
// key) and delivers it best-effort — mirrors groupFanOut. Unreachable members are
// reconciled by gossip when they return.
func (s *Server) groupReactionFanOut(id *identity.Identity, g chatstore.Group, gr protocol.GroupReaction) {
	if s.onion == nil {
		return
	}
	s.sessMu.Lock()
	self := s.myAccount
	s.sessMu.Unlock()
	for _, m := range g.Members {
		if m.Account == self || len(m.DHPub) != 32 {
			continue
		}
		var dh [32]byte
		copy(dh[:], m.DHPub)
		env, err := protocol.SealGroupReaction(id, gr, m.Account, dh)
		if err != nil {
			continue
		}
		ctx, cancel := deliveryContext(groupOpTimeout)
		err = protocol.SendGroupReactionEnvelope(ctx, s.onion.Dialer(), env, m.Account)
		cancel()
		if err != nil {
			log.Printf("group reaction send to a member failed (will reconcile via gossip): %v", err)
		}
	}
}
