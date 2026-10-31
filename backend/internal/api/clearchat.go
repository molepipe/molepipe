package api

import (
	"net/http"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

// handleClearChat removes every message in one 1:1 conversation from THIS
// account's devices, keeping the contact. It is the bulk form of the existing
// per-message "delete for me" (handleDeleteMessage with local:true) and carries
// exactly the same semantics — including the tombstone, without which the next
// /sync would resurrect the whole conversation from the user's other device.
//
// It is a separate endpoint rather than a client-side loop because clearing a
// long chat one request at a time is both slow and non-atomic: an interrupted
// loop leaves a half-cleared conversation, and the tombstones it did write would
// still be racing an inbound sync.
//
// Nothing is sent to the peer: "clear chat" is local history, not a retraction.
// Deleting for everyone stays the per-message action it already was.
func (s *Server) handleClearChat(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	acct := s.decodeAccount(w, r)
	if acct == "" {
		return
	}

	s.sessMu.Lock()
	kept := s.messages[:0]
	removed := 0
	for _, m := range s.messages {
		if m.Peer != acct || m.GroupID != "" {
			kept = append(kept, m)
			continue
		}
		s.deleteAttachmentsLocked(m)
		s.deleteTombstone(m.ID)
		removed++
	}
	s.messages = kept
	s.persistLocked()
	s.sessMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"status": "cleared", "removed": removed})
}
