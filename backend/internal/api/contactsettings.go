package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
)

// mediaPolicy is the wire spelling of Contact.MediaAutoSave. It is a tri-state
// string rather than a bool because the zero value has to mean "inherit the
// global default", which a JSON bool cannot express: an omitted `false` and an
// explicit `false` decode identically, so a contact the user had deliberately
// set to "never" would silently follow the global back on.
const (
	mediaPolicyDefault = "default" // inherit Profile.MediaAutoSave
	mediaPolicyOn      = "on"      // always copy this contact's images to the gallery
	mediaPolicyOff     = "off"     // never copy them, whatever the global says
)

// mediaPolicyOf renders a contact's stored override in wire form.
func mediaPolicyOf(c chatstore.Contact) string {
	if c.MediaAutoSave == nil {
		return mediaPolicyDefault
	}
	if *c.MediaAutoSave {
		return mediaPolicyOn
	}
	return mediaPolicyOff
}

// maxNicknameRunes bounds the user's private label for a contact. Counted in
// runes, not bytes, so a name in a non-Latin script gets the same 64 characters a
// Latin one does. Unlike the peer-supplied names protocol.clampName truncates,
// this is the user's own typing, so an over-long value is REJECTED — silently
// trimming what someone just typed is worse than telling them it was too long.
const maxNicknameRunes = 64

// handleContactSettings updates the per-contact preferences owned by the friend
// profile pane: the private nickname, notification mute and the media auto-save
// override. All fields
// are optional — only the ones present in the body are touched — so the pane can
// send one switch without having to round-trip the other and risk clobbering a
// change made on another device between polls.
//
// It deliberately refuses to CREATE a contact: settings for an account we do not
// know would be a silent no-op at best, and at worst would grow the contact map
// from an unauthenticated-looking call.
func (s *Server) handleContactSettings(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	var req struct {
		Account       string  `json:"account"`
		Nickname      *string `json:"nickname,omitempty"`
		Muted         *bool   `json:"muted,omitempty"`
		MediaAutoSave *string `json:"media_auto_save,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if _, err := identity.AccountNumberFromString(req.Account); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid account number"})
		return
	}
	if req.MediaAutoSave != nil {
		switch *req.MediaAutoSave {
		case mediaPolicyDefault, mediaPolicyOn, mediaPolicyOff:
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid media policy"})
			return
		}
	}
	nickname := ""
	if req.Nickname != nil {
		// Trim first, so a nickname of spaces clears rather than storing blanks that
		// would render as a nameless contact.
		nickname = strings.TrimSpace(*req.Nickname)
		if len([]rune(nickname)) > maxNicknameRunes {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nickname too long"})
			return
		}
	}

	s.sessMu.Lock()
	c, ok := s.contacts[req.Account]
	if !ok {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such contact"})
		return
	}
	if req.Nickname != nil {
		// An empty value (or one that was all whitespace) clears the nickname, so the
		// contact falls back to the name they publish. That is the whole "remove
		// nickname" path — no separate endpoint.
		c.Nickname = nickname
	}
	if req.Muted != nil {
		c.Muted = *req.Muted
	}
	if req.MediaAutoSave != nil {
		switch *req.MediaAutoSave {
		case mediaPolicyDefault:
			c.MediaAutoSave = nil
		case mediaPolicyOn:
			on := true
			c.MediaAutoSave = &on
		case mediaPolicyOff:
			off := false
			c.MediaAutoSave = &off
		}
	}
	s.putContactLocked(c)
	s.persistLocked()
	s.sessMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"nickname":        c.Nickname,
		"muted":           c.Muted,
		"media_auto_save": mediaPolicyOf(c),
	})
}
