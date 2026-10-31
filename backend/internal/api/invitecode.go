package api

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

// Always-on invite code. The shareable friend code always carries a token, and a
// friend request must present the CURRENT token to be admitted — the bare account
// alone is not addable. "Refresh" mints a new token, revoking the previous code.
// The AutoRefresh toggle controls what happens after a code is used: on → rotate
// the token automatically (the code works once, then a fresh one appears); off →
// keep it (reusable until a manual refresh). State is device-local; the publishing
// device mints, shows and rotates the token.

// inviteCodeResponse is the shape both the GET status and every POST action
// return, so the UI can render the friend-code card from a single source of truth.
type inviteCodeResponse struct {
	Code        string `json:"code"`         // the shareable friend code to display / QR (mp1:…)
	AutoRefresh bool   `json:"auto_refresh"` // does the code auto-renew after each use?
	// QR is a base64 PNG of the friend code, for a data: URL.
	QR string `json:"qr,omitempty"`
}

func (s *Server) inviteCodeResponseLocked(id *identity.Identity) inviteCodeResponse {
	resp := inviteCodeResponse{
		Code:        s.shareCodeLocked(s.advertisedAccountLocked(id)),
		AutoRefresh: s.autoRefresh,
	}
	if png, err := qrcode.Encode(resp.Code, qrcode.Medium, 256); err == nil {
		resp.QR = base64.StdEncoding.EncodeToString(png)
	} else {
		log.Printf("invite code: qr encode: %v", err)
	}
	return resp
}

// handleInviteCodeStatus (GET) reports the current friend code and toggle state.
func (s *Server) handleInviteCodeStatus(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	s.sessMu.Lock()
	resp := s.inviteCodeResponseLocked(id)
	s.sessMu.Unlock()
	writeJSON(w, http.StatusOK, resp)
}

// handleInviteCode (POST) sets the auto-refresh toggle and mints fresh codes.
// Actions: "enable"/"disable" (auto-refresh on/off), "refresh" (mint a new code,
// revoking the previous one). Unlike the /api/security actions this is not
// password-gated: it neither destroys the account nor discloses secret material —
// it only changes the shareable code.
func (s *Server) handleInviteCode(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	switch req.Action {
	case "enable":
		s.autoRefresh = true
	case "disable":
		s.autoRefresh = false
	case "refresh":
		tok, err := newInviteToken()
		if err != nil {
			log.Printf("invite code: mint token: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.inviteToken = tok
	default:
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.persistLocked()
	writeJSON(w, http.StatusOK, s.inviteCodeResponseLocked(id))
}
