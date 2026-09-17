package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

// The desktop shell's hook into the server.
//
// cmd/server and cmd/desktop run the same api.Server; only cmd/desktop has a
// window, a tray and a login entry to offer. Rather than fork the server for
// one entrypoint, the shell registers itself here and the two extra settings
// appear. With no shell registered — every headless and development run —
// /api/desktop answers "available: false" and the UI hides the section, so
// cmd/server behaves exactly as it did before this existed.
//
// Nothing in this file relaxes a guard: the routes are auth'd and (for POST)
// origin-guarded like every other mutating route in the app.

// Desktop is implemented by the desktop shell. It covers only what the web UI
// cannot do for itself.
type Desktop interface {
	// AutostartAvailable reports whether start-at-login exists on this OS.
	AutostartAvailable() bool
	// AutostartEnabled reports whether it is currently on.
	AutostartEnabled() (bool, error)
	// SetAutostart turns it on or off.
	SetAutostart(on bool) error
	// OpenExternal opens an http(s) URL in the user's default browser. The
	// scheme has already been checked by the caller.
	OpenExternal(url string) error
}

// SetDesktop registers the desktop shell. Call it before Start.
func (s *Server) SetDesktop(d Desktop) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	s.desktop = d
}

// PostNotice queues a one-time message for the UI to show when it is next on
// screen. The shell uses it for the "still running in the background" notice,
// which is raised at the moment the window is hidden — when, by definition,
// nothing in the window can be seen. Holding it until the user looks again is
// the point.
func (s *Server) PostNotice(text string) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	s.notice = text
}

// LockNow locks the vault and tears down the onion service — the same thing
// POST /api/lock does, callable from inside the process.
//
// The tray's Lock item cannot go through the HTTP route: that route requires
// the bearer session token, which lives in the page's memory and never reaches
// Go. Rather than plumb the token out to the tray (a second copy of the
// credential, for a menu item) or exempt the route from auth (weakening a
// guard for convenience — the thing Phase 7 must not do), both callers share
// this method.
func (s *Server) LockNow() {
	s.vault.lock()
	s.lockOnion() // immediate teardown, or a grace-deferred one (see lockOnion)
	s.clearSession()
}

// handleDesktopGet reports what the desktop shell can offer, plus any pending
// one-time notice.
func (s *Server) handleDesktopGet(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	s.sessMu.Lock()
	d, notice := s.desktop, s.notice
	s.sessMu.Unlock()

	out := map[string]any{"available": d != nil, "notice": notice}
	if d != nil {
		out["autostart_available"] = d.AutostartAvailable()
		on, err := d.AutostartEnabled()
		if err != nil {
			// Report it as off and say so, rather than hiding a broken toggle.
			log.Printf("autostart state: %v", err)
			out["error"] = "could not read the start-at-login setting"
		}
		out["autostart"] = on
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDesktopSet changes a desktop-shell setting.
func (s *Server) handleDesktopSet(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	var req struct {
		Autostart     *bool `json:"autostart"`
		DismissNotice bool  `json:"dismiss_notice"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.DismissNotice {
		s.PostNotice("")
	}
	if req.Autostart != nil {
		s.sessMu.Lock()
		d := s.desktop
		s.sessMu.Unlock()
		if d == nil || !d.AutostartAvailable() {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "start at login is not available in this build",
			})
			return
		}
		if err := d.SetAutostart(*req.Autostart); err != nil {
			log.Printf("set autostart: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "could not change the start-at-login setting",
			})
			return
		}
	}
	s.handleDesktopGet(w, r, nil)
}

// handleOpenExternal opens an http(s) link (Donate, Report a bug) in the user's
// default browser. Only the desktop shell can do this: the desktop UI is loaded
// over a loopback HTTP URL, so it has no Wails runtime of its own, and it must
// never navigate its own WebView to an outside site (that would replace the
// whole app with a web page). With no shell registered — cmd/server in a real
// browser, or any headless run — the route reports itself unavailable and the
// frontend falls back to window.open. Only http/https is honoured, so the
// endpoint can never be steered into arbitrary shell commands (tel:, file:, …).
func (s *Server) handleOpenExternal(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	u := strings.TrimSpace(req.URL)
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "only http(s) links can be opened"})
		return
	}
	s.sessMu.Lock()
	d := s.desktop
	s.sessMu.Unlock()
	if d == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "opening links is not available in this build"})
		return
	}
	if err := d.OpenExternal(u); err != nil {
		log.Printf("open external: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not open the link"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
