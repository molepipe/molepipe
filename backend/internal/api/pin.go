package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/pin"
)

// PIN unlock (security doc §1). The PIN is a convenience shortcut on THIS
// device, never a password replacement: identity.enc stays password-only, and
// the password remains required to set the shortcut up, to recover, and as the
// always-available fallback on the unlock screen.

// pinEnable creates the device-bound PIN shortcut. It requires BOTH an unlocked
// session and a fresh re-entry of the full password — the doc's "the user must
// authenticate with their full password" step. Requiring it again (rather than
// trusting the open session) is what stops someone who walks up to an
// unattended unlocked screen from minting themselves a 6-digit way back in.
func (s *Server) pinEnable(w http.ResponseWriter, id *identity.Identity, password, code string) {
	p := s.currentPin()
	if p == nil {
		http.Error(w, "pin unlock unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, err := s.store.Load([]byte(password)); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "password is incorrect"})
		return
	}
	if err := p.Enable([]byte(code), id.MnemonicString(), id.PassphraseString()); err != nil {
		if errors.Is(err, pin.ErrTooShort) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		log.Printf("enable pin: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pin_enabled": true})
}

// pinDisable removes the shortcut. The identity is untouched.
func (s *Server) pinDisable(w http.ResponseWriter) {
	p := s.currentPin()
	if p == nil {
		http.Error(w, "pin unlock unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := p.Disable(); err != nil {
		log.Printf("disable pin: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pin_enabled": false})
}

// handlePINUnlock opens the vault with the PIN. Tokenless (it runs before any
// session exists) but origin-guarded, exactly like /api/unlock.
func (s *Server) handlePINUnlock(w http.ResponseWriter, r *http.Request) {
	p := s.currentPin()
	if p == nil || !p.Exists() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "pin unlock is not set up on this device"})
		return
	}
	var req struct {
		PIN string `json:"pin"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	mnemonic, passphrase, err := p.Unlock([]byte(req.PIN))
	if err != nil {
		// Check duress on EVERY failure, not just a wrong PIN. If it were gated
		// behind the bad-PIN case, a panic code typed while the shortcut is
		// inside its backoff window — the likely state after someone has been
		// forcing guesses — would silently do nothing.
		if decoy, ok := s.checkDuress(req.PIN); ok {
			s.triggerDuress(w, decoy, req.PIN)
			return
		}
		var throttled *pin.ThrottleError
		switch {
		case errors.As(err, &throttled):
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error":       throttled.Error(),
				"retry_after": int(throttled.RetryAfter.Round(1e9).Seconds()),
			})
		case errors.Is(err, pin.ErrWiped):
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":       err.Error(),
				"pin_enabled": false,
			})
		case errors.Is(err, pin.ErrBadPIN):
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error":         "Incorrect PIN.",
				"attempts_left": p.Status().AttemptsLeft,
			})
		case errors.Is(err, pin.ErrNotEnabled):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "pin unlock is not set up on this device"})
		default:
			log.Printf("pin unlock: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}

	id, err := identity.FromMnemonic(mnemonic, passphrase)
	if err != nil {
		// The shortcut decrypted but yielded material that isn't a valid
		// identity — the blob is stale or damaged. Drop it and send the user
		// back to the password, rather than leaving a shortcut that can only
		// ever fail.
		log.Printf("pin unlock produced an unusable identity: %v", err)
		_ = p.Disable()
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":       "pin unlock is no longer valid — use your password",
			"pin_enabled": false,
		})
		return
	}
	s.ensureDuressBlob()
	s.finishUnlock(w, id)
}

// finishUnlock is the shared tail of both unlock paths: take the session, load
// the chat store, bring Tor up, and hand back a token. Session state is loaded
// synchronously before the response; only the Tor bring-up (seconds of
// bootstrap) runs in the background, so it does not block the perceived unlock
// time while the UI still receives a fully-populated session.
func (s *Server) finishUnlock(w http.ResponseWriter, id *identity.Identity) {
	token, err := s.vault.unlock(id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Load the session state (contacts, chat store, background loops) BEFORE the
	// response. Authenticated requests are gated only on the vault token (see
	// auth()), so the UI can hit session endpoints the instant it holds the
	// token — s.chat / s.contacts must already be populated or those first
	// requests race against nil session state. startSession is fast local disk
	// I/O; the slow part (Tor bootstrap) is deferred below.
	s.startSession(id)
	// Derive the onion key while the identity is still guaranteed live — it reads
	// key material that a concurrent lock would zero, and once the token below is
	// out the client can fire /api/lock at any moment. Only the slow part (Tor
	// bootstrap) is backgrounded; the derive itself is microseconds.
	onionKey, keyErr := onionKeyFor(id)
	// Hand back the token now: the UI transitions to the chat screen with a
	// populated session while Tor bootstraps in the background.
	writeJSON(w, http.StatusOK, map[string]string{
		"account_number": id.AccountNumber(),
		"session_token":  token,
	})
	// Bring Tor up in the background. A Tor failure must not fail unlock — the
	// identity is usable locally regardless; the UI reflects Tor state via
	// /api/identity. s.ready lets callers/tests await bootstrap completion.
	s.ready.Add(1)
	go func() {
		defer s.ready.Done()
		if keyErr != nil {
			log.Printf("derive onion key for tor: %v", keyErr)
			return
		}
		if err := s.startOnion(onionKey); err != nil {
			log.Printf("onion service failed to start: %v", err)
			return
		}
		s.startPublishWatchdog()
	}()
}

// pinEnabled reports whether the unlock screen should offer the PIN pad.
func (s *Server) pinEnabled() bool {
	p := s.currentPin()
	return p != nil && p.Status().Enabled
}
