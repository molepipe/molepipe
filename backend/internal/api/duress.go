package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"github.com/molepipe/molepipe/backend/internal/duress"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/unlockguard"
	"github.com/molepipe/molepipe/backend/internal/wipe"
)

// Duress wipe (security doc §2), silent-decoy variant.
//
// NOTHING in the trigger path may log. The coercion scenario has someone
// standing over the machine, and a terminal line reading "duress triggered" is
// a worse tell than the error screen this variant exists to avoid. Errors here
// are deliberately swallowed rather than reported: there is no safe way to
// surface them, and a half-completed wipe that says so out loud is the worst of
// both worlds. The same rule bans a "decoy mode" flag anywhere in the app —
// after the trigger this is a genuine account on a genuine code path, which is
// what makes it indistinguishable.

// checkDuress tests a submitted credential against the duress blob. It is
// called from both unlock prompts on failure, so the panic code works wherever
// a credential is accepted.
func (s *Server) checkDuress(code string) (*identity.Identity, bool) {
	return duress.Check(s.store.Dir, []byte(code))
}

// triggerDuress destroys local data and opens the decoy in its place. The
// caller has already matched the code. It writes the same response shape as any
// successful unlock.
func (s *Server) triggerDuress(w http.ResponseWriter, decoy *identity.Identity, code string) {
	dir := s.store.Dir

	// Stop everything holding the real identity FIRST: the background loops
	// captured it in their closures and would otherwise keep dialling the wiped
	// account's contacts over Tor after the wipe.
	s.haltForWipe()

	// Scrub the real identity in place, then install the decoy over it. The
	// scrub has to happen before the replacement, because an atomic rename
	// unlinks the old inode and puts its ciphertext out of reach — and the
	// threat is a coercer who takes the disk now and gets the password later.
	// The gap where identity.enc is scrubbed but not yet replaced is a single
	// rename wide; a crash inside it leaves an unreadable identity, which is
	// the visible-wipe outcome, not a data leak. This is why the duress path
	// handles identity.enc up front rather than in sensitivity order.
	_ = wipe.Scrub(s.store.Path())
	_ = s.store.Save(decoy, []byte(code))

	// Everything else, ordered by what hurts most if a snapshot catches us
	// half-way, and with relay/ put back empty so the directory still matches
	// a fresh install.
	s.wipeAccountFiles()

	// Re-arm an inert duress blob so the device still carries one — its absence
	// would be as loud as its presence. The code just used is now simply the
	// decoy account's password, so entering it again is an ordinary unlock that
	// wipes nothing.
	_ = duress.Clear(dir)

	// Run the decoy on a genuinely fresh device identity, not the real one's.
	s.reloadDeviceState()

	// Open the decoy exactly the way a real unlock opens a real identity.
	s.finishUnlock(w, decoy)
}

// handleSecurity is the single entry point for changing local security
// settings: PIN on/off and duress on/off.
//
// They share one path deliberately. The request logger records every path, and
// a line reading "POST /api/duress/enable" tells anyone who reads the log that
// a panic code exists — which is exactly the fact §2 has to hide, and it
// survives in the log long after the setup screen is closed. A live-Tor run
// found this: the duress TRIGGER was indistinguishable from a normal unlock, as
// designed, but arming it had written itself down. Routing ordinary PIN changes
// through the same path makes "POST /api/security -> 200" ambiguous, which is
// the property we need. The discriminating action is in the body, which is
// never logged.
func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		Action        string `json:"action"`
		Password      string `json:"password"`
		Code          string `json:"code"`
		WipeEnabled   bool   `json:"wipe_enabled"`
		WipeThreshold int    `json:"wipe_threshold"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	switch req.Action {
	case "pin-enable":
		s.pinEnable(w, id, req.Password, req.Code)
	case "pin-disable":
		s.pinDisable(w)
	case "duress-set":
		s.duressSet(w, req.Password, req.Code)
	case "duress-clear":
		s.duressClear(w)
	case "wipe-set":
		s.wipePolicySet(w, req.Password, req.WipeEnabled, req.WipeThreshold)
	case "phrase-reveal":
		s.phraseReveal(w, req.Password)
	default:
		http.Error(w, "bad request", http.StatusBadRequest)
	}
}

// handleSecurityStatus reports the local security settings the You tab renders:
// PIN state and the erase-after-failed-unlocks policy. It deliberately does NOT
// report anything about the duress code — whether one is set is the single fact
// that feature exists to hide, so it has no status line anywhere.
func (s *Server) handleSecurityStatus(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	g := s.currentGuard()
	resp := map[string]any{
		"pin_enabled":    s.pinEnabled(),
		"wipe_available": g != nil,
		"wipe_enabled":   false,
		"wipe_threshold": unlockguard.DefaultWipeThreshold,
	}
	if g != nil {
		st := g.Status()
		resp["wipe_enabled"] = st.WipeEnabled
		resp["wipe_threshold"] = st.WipeThreshold
	}
	writeJSON(w, http.StatusOK, resp)
}

// wipePolicySet turns the erase-after-failed-unlocks policy on or off. Like PIN
// and duress setup it requires the full password even from an unlocked session:
// arming (or disarming) a control that can destroy the account should not be
// reachable from an unattended unlocked screen. The password check here is a
// direct Load, so a wrong entry is a 401 and never counts toward the very
// counter this setting governs.
func (s *Server) wipePolicySet(w http.ResponseWriter, password string, enabled bool, threshold int) {
	g := s.currentGuard()
	if g == nil {
		http.Error(w, "unlock guard unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, err := s.store.Load([]byte(password)); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "password is incorrect"})
		return
	}
	if enabled && threshold == 0 {
		threshold = unlockguard.DefaultWipeThreshold
	}
	if err := g.SetWipePolicy(enabled, threshold); err != nil {
		if errors.Is(err, unlockguard.ErrThresholdTooLow) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"wipe_enabled": enabled, "wipe_threshold": threshold})
}

// phraseReveal returns the account's 24-word recovery phrase so the user can
// see it again after setup — the onboarding wizard promises it is always
// retrievable rather than shown once. Like every other /api/security action it
// demands the full password even from an unlocked session: the phrase IS the
// whole account, and an unattended unlocked screen must not surrender it to
// whoever taps through Settings. The password is checked by a direct store.Load
// (a wrong entry is a plain 401), so this never consults the duress code — that
// belongs only to the unlock prompt — and never touches the erase counter. A
// coerced user cannot be made to reveal the real phrase without the real
// password, and after a duress unlock the real store is gone entirely.
func (s *Server) phraseReveal(w http.ResponseWriter, password string) {
	id, err := s.store.Load([]byte(password))
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "password is incorrect"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"recovery_phrase": id.MnemonicString()})
}

// duressSet arms the duress code. Like PIN setup it requires the full password
// even from an unlocked session.
func (s *Server) duressSet(w http.ResponseWriter, password, code string) {
	if _, err := s.store.Load([]byte(password)); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "password is incorrect"})
		return
	}
	// A duress code equal to the real password would never fire — the password
	// is tried first and succeeds. A code equal to the PIN is worse: the PIN
	// wins at its own prompt, so the user believes they have a panic code that
	// silently does nothing. A feature that only appears to work is the one
	// outcome worth refusing outright.
	if code == password {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "the duress code must be different from your password — it would never trigger",
		})
		return
	}
	if p := s.currentPin(); p != nil && p.Matches([]byte(code)) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "the duress code must be different from your PIN — it would never trigger",
		})
		return
	}
	if err := duress.Set(s.store.Dir, []byte(code)); err != nil {
		if errors.Is(err, duress.ErrTooShort) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "armed"})
}

// duressClear replaces the armed code with an inert one.
func (s *Server) duressClear(w http.ResponseWriter) {
	if err := duress.Clear(s.store.Dir); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

// ensureDuressBlob creates the always-present blob on installs that predate the
// feature. Called on unlock, where the one-time cost is invisible among the
// Argon2id derivation that already happens there.
func (s *Server) ensureDuressBlob() {
	if _, err := os.Stat(s.store.Path()); err != nil {
		return // no identity yet; nothing to be deniable about
	}
	_ = duress.Ensure(s.store.Dir)
}
