package api

import (
	"context"
	"net/http"
	"runtime"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/updatecheck"
	"github.com/molepipe/molepipe/backend/internal/updatepin"
	"github.com/molepipe/molepipe/backend/internal/version"
)

// updateCheckTimeout bounds the whole synchronous check. A Tor round-trip to the
// release onion can be slow, but a manual "check for updates" tap must not hang
// indefinitely. The check runs inline (no goroutine escapes into the session
// path), so this deadline is the only thing that ends a stuck fetch.
const updateCheckTimeout = 90 * time.Second

// SetRunningVersionCode records the authoritative running build number, injected
// at startup from the platform (on Android, PackageInfo.longVersionCode). Desktop
// need not call it: the handler falls back to version.Code(), the ldflags stamp
// that IS authoritative there. Call once before serving. See the
// runningVersionCode field doc for why Android must not trust that stamp.
func (s *Server) SetRunningVersionCode(code int) {
	s.runningVersionCode.Store(int64(code))
}

// resolveRunningCode returns the build number to compare against the manifest and
// whether it is known. Desktop trusts the ldflags stamp; Android without an
// injected code refuses to compare (fail closed) rather than risk the standalone
// build-aar.sh stamp being stale — the silent mis-compare UPDATE_CHANNEL.md's
// step 6 warns about.
func (s *Server) resolveRunningCode() (int, bool) {
	if code := s.runningVersionCode.Load(); code >= 0 {
		return int(code), true
	}
	if runtime.GOOS == "android" {
		return 0, false
	}
	return version.Code(), true
}

// handleUpdateCheck runs the notify-only update check: fetch the signed release
// manifest over Tor, verify it against the pinned manifest key, and report
// whether a newer build exists. It NEVER downloads or installs anything — the
// client only compares and notifies. Authenticated (a session token), because it
// dials the network on behalf of the unlocked identity.
//
// The states it can return: "disabled" (no pins compiled in — dev or Play),
// "offline" (onion not dialable yet), "unknown" (running build number not
// injected on Android), "error" (fetch/verify/channel failure — fail closed,
// never a prompt), "up_to_date", "stale" (signed but too old — the freeze-attack
// signal), and "available" (a newer signed, fresh build exists).
func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	if !updatepin.Enabled() {
		writeJSON(w, http.StatusOK, updatecheck.Result{State: updatecheck.StateDisabled})
		return
	}
	if s.onion == nil || !s.onion.Dialable() {
		writeJSON(w, http.StatusOK, updatecheck.Result{State: updatecheck.StateOffline})
		return
	}
	code, ok := s.resolveRunningCode()
	if !ok {
		writeJSON(w, http.StatusOK, updatecheck.Result{State: updatecheck.StateUnknown})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), updateCheckTimeout)
	defer cancel()
	res := updatecheck.Check(ctx, s.onion.Dialer(), updatepin.ReleaseOnion, updatepin.Channel, updatepin.PubKey(), code, time.Now())
	writeJSON(w, http.StatusOK, res)
}
