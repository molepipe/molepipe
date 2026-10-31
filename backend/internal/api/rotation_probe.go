//go:build molepiperotationprobe

package api

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/molepipe/molepipe/backend/internal/tor"
)

// probeCounter gives each probe alias a unique arti nickname.
var probeCounter atomic.Uint64

// registerRotationProbe wires the Phase-A feasibility endpoints (compiled in
// ONLY under the `molepiperotationprobe` build tag). They answer the gating
// question for the rotating-identity epic: can the native Tor layer publish and
// keep reachable a SECOND onion service alongside the primary account onion?
//
//	POST /api/dev/alias-probe        → mint a throwaway alias key, start an extra
//	                                    onion, return {onion,id}
//	GET  /api/dev/alias-probe/dial?onion=<addr>
//	                                 → self-dial that onion; {reachable,err}
//	POST /api/dev/alias-probe/stop?id=<id>
//	                                 → tear the alias down
//
// The alias key is random (NOT the account) so the probe never publishes a real
// identity. All endpoints sit behind the control-token auth like the rest of /api.
func (s *Server) registerRotationProbe(mux *http.ServeMux) {
	// NOT behind s.auth: the probe validates two concurrent aliases at the LOCK
	// screen (pre-warm client up, real account never unlocked). Still gated by
	// the control-token guard that wraps the whole mux. Log the token so the
	// probe can be driven from `adb shell` — dev-tag build only.
	log.Printf("[rotation-probe] armed; control token = %s", s.controlToken)
	mux.HandleFunc("POST /api/dev/alias-probe", s.handleAliasProbeStart)
	mux.HandleFunc("GET /api/dev/alias-probe/dial", s.handleAliasProbeDial)
	mux.HandleFunc("POST /api/dev/alias-probe/stop", s.handleAliasProbeStop)
}

func (s *Server) handleAliasProbeStart(w http.ResponseWriter, r *http.Request) {
	host, ok := s.asExtraOnionHost()
	if !ok {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "onion host does not support concurrent alias services"})
		return
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rng: " + err.Error()})
		return
	}
	key, err := tor.DeriveOnionKey(seed)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "derive: " + err.Error()})
		return
	}
	nick := fmt.Sprintf("probe-%d", probeCounter.Add(1))
	onion, id, err := host.StartExtraService(key, s.publicAddr(), nick)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"onion": onion, "id": id, "nickname": nick})
}

func (s *Server) handleAliasProbeDial(w http.ResponseWriter, r *http.Request) {
	onion := r.URL.Query().Get("onion")
	if onion == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing onion"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	conn, err := s.onion.Dialer().DialOnion(ctx, onion+":80")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"reachable": false, "error": err.Error()})
		return
	}
	_ = conn.Close()
	writeJSON(w, http.StatusOK, map[string]any{"reachable": true})
}

func (s *Server) handleAliasProbeStop(w http.ResponseWriter, r *http.Request) {
	host, ok := s.asExtraOnionHost()
	if !ok {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "unsupported"})
		return
	}
	var id uint64
	if _, err := fmt.Sscan(r.URL.Query().Get("id"), &id); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	host.StopExtraService(id)
	writeJSON(w, http.StatusOK, map[string]any{"stopped": id})
}
