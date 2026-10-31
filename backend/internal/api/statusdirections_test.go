package api

import (
	"testing"

	"github.com/molepipe/molepipe/backend/internal/tor"
)

// The UI renders its connection indicator from /api/identity, and for the whole
// descriptor-publish window the two directions genuinely disagree: outbound
// circuits are up, so sending works, while nothing can reach us yet. The pill
// splits in two to say exactly that, so these four fields have to keep telling
// the two directions apart rather than averaging them into one word.
func TestIdentityReportsTheTwoDirectionsSeparately(t *testing.T) {
	o := newStatefulOnion(tor.StateDegradedUnreachable)
	s := newServerOnOnion(t, o)
	tok := unlockOn(t, s)

	body := decode(t, s.do(t, "GET", "/api/identity", "", authHdr(s, tok)).Body)
	if sendable, _ := body["tor_sendable"].(bool); !sendable {
		t.Error("tor_sendable false while outbound circuits are up — the UI would disable sending for the whole publish window")
	}
	if ready, _ := body["tor_ready"].(bool); ready {
		t.Error("tor_ready true before the descriptor is published — the UI would claim peers can reach us")
	}
	if got, _ := body["tor_hs_state"].(string); got != "publishing" {
		t.Errorf("tor_hs_state = %q, want %q", got, "publishing")
	}
	// arti's own word for what it is doing. "degraded-unreachable" after a failed
	// upload reads very differently from a first publish still in flight, and the
	// derived hs_state above cannot tell them apart.
	if got, _ := body["tor_service_state"].(string); got != "degraded-unreachable" {
		t.Errorf("tor_service_state = %q, want %q", got, "degraded-unreachable")
	}

	// Published: both directions agree, and the UI collapses back to one word.
	o.ready.Store(true)
	o.state.Store(int32(tor.StateRunning))
	body = decode(t, s.do(t, "GET", "/api/identity", "", authHdr(s, tok)).Body)
	if ready, _ := body["tor_ready"].(bool); !ready {
		t.Error("tor_ready false after the descriptor published")
	}
	if got, _ := body["tor_hs_state"].(string); got != "running" {
		t.Errorf("tor_hs_state = %q, want %q", got, "running")
	}
	if got, _ := body["tor_service_state"].(string); got != "running" {
		t.Errorf("tor_service_state = %q, want %q", got, "running")
	}
}

// Not every backend can ask: the desktop sidecar scrapes a log and has no state
// to report. The field must then be absent-but-harmless (empty), never a
// placeholder the UI would print as if it meant something.
func TestIdentityOmitsServiceStateWhenTheBackendCannotAsk(t *testing.T) {
	s := newServerOnOnion(t, &stuckOnion{}) // no ServiceState method
	tok := unlockOn(t, s)

	body := decode(t, s.do(t, "GET", "/api/identity", "", authHdr(s, tok)).Body)
	if got, _ := body["tor_service_state"].(string); got != "" {
		t.Errorf("tor_service_state = %q, want empty for a backend that cannot report it", got)
	}
	if got, _ := body["tor_hs_state"].(string); got != "publishing" {
		t.Errorf("tor_hs_state = %q, want %q — the derived state must still work without it", got, "publishing")
	}
}
