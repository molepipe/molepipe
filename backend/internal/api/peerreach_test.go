package api

import (
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/tor"
)

// Measured on hardware 2026-10-17: a peer was fetching /p2p/profile over the
// onion 43 seconds after the publish began, and kept doing so every ~40s, while
// Arti's Ready() stayed false for 5m20s — one HSDir that never answered held the
// whole batch up for OVERALL_UPLOAD_TIMEOUT. For 4m37s of that the UI told the
// user nobody could reach them while somebody demonstrably was. An arrival on
// the onion listener means a peer found our descriptor and completed a
// rendezvous with us, so it outranks Arti's not-finished-yet.
func TestPeerArrivalCountsAsReachableBeforeArtiAdmitsIt(t *testing.T) {
	o := newStatefulOnion(tor.StateBootstrapping) // Ready() false, still publishing
	s := newServerOnOnion(t, o)
	tok := unlockOn(t, s)

	body := decode(t, s.do(t, "GET", "/api/identity", "", authHdr(s, tok)).Body)
	if ready, _ := body["tor_ready"].(bool); ready {
		t.Fatal("tor_ready true before anything reached us — the test cannot show the change")
	}

	if err := hitOnionListener(s); err != nil {
		t.Fatalf("peer request to the onion listener: %v", err)
	}

	body = decode(t, s.do(t, "GET", "/api/identity", "", authHdr(s, tok)).Body)
	if ready, _ := body["tor_ready"].(bool); !ready {
		t.Error("tor_ready false while a peer is actively reaching us over the onion")
	}
	if got, _ := body["tor_hs_state"].(string); got != "running" {
		t.Errorf("tor_hs_state = %q, want %q", got, "running")
	}
	// Arti's own word must NOT be overwritten. The disagreement between a
	// "running" hs_state and a "bootstrapping" service_state is exactly what
	// makes this situation visible in diagnostics; collapsing the two would
	// hide the next instance of it.
	if got, _ := body["tor_service_state"].(string); got != "bootstrapping" {
		t.Errorf("tor_service_state = %q, want %q — arti's own state must be reported verbatim", got, "bootstrapping")
	}
}

// The evidence does NOT expire with time, and that is deliberate. A user whose
// only contact closes their app stops being dialled, but nothing has changed
// about their descriptor — it is still published and still being served. On a
// time window the pill would fall back to "publishing your address" a minute
// later, which is the same jarring status this change exists to remove, just
// arriving from the other direction. Measured on hardware: Arti stayed un-Ready
// for over three minutes past the flip, far longer than any contact is
// guaranteed to keep sweeping, so that window is reached easily in practice.
func TestPeerEvidenceSurvivesAQuietContact(t *testing.T) {
	s := newServerOnOnion(t, newStatefulOnion(tor.StateBootstrapping)) // Arti still has not finished
	tok := unlockOn(t, s)
	if err := hitOnionListener(s); err != nil {
		t.Fatalf("peer request to the onion listener: %v", err)
	}
	// The contact goes quiet: no hit for far longer than a presence sweep.
	s.lastPeerHit.Store(time.Now().Add(-30 * time.Minute).UnixNano())

	body := decode(t, s.do(t, "GET", "/api/identity", "", authHdr(s, tok)).Body)
	if ready, _ := body["tor_ready"].(bool); !ready {
		t.Error("tor_ready went false because the contact stopped dialling; the service is still published and the pill would flap")
	}
}

// ...but the latch is not unconditional. If Arti reports a state meaning there
// is no service any more, a past rendezvous proves nothing about the present
// and the latch must not hold the UI green over it. The in-progress states are
// the ones that must still latch: they all have a descriptor out there.
func TestServiceStateThatMeansNothingIsPublishedDropsPeerEvidence(t *testing.T) {
	for _, tc := range []struct {
		st   tor.ServiceState
		want bool
	}{
		{tor.StateBroken, false},
		{tor.StateShutdown, false},
		{tor.StateBootstrapping, true},
		{tor.StateRecovering, true},
		{tor.StateDegradedUnreachable, true},
	} {
		t.Run(tc.st.String(), func(t *testing.T) {
			s := newServerOnOnion(t, newStatefulOnion(tc.st))
			tok := unlockOn(t, s)
			if err := hitOnionListener(s); err != nil {
				t.Fatalf("peer request to the onion listener: %v", err)
			}

			body := decode(t, s.do(t, "GET", "/api/identity", "", authHdr(s, tok)).Body)
			ready, _ := body["tor_ready"].(bool)
			if ready != tc.want {
				t.Errorf("tor_ready = %v on service state %q, want %v", ready, tc.st, tc.want)
			}
		})
	}
}

// The hole this closes: lastPeerHit lives on the Server, not the session, so
// without an explicit reset a hit from the PREVIOUS publish would still be
// inside the window after a lock or a restart — and the UI would report
// reachable during the one window where the new descriptor definitely is not
// published yet. That is the same lie as before, pointing the other way.
func TestTearingTheServiceDownForgetsPeerTraffic(t *testing.T) {
	for _, tc := range []struct {
		name string
		act  func(s *Server)
	}{
		{"stopOnion", func(s *Server) { s.stopOnion() }},
		{"startOnion republishes", func(s *Server) { _ = s.startOnion(tor.OnionKey{}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newServerOnOnion(t, newStatefulOnion(tor.StateRunning))
			if err := hitOnionListener(s); err != nil {
				t.Fatalf("peer request to the onion listener: %v", err)
			}
			if !s.reachProven.Load() {
				t.Fatal("peer hit not recorded — the test cannot show the reset")
			}

			tc.act(s)

			if s.reachProven.Load() {
				t.Error("peer traffic survived the teardown; reachable() would vouch for a descriptor that no longer exists")
			}
		})
	}
}

// ...but the lock grace path is the exception, and deliberately so: it keeps the
// SAME service published so a quick re-unlock is reachable at once. Nothing was
// torn down, so the evidence still holds.
func TestGraceReuseKeepsPeerTraffic(t *testing.T) {
	s := newServerOnOnion(t, newStatefulOnion(tor.StateRunning))
	if err := hitOnionListener(s); err != nil {
		t.Fatalf("peer request to the onion listener: %v", err)
	}
	s.startGrace()

	if err := s.startOnion(tor.OnionKey{}); err != nil {
		t.Fatalf("startOnion: %v", err)
	}
	if !s.reachProven.Load() {
		t.Error("grace reuse forgot peer traffic, so a re-unlock onto a still-published service reports unreachable")
	}
}

// The same flap from the other seat. Arti reaching Running is at least as good
// evidence that we are published as a rendezvous is — but if no peer happened
// to dial during that window, nothing was latched, and the moment an intro
// point drops (tormsg.log is full of "Bootstrapping — intro point failure")
// Ready() goes false, NeedsRestart() is false, and the pill goes red
// mid-session on a service that is merely re-establishing. Arti's own success
// must latch on the same terms as a peer's arrival.
func TestArtiReachingReadyLatchesLikeAPeerArrival(t *testing.T) {
	o := newStatefulOnion(tor.StateRunning)
	o.ready.Store(true)
	s := newServerOnOnion(t, o)
	tok := unlockOn(t, s)

	body := decode(t, s.do(t, "GET", "/api/identity", "", authHdr(s, tok)).Body)
	if ready, _ := body["tor_ready"].(bool); !ready {
		t.Fatal("tor_ready false on a fully published service — the test cannot show the change")
	}

	// An intro point drops and Arti sets about replacing it. Nobody dialled us
	// while we were Running, so a peer-only latch holds nothing.
	o.ready.Store(false)
	o.state.Store(int32(tor.StateRecovering))

	body = decode(t, s.do(t, "GET", "/api/identity", "", authHdr(s, tok)).Body)
	if ready, _ := body["tor_ready"].(bool); !ready {
		t.Error("tor_ready went false while Arti re-establishes an intro point; the pill flaps red mid-session on a published service")
	}
}
