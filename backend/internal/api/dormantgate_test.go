package api

import (
	"testing"

	"github.com/molepipe/molepipe/backend/internal/tor"
)

// TorServing is shell binding API with no caller today, and before this it
// read onion.Ready() live. Arti reports Bootstrapping for a routine descriptor
// REUPLOAD on a service that is still published, and Ready() is false in
// Bootstrapping: one phone logged 24 such dips in 12 minutes on 2026-10-20
// while serving peers throughout. A live read therefore makes the power policy
// flip tens of times an hour on a perfectly healthy service, and a backgrounding
// that lands inside a dip silently fails to go dormant.
func TestTorServingSurvivesAReuploadDip(t *testing.T) {
	o := newStatefulOnion(tor.StateRunning)
	// Published before the unlock, so the publish watchdog takes its early exit
	// at the first Ready() and cannot restart the service underneath the test.
	o.ready.Store(true)
	s := newServerOnOnion(t, o)
	unlockOn(t, s)

	if !s.TorServing() {
		t.Fatal("TorServing false on a published, unlocked service")
	}

	// The dip. Nothing about our hosting has changed: the descriptor is still
	// out there and the intro points are still established.
	o.ready.Store(false)
	o.state.Store(int32(tor.StateBootstrapping))
	if !s.TorServing() {
		t.Error("a descriptor-reupload dip reported Tor as not serving")
	}

	// Same for every other state that still means work in progress, which is
	// what Arti spends most of a flap in.
	for _, st := range []tor.ServiceState{tor.StateDegradedUnreachable, tor.StateRecovering, tor.StateDegradedReachable} {
		o.state.Store(int32(st))
		if !s.TorServing() {
			t.Errorf("TorServing false in %v, which still has a descriptor being served", st)
		}
	}
}

// The latch must not swallow the cases where we really have stopped hosting —
// otherwise the gate is stuck open and dormant mode engages against a service
// that is trying to publish, which is the thing the gate exists to prevent.
func TestTorServingDropsWhenTheServiceIsGone(t *testing.T) {
	for _, st := range []tor.ServiceState{tor.StateShutdown, tor.StateBroken} {
		t.Run(st.String(), func(t *testing.T) {
			o := newStatefulOnion(tor.StateRunning)
			o.ready.Store(true)
			s := newServerOnOnion(t, o)
			unlockOn(t, s)
			if !s.TorServing() {
				t.Fatal("TorServing false on a published, unlocked service")
			}

			o.ready.Store(false)
			o.state.Store(int32(st))
			if s.TorServing() {
				t.Errorf("TorServing stayed true in %v — nothing is published any more", st)
			}
		})
	}
}

// A locked app hosts no onion at all, whatever evidence the latch is holding
// from the session before. Note this does not isolate the vault.unlocked() term:
// /api/lock also tears the onion down, so either half could be what satisfies
// it. It guards the observable behaviour, not the mechanism.
func TestTorServingIsFalseWhileLocked(t *testing.T) {
	o := newStatefulOnion(tor.StateRunning)
	o.ready.Store(true)
	s := newServerOnOnion(t, o)
	tok := unlockOn(t, s)
	if !s.TorServing() {
		t.Fatal("TorServing false on a published, unlocked service")
	}

	if r := s.do(t, "POST", "/api/lock", "", authHdr(s, tok)); r.Code != 200 {
		t.Fatalf("lock: %d", r.Code)
	}
	if s.TorServing() {
		t.Error("TorServing true while the vault is locked")
	}
}

// The case that decides which latch the dormant gate may use. A peer can reach
// us off a descriptor published in a PREVIOUS session — HS descriptors live 3
// hours and the intro points stay established — while this session's publisher
// is still retrying HSDir uploads. One device on 2026-10-20 was in exactly that
// state: DegradedUnreachable, "descriptor upload failed (1): timeout ... 14
// times, but all attempts failed", serving the other device every ~30s off the
// old descriptor.
//
// Dormant mode suspends preemptive circuit building and directory fetches, which
// is the work that retry depends on. So reachability — which latches on peer
// traffic — must NOT open this gate; only our own completed publish may.
func TestDormantStaysDeferredWhileOurOwnPublishHasNeverLanded(t *testing.T) {
	// Ready() false throughout: the publisher is still retrying, and
	// DegradedUnreachable is not NeedsRestart, so the watchdog's state veto
	// holds it off rather than restarting under the test.
	o := newStatefulOnion(tor.StateDegradedUnreachable)
	s := newServerOnOnion(t, o)
	unlockOn(t, s)

	if s.DormantAllowed() {
		t.Fatal("dormant allowed before anything was published at all")
	}

	if err := hitOnionListener(s); err != nil {
		t.Fatalf("peer request to the onion listener: %v", err)
	}

	// Somebody demonstrably reaches us, so "is Tor serving" is true and the
	// status pill is green — both correct.
	if !s.TorServing() {
		t.Error("TorServing false while a peer is actively reaching us over the onion")
	}
	// But our own descriptor has never landed this session.
	if s.DormantAllowed() {
		t.Error("dormant allowed off peer traffic alone, while our publisher is still retrying HSDir uploads")
	}

	// Only Arti confirming the publication opens it.
	o.ready.Store(true)
	o.state.Store(int32(tor.StateRunning))
	if !s.DormantAllowed() {
		t.Error("dormant still deferred after our own publish completed")
	}
}

// A republish means an unfinished publish, so the gate must close again for it.
// Documented here because it looks like a regression to anyone who assumes the
// latch is one-way for the session.
func TestDormantDefersAgainThroughARepublish(t *testing.T) {
	o := newStatefulOnion(tor.StateRunning)
	o.ready.Store(true)
	s := newServerOnOnion(t, o)
	unlockOn(t, s)
	if !s.DormantAllowed() {
		t.Fatal("dormant deferred on a published, unlocked service")
	}

	o.ready.Store(false)
	o.state.Store(int32(tor.StateBootstrapping))
	// A reupload dip is not a republish: the gate stays open.
	if !s.DormantAllowed() {
		t.Error("a descriptor-reupload dip closed the dormant gate")
	}

	s.forgetReachEvidence()
	if s.DormantAllowed() {
		t.Error("dormant allowed through a republish, whose publish has not landed yet")
	}
}
