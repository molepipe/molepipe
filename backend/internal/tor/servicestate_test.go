package tor

import "testing"

// A restart drops the intro points and the descriptor-signing keys, so it only
// helps where the service has actually stopped making progress. Every other
// state is work a restart would throw away — a phone lost 14 in-flight HSDir
// uploads and 6m35s to one. Guard the split, including the zero value: an
// implementation that cannot report state must not come out as "leave it
// alone", because "no information" is a question for the caller's fallback,
// not an answer from here.
func TestNeedsRestartOnlyWhereARestartIsTheRemedy(t *testing.T) {
	want := map[ServiceState]bool{
		StateUnknown:             false,
		StateShutdown:            true,
		StateBootstrapping:       false,
		StateDegradedUnreachable: false,
		StateRunning:             false,
		StateDegradedReachable:   false,
		StateRecovering:          false,
		StateBroken:              true,
		ServiceState(99):         false, // a state a future arti might add
	}
	for st, w := range want {
		if got := st.NeedsRestart(); got != w {
			t.Errorf("%s (%d).NeedsRestart() = %v, want %v", st, int(st), got, w)
		}
	}
}

// The codes cross an FFI boundary (torhost_service_state in
// torhost/src/lib.rs). Reordering them silently remaps arti's states onto the
// wrong meanings — "broken" read as "running" would strand a dead service —
// so pin the wire values.
func TestServiceStateCodesMatchTheRustSide(t *testing.T) {
	want := map[ServiceState]int{
		StateUnknown: 0, StateShutdown: 1, StateBootstrapping: 2,
		StateDegradedUnreachable: 3, StateRunning: 4,
		StateDegradedReachable: 5, StateRecovering: 6, StateBroken: 7,
	}
	for st, code := range want {
		if int(st) != code {
			t.Errorf("%s = %d, want %d", st, int(st), code)
		}
	}
}
