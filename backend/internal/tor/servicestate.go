package tor

// ServiceState is an onion service's own view of its publication state, as
// reported by the Tor implementation underneath. It exists because Ready() is a
// single bit — "can peers reach us" — and a false answer there covers two
// opposite situations: the publisher is grinding through descriptor uploads and
// getting somewhere, or it has given up. Restarting is the remedy for the second
// and actively destructive in the first (it drops the intro points and the
// descriptor-signing keys, so every in-flight upload is discarded and the
// several-minute publish starts over).
//
// Only some implementations can answer. Desktop's Arti sidecar is driven by log
// scraping and cannot, so this is NOT part of OnionService: a caller asserts for
// an optional accessor and falls back to its own heuristics when absent. The
// codes mirror torhost_service_state in torhost/src/lib.rs — keep them in step.
type ServiceState int

const (
	// StateUnknown means the implementation has no opinion: it does not track
	// state, has no service running, or reported a state this build does not
	// know. Callers must treat it as "no information" and fall back, never as
	// either answer.
	StateUnknown ServiceState = 0
	// StateShutdown means the service is not running at all.
	StateShutdown ServiceState = 1
	// StateBootstrapping means the service is starting up and has not hit any
	// significant problem yet.
	StateBootstrapping ServiceState = 2
	// StateDegradedUnreachable means the intro points are up but the descriptor
	// has not been uploaded to one or more HsDirs — the publisher is retrying.
	StateDegradedUnreachable ServiceState = 3
	// StateRunning means fully published and reachable.
	StateRunning ServiceState = 4
	// StateDegradedReachable means reachable, with some component unhappy.
	StateDegradedReachable ServiceState = 5
	// StateRecovering means a problem was hit and recovery is under way.
	StateRecovering ServiceState = 6
	// StateBroken means the failure is unrecoverable, or recovery was attempted
	// for a while and failed.
	StateBroken ServiceState = 7
)

// NeedsRestart reports whether restarting the service is the right response to
// this state.
//
// Only two states qualify. StateBroken is the condition a restart exists for —
// the failure is unrecoverable, or recovery already ran for a while and failed.
// StateShutdown means nothing is published and nothing is trying to be, so
// starting it is simply correct.
//
// Everything else is work in progress that a restart would throw away:
// bootstrapping has not hit a problem yet, degraded-unreachable means the
// descriptor upload is being retried right now, and recovering means arti is
// already doing what a restart would ask for. The reachable states cannot
// reach this method in practice — a caller only asks after Ready() came back
// false, and Ready() is true for both of them — but they answer false for the
// same reason. StateUnknown answers false as well; a caller must gate on
// whether the state is known at all rather than on this bit, since "no
// information" is not "leave it alone".
func (s ServiceState) NeedsRestart() bool {
	return s == StateBroken || s == StateShutdown
}

// String names the state for log lines.
func (s ServiceState) String() string {
	switch s {
	case StateShutdown:
		return "shutdown"
	case StateBootstrapping:
		return "bootstrapping"
	case StateDegradedUnreachable:
		return "degraded-unreachable"
	case StateRunning:
		return "running"
	case StateDegradedReachable:
		return "degraded-reachable"
	case StateRecovering:
		return "recovering"
	case StateBroken:
		return "broken"
	default:
		return "unknown"
	}
}
