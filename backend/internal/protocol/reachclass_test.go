package protocol

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// fakeNetErr is a net.Error with a settable Timeout(), to prove Classify routes
// a residual net timeout (one that did not surface as a context deadline) to
// ClassTimeout rather than the hard-unreachable default.
type fakeNetErr struct{ timeout bool }

func (e fakeNetErr) Error() string   { return "net error" }
func (e fakeNetErr) Timeout() bool   { return e.timeout }
func (e fakeNetErr) Temporary() bool { return false }

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want FailureClass
	}{
		{"nil is none", nil, ClassNone},
		{"caller canceled", fmt.Errorf("op: %w", context.Canceled), ClassCanceled},
		{"attempt deadline", fmt.Errorf("op: %w", context.DeadlineExceeded), ClassTimeout},
		{"verification failure", fmt.Errorf("profile signature invalid: %w", ErrProtocol), ClassProtocol},
		{"verification failure double-wrapped", fmt.Errorf("lookup: %w", fmt.Errorf("bad: %w", ErrProtocol)), ClassProtocol},
		{"peer refused 4xx", &StatusError{Code: 403, Body: "blocked"}, ClassPeerRejected},
		{"peer refused 400", &StatusError{Code: 400}, ClassPeerRejected},
		{"throttled 429 is transient", &StatusError{Code: 429}, ClassPeerUnreachable},
		{"request timeout 408 is transient", &StatusError{Code: 408}, ClassPeerUnreachable},
		{"too early 425 is transient", &StatusError{Code: 425}, ClassPeerUnreachable},
		{"peer 5xx is transient", &StatusError{Code: 502}, ClassPeerUnreachable},
		{"net timeout", fakeNetErr{timeout: true}, ClassTimeout},
		{"net non-timeout falls through", fakeNetErr{timeout: false}, ClassPeerUnreachable},
		{"unknown error is unreachable", errors.New("general SOCKS server failure"), ClassPeerUnreachable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.err); got != tc.want {
				t.Fatalf("Classify(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

// TestRetryable pins the terminal/transient split that reachRetry depends on:
// only rejected/protocol/canceled are terminal; everything else is worth another
// circuit. A wrong split here would either resurrect the budget-burning hang
// (terminal treated as retryable) or give up on a reachable-but-slow peer
// (transient treated as terminal).
func TestRetryable(t *testing.T) {
	terminal := []FailureClass{ClassPeerRejected, ClassProtocol, ClassCanceled}
	retryable := []FailureClass{ClassNone, ClassPeerUnreachable, ClassTimeout}
	for _, c := range terminal {
		if c.Retryable() {
			t.Fatalf("class %d should be terminal", c)
		}
	}
	for _, c := range retryable {
		if !c.Retryable() {
			t.Fatalf("class %d should be retryable", c)
		}
	}
}
