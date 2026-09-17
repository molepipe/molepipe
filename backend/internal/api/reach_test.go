package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// TestReachFailure pins the class-driven copy + the dialable overlay's placement.
// The discriminating rows: a terminal class (protocol/rejected) must NOT flip to
// "offline" even when dialable is false — those classes prove we reached the peer,
// so the overlay only applies on the transient branch. The peer-controlled
// StatusError.Body must never appear in the user-facing message.
func TestReachFailure(t *testing.T) {
	proto := fmt.Errorf("profile signature invalid: %w", protocol.ErrProtocol)
	rejected := &protocol.StatusError{Code: 403, Body: "SECRET-PEER-BODY"}
	unreach := errors.New("no introduction points")
	cases := []struct {
		name       string
		err        error
		dialable   bool
		wantReason string
		wantStatus int
	}{
		{"protocol stays protocol when not dialable", proto, false, "protocol", http.StatusBadGateway},
		{"protocol when dialable", proto, true, "protocol", http.StatusBadGateway},
		{"rejected stays rejected when not dialable", rejected, false, "rejected", http.StatusBadGateway},
		{"rejected when dialable", rejected, true, "rejected", http.StatusBadGateway},
		{"transient + offline blames us", unreach, false, "offline", http.StatusServiceUnavailable},
		{"transient + online blames peer", unreach, true, "unreachable", http.StatusBadGateway},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, reason, msg := reachFailure(tc.err, tc.dialable, "reach that account")
			if status != tc.wantStatus || reason != tc.wantReason {
				t.Fatalf("reachFailure = (%d,%q), want (%d,%q)", status, reason, tc.wantStatus, tc.wantReason)
			}
			if msg == "" {
				t.Fatal("message must not be empty")
			}
			if strings.Contains(msg, "SECRET-PEER-BODY") {
				t.Fatalf("message leaked peer-controlled StatusError.Body: %q", msg)
			}
		})
	}
}

// TestReachRetrySucceedsAfterFailures: a flaky onion that fails the first two
// attempts and then succeeds is reached, not reported unreachable.
func TestReachRetrySucceedsAfterFailures(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	n := 0
	err := reachRetry(ctx, time.Second, time.Millisecond, func(context.Context) error {
		n++
		if n < 3 {
			return errors.New("general SOCKS server failure")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 attempts, got %d", n)
	}
}

// TestReachRetryReturnsLastErrorOnTimeout: when the budget runs out, the last
// underlying error is returned (so it can be logged), not a generic one.
func TestReachRetryReturnsLastErrorOnTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	sentinel := errors.New("descriptor not found")
	err := reachRetry(ctx, 20*time.Millisecond, 5*time.Millisecond, func(context.Context) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected the last underlying error, got %v", err)
	}
}

// TestReachRetryStopsEarlyOnTerminal: a peer whose answer fails verification
// (ClassProtocol) will fail identically forever — reachRetry must return after
// ONE attempt rather than burning the whole budget. This is the acute bug the
// taxonomy fixes: before, a signature-invalid peer hung the caller for minutes.
func TestReachRetryStopsEarlyOnTerminal(t *testing.T) {
	// A generous budget: if the early-stop is broken, this would loop many times
	// well within it, so the attempt count is the discriminating assertion.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	n := 0
	terminal := fmt.Errorf("profile signature invalid: %w", protocol.ErrProtocol)
	err := reachRetry(ctx, time.Second, 10*time.Millisecond, func(context.Context) error {
		n++
		return terminal
	})
	if !errors.Is(err, protocol.ErrProtocol) {
		t.Fatalf("expected the terminal error back, got %v", err)
	}
	if n != 1 {
		t.Fatalf("terminal failure must not be retried: got %d attempts, want 1", n)
	}
}

// TestReachRetryStopsEarlyOnRejection: a 4xx from the peer (it answered and
// refused) is likewise terminal — one attempt, no retry loop.
func TestReachRetryStopsEarlyOnRejection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	n := 0
	err := reachRetry(ctx, time.Second, 10*time.Millisecond, func(context.Context) error {
		n++
		return &protocol.StatusError{Code: 403, Body: "blocked"}
	})
	var se *protocol.StatusError
	if !errors.As(err, &se) || se.Code != 403 {
		t.Fatalf("expected the 403 back, got %v", err)
	}
	if n != 1 {
		t.Fatalf("peer rejection must not be retried: got %d attempts, want 1", n)
	}
}

// TestReachRetryRetriesTransient: a transient class (a plain unreachable) is
// still retried to the budget — the early-stop must not swallow a peer that a
// fresh circuit could reach.
func TestReachRetryRetriesTransient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	n := 0
	_ = reachRetry(ctx, 20*time.Millisecond, time.Millisecond, func(context.Context) error {
		n++
		return errors.New("no introduction points")
	})
	if n < 2 {
		t.Fatalf("transient failure must be retried: got %d attempts, want >= 2", n)
	}
}

// TestReachBackoffBounds: full-jitter exponential backoff stays within
// [0, min(cap, base*2^attempt)] and collapses to 0 for a non-positive base
// (so a zero gap keeps its old immediate-retry behaviour).
func TestReachBackoffBounds(t *testing.T) {
	if got := reachBackoff(0, 5); got != 0 {
		t.Fatalf("zero base must yield zero backoff, got %v", got)
	}
	base := 100 * time.Millisecond
	const capGap = 30 * time.Second
	for attempt := 0; attempt < 12; attempt++ {
		ceil := base
		for i := 0; i < attempt && ceil < capGap; i++ {
			ceil *= 2
		}
		if ceil > capGap {
			ceil = capGap
		}
		// Sample repeatedly: jitter is random, so one draw can't prove the bound.
		for i := 0; i < 200; i++ {
			d := reachBackoff(base, attempt)
			if d < 0 || d > ceil {
				t.Fatalf("attempt %d: backoff %v out of [0,%v]", attempt, d, ceil)
			}
		}
	}
}
