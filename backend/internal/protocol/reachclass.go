package protocol

import (
	"context"
	"errors"
	"net"
)

// FailureClass buckets WHY a peer operation failed, so two callers can act on
// the reason instead of on an opaque string:
//
//   - reachRetry (internal/api) tells a TRANSIENT miss (worth another circuit)
//     from a TERMINAL one — retrying a terminal failure just burns the whole
//     multi-minute budget on something that can never succeed.
//   - the HTTP handlers turn the class into an honest message: "they're
//     unreachable" vs "they answered and refused" vs "that answer didn't verify"
//     (and, overlaid at the api layer from Dialable(), "you're offline").
//
// This classifies the PEER/op error only. Whether OUR transport is down is not
// knowable from a peer error — it is decided at the api layer from Dialable(),
// which authoritatively knows our own bootstrap state — so there is deliberately
// no transport-down class here.
type FailureClass int

const (
	// ClassNone is a nil error (the op succeeded).
	ClassNone FailureClass = iota
	// ClassPeerUnreachable: the dial or request never got a well-formed answer —
	// no intro points, SOCKS connect failure, circuit build failed, connection
	// reset. The default transient bucket; another fresh circuit may reach them.
	ClassPeerUnreachable
	// ClassTimeout: an attempt's deadline elapsed mid-op. Transient — the peer may
	// simply be slow to reach (mobile onions routinely take 20-40s). Retry.
	ClassTimeout
	// ClassPeerRejected: the peer ANSWERED and refused with a 4xx. TERMINAL — the
	// identical request will be refused identically (e.g. they blocked us, or the
	// request was malformed). Retrying only wastes the budget.
	ClassPeerRejected
	// ClassProtocol: the peer answered but the answer failed OUR verification —
	// signature invalid, account/hash mismatch. TERMINAL and deterministic: the
	// peer's key is fixed by its onion address, so a bad signature never checks on
	// a retry. Distinct from Rejected because it is a correctness/mismatch signal,
	// not the peer's choice.
	ClassProtocol
	// ClassCanceled: the CALLER's context was canceled (they navigated away, the
	// enclosing budget was cut). TERMINAL — the request is abandoned, not failed.
	ClassCanceled
)

// ErrProtocol wraps a peer answer that failed our own verification. Callers wrap
// it with %w at each verify/mismatch site so Classify can recognise the whole
// family through errors.Is without matching on message text. It is TERMINAL: the
// peer key is bound to its onion address, so a signature or hash that doesn't
// check will never check against the same onion on a retry.
var ErrProtocol = errors.New("peer answer failed verification")

// Retryable reports whether another attempt against a fresh circuit could
// plausibly succeed. The terminal classes (rejected / protocol / canceled)
// never can, so reachRetry stops early on them instead of burning the budget.
func (c FailureClass) Retryable() bool {
	switch c {
	case ClassPeerRejected, ClassProtocol, ClassCanceled:
		return false
	default:
		return true
	}
}

// Classify buckets a peer-op error. Order matters: the caller's cancel and the
// attempt deadline are checked first (both are context errors but mean opposite
// things for retry), then our own verification sentinel, then a peer refusal
// (a *StatusError with a 4xx), then a residual net timeout, else a plain
// unreachable — the safe transient default, so an unrecognised error is retried
// rather than mistaken for terminal.
func Classify(err error) FailureClass {
	if err == nil {
		return ClassNone
	}
	// Caller abandoned the request vs one attempt timing out. Check Canceled
	// first: a canceled context is terminal, a deadline is a retryable slow reach.
	if errors.Is(err, context.Canceled) {
		return ClassCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ClassTimeout
	}
	if errors.Is(err, ErrProtocol) {
		return ClassProtocol
	}
	var se *StatusError
	if errors.As(err, &se) {
		// 4xx: the peer answered and refused — terminal. EXCEPT the transient 4xx
		// codes that explicitly mean "try again": 408 (request timeout), 425 (too
		// early), 429 (too many requests). Our own ungated avatar endpoint returns
		// 429 from its global rate limiter, so treating the whole band as terminal
		// would give up on a throttle that a moment's backoff clears. 5xx or
		// anything else the peer emitted is likewise transient (a mailbox/relay
		// hiccup), worth a retry.
		switch se.Code {
		case 408, 425, 429:
			return ClassPeerUnreachable
		}
		if se.Code >= 400 && se.Code < 500 {
			return ClassPeerRejected
		}
		return ClassPeerUnreachable
	}
	// A net timeout that did not surface as a context deadline (the SOCKS dialer
	// can return one directly) is still a timeout, not a hard unreachable.
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ClassTimeout
	}
	return ClassPeerUnreachable
}
