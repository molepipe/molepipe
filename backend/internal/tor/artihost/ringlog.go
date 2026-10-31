// Package-level helpers for mirroring the Rust log ring into the Go run log.
//
// Deliberately NOT behind the android||ios build tag that covers the rest of
// this package: the diff logic below is the only part with edge cases worth a
// test, and a tagged file cannot be tested on the host (there is no NDK and no
// libtorhost.a). Everything here is pure Go — no cgo — so it compiles anywhere.
package artihost

import (
	"strconv"
	"strings"
)

// ringBase splits a ring line into its text and its repeat count.
//
// The Rust ring collapses an identical consecutive message into one entry with
// a " (xN)" suffix, which means the newest entry can change in place — a retry
// loop logging the same failure turns "(x2)" into "(x3)" with no new line
// added. Mirroring compares base text so such a line is recognised as the one
// already written to the log rather than mistaken for a new one.
func ringBase(line string) (string, int) {
	if !strings.HasSuffix(line, ")") {
		return line, 1
	}
	i := strings.LastIndex(line, " (x")
	if i < 0 {
		return line, 1
	}
	n, err := strconv.Atoi(line[i+len(" (x") : len(line)-1])
	if err != nil || n < 2 {
		return line, 1
	}
	return line[:i], n
}

// newRingLines returns the entries of cur that prev did not already contain.
//
// The ring is a sliding window, so between two polls it has lost some number of
// lines off the front and gained some at the back: cur is prev with a prefix
// dropped and a suffix added. Recovering the suffix means finding the longest
// overlap between the tail of prev and the head of cur — not simply comparing
// lengths, which would double-log everything whenever the window had also
// evicted lines. With no overlap at all (a poll slow enough that the whole ring
// turned over, or the first poll) every line is new, which is the safe
// direction to err: a duplicated log line is readable, a dropped one is gone.
func newRingLines(prev, cur []string) []string {
	max := len(prev)
	if len(cur) < max {
		max = len(cur)
	}
	for m := max; m > 0; m-- {
		if ringOverlaps(prev[len(prev)-m:], cur[:m]) {
			return cur[m:]
		}
	}
	return cur
}

// ringOverlaps reports whether two equal-length runs of ring lines are the same
// messages, ignoring repeat counts.
func ringOverlaps(a, b []string) bool {
	for i := range a {
		x, _ := ringBase(a[i])
		y, _ := ringBase(b[i])
		if x != y {
			return false
		}
	}
	return true
}
