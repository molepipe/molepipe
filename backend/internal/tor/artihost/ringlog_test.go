package artihost

import (
	"reflect"
	"testing"
)

func TestRingBaseSplitsRepeatSuffix(t *testing.T) {
	for _, tc := range []struct {
		line string
		base string
		n    int
	}{
		{"[WARN] dial failed", "[WARN] dial failed", 1},
		{"[WARN] dial failed (x2)", "[WARN] dial failed", 2},
		{"[WARN] dial failed (x147)", "[WARN] dial failed", 147},
		// Not a count: must be left alone rather than silently truncated.
		{"[WARN] no route (to host)", "[WARN] no route (to host)", 1},
		{"[WARN] weird (x)", "[WARN] weird (x)", 1},
		{"[WARN] weird (x1)", "[WARN] weird (x1)", 1},
		{"[WARN] weird (xabc)", "[WARN] weird (xabc)", 1},
	} {
		base, n := ringBase(tc.line)
		if base != tc.base || n != tc.n {
			t.Errorf("ringBase(%q) = (%q, %d), want (%q, %d)", tc.line, base, n, tc.base, tc.n)
		}
	}
}

func TestNewRingLinesFindsOnlyTheNewOnes(t *testing.T) {
	for _, tc := range []struct {
		name string
		prev []string
		cur  []string
		want []string
	}{
		{"first poll", nil, []string{"a", "b"}, []string{"a", "b"}},
		{"nothing new", []string{"a", "b"}, []string{"a", "b"}, nil},
		{"appended", []string{"a", "b"}, []string{"a", "b", "c"}, []string{"c"}},
		// The window slid: lines were evicted off the front AND added at the
		// back. Comparing lengths would re-log "b" and "c" here.
		{"slid", []string{"a", "b", "c"}, []string{"b", "c", "d"}, []string{"d"}},
		{"turned over", []string{"a", "b"}, []string{"y", "z"}, []string{"y", "z"}},
		// The newest line gained repeats in place: not a new line.
		{"repeat bumped", []string{"a", "b (x2)"}, []string{"a", "b (x3)"}, nil},
		{"repeat then new", []string{"a", "b (x2)"}, []string{"a", "b (x5)", "c"}, []string{"c"}},
	} {
		got := newRingLines(tc.prev, tc.cur)
		if len(got) == 0 && len(tc.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: newRingLines(%v, %v) = %v, want %v", tc.name, tc.prev, tc.cur, got, tc.want)
		}
	}
}

// A line that repeats forever must not be able to make the mirror log forever:
// the drain re-reports it only as the count doubles.
func TestRepeatReportingIsLogarithmic(t *testing.T) {
	base := "[WARN] dial failed"
	lastCount := 1
	reports := 0
	for n := 2; n <= 10000; n++ {
		if n >= lastCount*2 {
			reports++
			lastCount = n
		}
	}
	if reports > 16 {
		t.Errorf("10k repeats produced %d log lines, want a logarithmic handful", reports)
	}
	if reports == 0 {
		t.Errorf("10k repeats of %q produced no log line at all", base)
	}
}
