package mobile

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The prefix the run log is read by: a date, a wall-clock time, and the UTC
// offset that makes it unambiguous once the file is off the device.
var stampRe = regexp.MustCompile(`^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d [+-]\d{4} `)

func TestLocalStampWritesTheDeviceZone(t *testing.T) {
	t.Cleanup(func() { logLoc.Store(nil) })

	// A zone the device's tzdata can't supply falls back to the offset the
	// shell handed us, which is the whole point of passing both.
	SetTimeZone("Mars/Olympus", 2*60*60)
	var buf bytes.Buffer
	line := "publish watchdog: left the service alone\n"
	n, err := localStamp{w: &buf}.Write([]byte(line))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(line) {
		t.Errorf("Write reported %d bytes for a %d-byte line", n, len(line))
	}
	got := buf.String()
	if !stampRe.MatchString(got) {
		t.Errorf("no local timestamp on the line: %q", got)
	}
	if !strings.Contains(got, "+0200 ") {
		t.Errorf("want the +0200 offset we were given, got %q", got)
	}
	if !strings.HasSuffix(got, line) {
		t.Errorf("the line itself was mangled: %q", got)
	}
}

func TestSetTimeZoneLoadsARealZone(t *testing.T) {
	t.Cleanup(func() { logLoc.Store(nil) })

	// Offset deliberately wrong: a loadable zone must win over it, because only
	// the zone knows when DST starts.
	SetTimeZone("America/New_York", 99*60*60)
	loc := logLoc.Load()
	if loc == nil {
		t.Fatal("SetTimeZone stored nothing")
	}
	if loc.String() != "America/New_York" {
		t.Fatalf("want the loaded zone, got %q (fell back to the fixed offset)", loc)
	}
	// Known instants either side of a US transition: the zone, not the offset,
	// decides which applies.
	jan := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC).In(loc).Format("-0700")
	jul := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC).In(loc).Format("-0700")
	if jan != "-0500" || jul != "-0400" {
		t.Errorf("DST not tracked: january %s, july %s", jan, jul)
	}
}

// Never told the zone — a device whose shell predates SetTimeZone — still
// stamps, in UTC, rather than losing the timestamp or panicking on a nil zone.
func TestLocalStampFallsBackToUTC(t *testing.T) {
	logLoc.Store(nil)
	var buf bytes.Buffer
	if _, err := (localStamp{w: &buf}).Write([]byte("hello\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := buf.String(); !stampRe.MatchString(got) || !strings.Contains(got, "+0000 ") {
		t.Errorf("want a UTC-stamped line, got %q", got)
	}
}
