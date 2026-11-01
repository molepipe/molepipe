package porthint

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	Write(dir, "54321")
	if got := Read(dir); got != "54321" {
		t.Fatalf("Read = %q, want 54321", got)
	}
	addr, hinted := Addr(dir)
	if addr != "127.0.0.1:54321" || !hinted {
		t.Fatalf("Addr = %q, %v; want 127.0.0.1:54321, true", addr, hinted)
	}
}

// With no hint the caller must get an OS-assigned port AND be told it was not
// hinted — that second value is what stops it retrying a bind failure that has
// nothing to do with a stale hint.
func TestNoHintIsNotReportedAsHinted(t *testing.T) {
	dir := t.TempDir()
	if got := Read(dir); got != "" {
		t.Fatalf("Read of an empty dir = %q, want \"\"", got)
	}
	addr, hinted := Addr(dir)
	if addr != "127.0.0.1:0" || hinted {
		t.Fatalf("Addr = %q, %v; want 127.0.0.1:0, false", addr, hinted)
	}
}

// Everything unusable must read as "no hint" rather than being passed through:
// the value is concatenated into a listen address, so anything that is not a
// bindable port number has to be dropped here.
func TestUnusableHintsAreIgnored(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
	}{
		{"empty", ""},
		{"blank", "   \n"},
		{"not a number", "abcd"},
		{"host and port", "127.0.0.1:54321"},
		{"privileged", "80"},
		{"zero", "0"},
		{"above range", "65536"},
		{"negative", "-1"},
		{"injection", "54321\nevil"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, File), []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := Read(dir); got != "" {
				t.Fatalf("Read(%q) = %q, want \"\" (unusable hints must be dropped)", tc.content, got)
			}
			if addr, hinted := Addr(dir); addr != "127.0.0.1:0" || hinted {
				t.Fatalf("Addr = %q, %v; want 127.0.0.1:0, false", addr, hinted)
			}
		})
	}
}

// Surrounding whitespace is normal for a file written by hand or by an editor
// that adds a trailing newline, and must not invalidate an otherwise good hint.
func TestSurroundingWhitespaceIsTolerated(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, File), []byte("  54321\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Read(dir); got != "54321" {
		t.Fatalf("Read = %q, want 54321", got)
	}
}

// Writing "" must not create or truncate the file: a caller that could not
// determine its port should leave the previous good hint alone.
func TestWriteEmptyLeavesTheExistingHint(t *testing.T) {
	dir := t.TempDir()
	Write(dir, "54321")
	Write(dir, "")
	if got := Read(dir); got != "54321" {
		t.Fatalf("Read = %q, want the earlier 54321 to survive", got)
	}
}

// The hint is inside the app's private data directory and names a port the UI
// is reachable on; it is not a secret, but it should not be world-readable.
func TestHintIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	Write(dir, "54321")
	fi, err := os.Stat(filepath.Join(dir, File))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("hint mode = %o, want 600", perm)
	}
}

// An unwritable directory must not panic or fail the caller: losing the hint is
// one round of reset preferences, never a reason to fail a good startup.
func TestWriteToAnUnwritableDirIsSilent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	Write(dir, "54321")
	if got := Read(dir); got != "" {
		t.Fatalf("Read = %q, want \"\"", got)
	}
}
