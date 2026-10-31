package runlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// open is the common setup: a run log in a temp dir with a small limit, so a
// test can cross it with a handful of writes instead of 8 MiB of them.
func open(t *testing.T, max int64) (*File, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tormsg.log")
	f, err := Open(path, max)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f, path
}

func write(t *testing.T, f *File, s string) {
	t.Helper()
	if _, err := f.Write([]byte(s)); err != nil {
		t.Fatalf("Write(%q): %v", s, err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	return string(b)
}

func TestRotatesAtLimit(t *testing.T) {
	f, path := open(t, 10)

	// Under the limit: nothing moves.
	write(t, f, "aaaa")
	if _, err := os.Stat(RotatedPath(path)); !os.IsNotExist(err) {
		t.Fatalf("rotated early: %v", err)
	}

	// Crossing it rotates, and the write that crossed is kept — it lands in the
	// generation being rotated out, not dropped.
	write(t, f, "bbbbbbbb")
	if got := read(t, RotatedPath(path)); got != "aaaabbbbbbbb" {
		t.Fatalf("rotated file = %q, want %q", got, "aaaabbbbbbbb")
	}
	if got := read(t, path); got != "" {
		t.Fatalf("live file = %q, want empty", got)
	}

	// The fresh live file takes subsequent writes.
	write(t, f, "cccc")
	if got := read(t, path); got != "cccc" {
		t.Fatalf("live file = %q, want %q", got, "cccc")
	}
}

func TestKeepsOnlyTwoGenerations(t *testing.T) {
	f, path := open(t, 4)

	write(t, f, "1111") // rotate: ".1" = 1111
	write(t, f, "2222") // rotate: ".1" = 2222, the 1111 generation is discarded
	write(t, f, "3333") // rotate: ".1" = 3333

	if got := read(t, RotatedPath(path)); got != "3333" {
		t.Fatalf("rotated file = %q, want the most recent generation %q", got, "3333")
	}
	// There is no ".2": the cap is two files, so the directory cannot creep.
	if _, err := os.Stat(RotatedPath(RotatedPath(path))); !os.IsNotExist(err) {
		t.Fatalf("a second rotated generation exists: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 2 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("got %d files (%s), want exactly 2", len(entries), strings.Join(names, ", "))
	}
}

// Open must adopt the size already on disk. The process restarts far more often
// than the log rotates, so a counter that reset to zero each launch would let an
// already-oversized file grow for ever — the bug rotation is here to fix.
func TestOpenAdoptsExistingSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tormsg.log")
	if err := os.WriteFile(path, []byte("already too big"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	f, err := Open(path, 10)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	write(t, f, "x")
	if got := read(t, path); got != "" {
		t.Fatalf("live file = %q, want empty after rotating an oversized log", got)
	}
	if got := read(t, RotatedPath(path)); got != "already too bigx" {
		t.Fatalf("rotated file = %q", got)
	}
}

// The duress / account-removal wipe truncates the live log underneath this
// writer. The cached counter then overstates the file, and a writer that
// trusted it would rotate an almost-empty log and throw away the previous
// generation for nothing.
func TestTruncationUnderneathDoesNotRotate(t *testing.T) {
	f, path := open(t, 20)

	write(t, f, strings.Repeat("a", 19))
	// Stand in for wipe.Truncate: empty the file this process holds open.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatalf("Truncate: %v", err)
	}

	write(t, f, "b")
	if _, err := os.Stat(RotatedPath(path)); !os.IsNotExist(err) {
		t.Fatalf("rotated after an external truncation: %v", err)
	}
	if got := read(t, path); got != "b" {
		t.Fatalf("live file = %q, want %q", got, "b")
	}
}

func TestZeroMaxDisablesRotation(t *testing.T) {
	f, path := open(t, 0)
	for i := 0; i < 50; i++ {
		write(t, f, "aaaaaaaaaa")
	}
	if _, err := os.Stat(RotatedPath(path)); !os.IsNotExist(err) {
		t.Fatalf("rotated with rotation disabled: %v", err)
	}
	if got := len(read(t, path)); got != 500 {
		t.Fatalf("live file = %d bytes, want 500", got)
	}
}

func TestWriteAfterCloseIsAnError(t *testing.T) {
	f, _ := open(t, 10)
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := f.Write([]byte("x")); err == nil {
		t.Fatal("Write after Close succeeded, want an error")
	}
	// Close is idempotent: closeLog runs on teardown paths that can overlap.
	if err := f.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestRotatedPathIsStable(t *testing.T) {
	if got, want := RotatedPath("/data/tormsg.log"), "/data/tormsg.log.1"; got != want {
		t.Fatalf("RotatedPath = %q, want %q", got, want)
	}
}

// A rotation can fail — most plausibly because the data directory is not
// writable at that moment. Logging must survive it, the cap may be overshot,
// but the retry must NOT happen on every subsequent line: each attempt scrubs a
// whole generation, so a per-line retry would turn one unrenameable file into a
// multi-MiB random-byte write per log statement.
func TestFailedRotationDefersInsteadOfRetryingEveryWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tormsg.log")
	f, err := Open(path, 10)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	// Make the rename fail: a directory with no write permission still allows
	// writing through an already-open fd, and still allows reopening an existing
	// file, but refuses to create or rename entries within it.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	write(t, f, strings.Repeat("a", 10)) // crosses the limit: attempt 1, fails
	if f.attempts != 1 {
		t.Fatalf("attempts = %d after crossing the limit, want 1", f.attempts)
	}
	if _, err := os.Stat(RotatedPath(path)); !os.IsNotExist(err) {
		t.Fatalf("rotation unexpectedly succeeded: %v", err)
	}

	// Writes keep landing, and no further attempt is made for the next max bytes.
	for i := 0; i < 9; i++ {
		write(t, f, "b")
	}
	if f.attempts != 1 {
		t.Fatalf("attempts = %d while deferred, want 1 — retrying per write", f.attempts)
	}
	if got := read(t, path); got != strings.Repeat("a", 10)+strings.Repeat("b", 9) {
		t.Fatalf("writes were lost during a failed rotation: %q", got)
	}

	// Once it has grown another max bytes, it is worth trying again.
	write(t, f, "c")
	if f.attempts != 2 {
		t.Fatalf("attempts = %d after another max bytes, want 2", f.attempts)
	}

	// And when the directory becomes writable, the next attempt succeeds.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod back: %v", err)
	}
	for i := 0; i < 10; i++ {
		write(t, f, "d")
	}
	if _, err := os.Stat(RotatedPath(path)); err != nil {
		t.Fatalf("rotation did not recover once the directory was writable: %v", err)
	}
}

// The guaranteed history is MaxBytes, not twice it: just after a rotation the
// live file is empty. This is the arithmetic MaxBytes is chosen against, so pin
// it — a future "two generations means 2x" reading would halve the window.
func TestGuaranteedHistoryIsOneGenerationNotTwo(t *testing.T) {
	f, path := open(t, 10)
	write(t, f, strings.Repeat("a", 10)) // rotates

	rotated := int64(len(read(t, RotatedPath(path))))
	live := int64(len(read(t, path)))
	if live != 0 {
		t.Fatalf("live file = %d bytes immediately after a rotation, want 0", live)
	}
	if rotated+live != 10 {
		t.Fatalf("history right after a rotation = %d bytes, want one generation (10)", rotated+live)
	}
}
