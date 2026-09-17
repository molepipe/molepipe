package datalock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSecondAcquireIsRefused(t *testing.T) {
	dir := t.TempDir()
	release, err := Acquire(dir)
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	defer release()

	_, err = Acquire(dir)
	var locked *ErrLocked
	if !errors.As(err, &locked) {
		t.Fatalf("second Acquire: got %v, want ErrLocked", err)
	}
	// The message has to point at the fix, not just report the problem — this
	// failure otherwise costs someone an hour of debugging the wrong layer.
	if msg := err.Error(); !contains(msg, "-data-dir") {
		t.Fatalf("error message should suggest a separate data dir: %q", msg)
	}
}

func TestReleaseAllowsReacquire(t *testing.T) {
	dir := t.TempDir()
	release, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	release2, err := Acquire(dir)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	_ = release2()
}

// Different directories are independent — two instances configured correctly
// must both start.
func TestSeparateDirsBothAcquire(t *testing.T) {
	base := t.TempDir()
	a, err := Acquire(filepath.Join(base, "a"))
	if err != nil {
		t.Fatalf("dir a: %v", err)
	}
	defer a()
	b, err := Acquire(filepath.Join(base, "b"))
	if err != nil {
		t.Fatalf("dir b: %v", err)
	}
	defer b()
}

func TestAcquireCreatesDirWithOwnerOnlyPerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fresh")
	release, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("data dir perms = %o, want 700", perm)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
