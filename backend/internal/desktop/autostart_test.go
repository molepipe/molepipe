package desktop

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mk(t *testing.T) *Autostart {
	t.Helper()
	return &Autostart{Dir: t.TempDir(), Exec: "/opt/tor messenger/tormsg-desktop"}
}

func TestSetIsIdempotentBothWays(t *testing.T) {
	a := mk(t)
	if on, err := a.Enabled(); err != nil || on {
		t.Fatalf("a fresh install must be off, got %v %v", on, err)
	}
	for range 2 {
		if err := a.Set(true); err != nil {
			t.Fatal(err)
		}
		if on, _ := a.Enabled(); !on {
			t.Fatal("Set(true) did not enable")
		}
	}
	for range 2 {
		if err := a.Set(false); err != nil {
			t.Fatalf("Set(false) must not fail when already off: %v", err)
		}
		if on, _ := a.Enabled(); on {
			t.Fatal("Set(false) did not disable")
		}
	}
}

// A path with a space is the normal case here, not an edge case: the app is
// unpacked wherever the user puts it, and "Downloads/Molepipe" is an
// entirely ordinary place. An unquoted Exec silently launches nothing.
func TestExecIsQuotedForPathsWithSpaces(t *testing.T) {
	a := mk(t)
	a.Args = []string{"-data-dir", "/home/me/My Files/tormsg"}
	if err := a.Set(true); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(a.Path())
	if err != nil {
		t.Fatal(err)
	}
	want := `Exec="/opt/tor messenger/tormsg-desktop" -data-dir "/home/me/My Files/tormsg"`
	if !strings.Contains(string(b), want) {
		t.Fatalf("Exec line not quoted as expected.\n got: %s\nwant: %s", b, want)
	}
}

// Moving the unpacked folder leaves an entry that would launch a binary which
// is no longer there. Reporting that as "on" tells the user a comforting lie,
// so it must read as off — and turning it on again must repair it.
func TestStaleEntryReadsAsOffAndIsRepaired(t *testing.T) {
	a := mk(t)
	if err := a.Set(true); err != nil {
		t.Fatal(err)
	}
	moved := &Autostart{Dir: a.Dir, Exec: "/somewhere/else/tormsg-desktop"}
	if on, err := moved.Enabled(); err != nil || on {
		t.Fatalf("an entry pointing at a different binary must read as off, got %v %v", on, err)
	}
	if err := moved.Set(true); err != nil {
		t.Fatal(err)
	}
	if on, _ := moved.Enabled(); !on {
		t.Fatal("re-enabling did not repair the stale entry")
	}
}

// The same data directory must come back after a login launch. An entry that
// dropped -data-dir would start the app on the default directory instead —
// an empty account, with the real one apparently gone.
func TestArgsSurviveIntoTheEntry(t *testing.T) {
	a := mk(t)
	a.Args = []string{"-data-dir", "/srv/second"}
	if err := a.Set(true); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(a.Path())
	if !strings.Contains(string(b), "-data-dir /srv/second") {
		t.Fatalf("the data directory did not survive into the entry: %s", b)
	}
	// And an entry written without those args is not the same entry.
	bare := &Autostart{Dir: a.Dir, Exec: a.Exec}
	if on, _ := bare.Enabled(); on {
		t.Fatal("an entry for a different data directory must not read as enabled")
	}
}

// The wipe paths call this. It must succeed when there is nothing to remove,
// or a wipe would report a failure over a file that was already absent.
func TestRemoveEntryToleratesAbsence(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	if err := RemoveEntry(); err != nil {
		t.Fatalf("removing a nonexistent entry must succeed: %v", err)
	}
	a := &Autostart{Dir: filepath.Join(dir, "autostart"), Exec: "/x/tormsg-desktop"}
	if err := a.Set(true); err != nil {
		t.Skipf("start-at-login not implemented here: %v", err)
	}
	if err := RemoveEntry(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a.Path()); !os.IsNotExist(err) {
		t.Fatal("RemoveEntry left the entry behind — a wipe would leak the app's presence")
	}
}

// The one-time notice must be exactly once, and must survive a restart, or the
// app either nags on every launch or never explains itself at all.
func TestBackgroundNoticeIsOnceEver(t *testing.T) {
	dir := t.TempDir()
	s := LoadState(dir)
	if !s.NeedsBackgroundNotice() {
		t.Fatal("the first ask must say yes")
	}
	if s.NeedsBackgroundNotice() {
		t.Fatal("the second ask in the same process must say no")
	}
	if LoadState(dir).NeedsBackgroundNotice() {
		t.Fatal("the notice reappeared after a restart")
	}
}

// The state file must be identical on a fresh install and after a wipe, or it
// becomes a way to tell a decoy directory from a new one.
func TestStateFileCarriesNothingAccountSpecific(t *testing.T) {
	dir := t.TempDir()
	LoadState(dir).NeedsBackgroundNotice()
	b, err := os.ReadFile(filepath.Join(dir, StateFile))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); got != `{"background_notice_shown":true}` {
		t.Fatalf("unexpected state contents %s — anything account-derived here is a leak", got)
	}
}
