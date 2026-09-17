package unlockguard

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s := New(dir, []byte("device-secret-under-test-0123456789"))
	return s, dir
}

func TestNoFileUntilAFailure(t *testing.T) {
	s, dir := newTestStore(t)
	// A clean device: no backoff, no file on disk.
	if d := s.Backoff(); d != 0 {
		t.Fatalf("fresh store has backoff %v", d)
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); !os.IsNotExist(err) {
		t.Fatalf("guard file exists before any failure (err=%v)", err)
	}
	// A success with nothing recorded must not create the file either.
	if err := s.RecordSuccess(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); !os.IsNotExist(err) {
		t.Fatalf("RecordSuccess created a file on a clean device (err=%v)", err)
	}
}

func TestBackoffEscalatesAndSuccessClears(t *testing.T) {
	s, dir := newTestStore(t)
	now := time.Now()
	s.now = func() time.Time { return now }

	// First two failures are free (no backoff yet).
	for i := 0; i < 2; i++ {
		if _, err := s.RecordFailure(); err != nil {
			t.Fatal(err)
		}
		if d := s.Backoff(); d != 0 {
			t.Fatalf("failure %d opened a backoff window (%v), want free", i+1, d)
		}
	}
	// Third failure opens a window.
	if _, err := s.RecordFailure(); err != nil {
		t.Fatal(err)
	}
	if d := s.Backoff(); d <= 0 {
		t.Fatalf("third failure should open a backoff window, got %v", d)
	}
	// The counter is persisted (survives a reopen of the same dir).
	reopened := New(dir, []byte("device-secret-under-test-0123456789"))
	reopened.now = func() time.Time { return now }
	if d := reopened.Backoff(); d <= 0 {
		t.Fatalf("backoff did not persist across reopen, got %v", d)
	}
	// A correct password clears it and removes the file (no policy set).
	if err := s.RecordSuccess(); err != nil {
		t.Fatal(err)
	}
	if d := s.Backoff(); d != 0 {
		t.Fatalf("success did not clear backoff, got %v", d)
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); !os.IsNotExist(err) {
		t.Fatalf("success left a residual file behind (err=%v)", err)
	}
}

func TestWipePolicyFiresAtThreshold(t *testing.T) {
	s, _ := newTestStore(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	if err := s.SetWipePolicy(true, 3); err != nil {
		t.Fatal(err)
	}
	// Advance the clock past each backoff window so we actually reach the cap.
	step := func() Outcome {
		now = now.Add(10 * time.Minute) // longer than maxBackoff
		out, err := s.RecordFailure()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if out := step(); out.Wipe || out.AttemptsLeft != 2 {
		t.Fatalf("failure 1: wipe=%v left=%d, want false/2", out.Wipe, out.AttemptsLeft)
	}
	if out := step(); out.Wipe || out.AttemptsLeft != 1 {
		t.Fatalf("failure 2: wipe=%v left=%d, want false/1", out.Wipe, out.AttemptsLeft)
	}
	if out := step(); !out.Wipe || out.AttemptsLeft != 0 {
		t.Fatalf("failure 3: wipe=%v left=%d, want true/0", out.Wipe, out.AttemptsLeft)
	}
}

func TestWipeDisabledMeansNoWipeSignal(t *testing.T) {
	s, _ := newTestStore(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	for i := 0; i < 20; i++ {
		now = now.Add(10 * time.Minute)
		out, err := s.RecordFailure()
		if err != nil {
			t.Fatal(err)
		}
		if out.Wipe {
			t.Fatalf("wipe fired with the policy disabled (attempt %d)", i+1)
		}
		if out.AttemptsLeft != -1 {
			t.Fatalf("attempts_left should be -1 when disabled, got %d", out.AttemptsLeft)
		}
	}
}

func TestThresholdFloorEnforced(t *testing.T) {
	s, _ := newTestStore(t)
	if err := s.SetWipePolicy(true, 2); err != ErrThresholdTooLow {
		t.Fatalf("threshold 2 should be rejected, got %v", err)
	}
	if err := s.SetWipePolicy(true, MinWipeThreshold); err != nil {
		t.Fatalf("threshold %d should be accepted, got %v", MinWipeThreshold, err)
	}
}

func TestTamperedFileFailsSafeToDisabled(t *testing.T) {
	s, dir := newTestStore(t)
	// Arm the policy and rack up a failure so a real file exists.
	if err := s.SetWipePolicy(true, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordFailure(); err != nil {
		t.Fatal(err)
	}
	// Corrupt the MAC by hand.
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, []byte(`{"version":1,"attempts":2,"wipe_enabled":true,"wipe_threshold":3,"mac":"AAAA"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// The tampered policy must NOT be trusted: status reads back as a clean slate
	// with the wipe disabled, and a failure never signals a wipe.
	st := s.Status()
	if st.WipeEnabled {
		t.Fatal("a tampered file was trusted to keep the wipe enabled")
	}
	if st.Attempts != 0 {
		t.Fatalf("a tampered counter should read as 0, got %d", st.Attempts)
	}
	out, err := s.RecordFailure()
	if err != nil {
		t.Fatal(err)
	}
	if out.Wipe {
		t.Fatal("a wipe fired from an unauthenticated policy")
	}
}

func TestDisablingRemovesTheResidualFile(t *testing.T) {
	s, dir := newTestStore(t)
	if err := s.SetWipePolicy(true, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); err != nil {
		t.Fatalf("enabling the policy should write a file: %v", err)
	}
	if err := s.SetWipePolicy(false, 0); err != nil {
		t.Fatal(err)
	}
	// With the policy off and no outstanding failures, the file should be gone so
	// the device looks unused.
	if _, err := os.Stat(filepath.Join(dir, FileName)); !os.IsNotExist(err) {
		t.Fatalf("disabling left a residual file (err=%v)", err)
	}
}
