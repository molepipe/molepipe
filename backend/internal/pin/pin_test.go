package pin

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	testPIN      = "246810"
)

// newTestStore builds a Store with a cheap KDF. The real Argon2id cost is
// deliberately high (see Argon2Params) and the attempt-cap test would otherwise
// pay it ten times over; the cost parameter is not what these tests exercise.
func newTestStore(dir string, secret []byte) *Store {
	s := New(dir, secret)
	s.params.TimeCost = 1
	s.params.MemoryKiB = 64
	return s
}

func testStore(t *testing.T) *Store {
	t.Helper()
	return newTestStore(t.TempDir(), bytes.Repeat([]byte{7}, 32))
}

func (s *Store) mustEnable(t *testing.T, code, mnemonic, passphrase string) {
	t.Helper()
	if err := s.Enable([]byte(code), mnemonic, passphrase); err != nil {
		t.Fatalf("Enable: %v", err)
	}
}

func TestEnableThenUnlockRoundTrip(t *testing.T) {
	s := testStore(t)
	if s.Exists() {
		t.Fatal("a fresh data dir should have no pin shortcut")
	}
	s.mustEnable(t, testPIN, testMnemonic, "extra")

	if !s.Exists() {
		t.Fatal("Exists should report the shortcut after Enable")
	}
	m, p, err := s.Unlock([]byte(testPIN))
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if m != testMnemonic || p != "extra" {
		t.Fatalf("round trip mismatch: got mnemonic=%q passphrase=%q", m, p)
	}
}

func TestUnlockRejectsWrongPIN(t *testing.T) {
	s := testStore(t)
	s.mustEnable(t, testPIN, testMnemonic, "")

	if _, _, err := s.Unlock([]byte("999999")); !errors.Is(err, ErrBadPIN) {
		t.Fatalf("wrong pin: got %v, want ErrBadPIN", err)
	}
	// The right PIN still works afterwards, and clears the counter.
	if _, _, err := s.Unlock([]byte(testPIN)); err != nil {
		t.Fatalf("correct pin after a failure: %v", err)
	}
	if got := s.Status().AttemptsLeft; got != MaxAttempts {
		t.Fatalf("a successful unlock should reset the counter, attempts left = %d", got)
	}
}

func TestPINTooShort(t *testing.T) {
	s := testStore(t)
	if err := s.Enable([]byte("12345"), testMnemonic, ""); !errors.Is(err, ErrTooShort) {
		t.Fatalf("short pin: got %v, want ErrTooShort", err)
	}
	if s.Exists() {
		t.Fatal("a rejected pin must not create a blob")
	}
}

func TestUnlockWithoutSetup(t *testing.T) {
	s := testStore(t)
	if _, _, err := s.Unlock([]byte(testPIN)); !errors.Is(err, ErrNotEnabled) {
		t.Fatalf("no shortcut: got %v, want ErrNotEnabled", err)
	}
}

// The PIN blob is bound to the device secret: lifting pin.enc onto another
// machine (a different secret) must not even let the brute-force start.
func TestBlobIsBoundToTheDevice(t *testing.T) {
	dir := t.TempDir()
	s := newTestStore(dir, bytes.Repeat([]byte{7}, 32))
	s.mustEnable(t, testPIN, testMnemonic, "")

	other := newTestStore(dir, bytes.Repeat([]byte{9}, 32))
	// The counter MAC fails first on a foreign secret, so the blob reads as
	// "not set up" — either way the correct PIN yields nothing.
	if _, _, err := other.Unlock([]byte(testPIN)); err == nil {
		t.Fatal("the correct pin must not unlock a blob bound to a different device secret")
	}
}

func TestBackoffEscalatesAndIsPersisted(t *testing.T) {
	dir := t.TempDir()
	secret := bytes.Repeat([]byte{7}, 32)
	now := time.Now()
	s := newTestStore(dir, secret)
	s.now = func() time.Time { return now }
	s.mustEnable(t, testPIN, testMnemonic, "")

	// First two wrong entries are free.
	for i := range 2 {
		if _, _, err := s.Unlock([]byte("000000")); !errors.Is(err, ErrBadPIN) {
			t.Fatalf("attempt %d: got %v, want ErrBadPIN", i+1, err)
		}
	}
	// The third opens a backoff window.
	if _, _, err := s.Unlock([]byte("000000")); !errors.Is(err, ErrBadPIN) {
		t.Fatalf("attempt 3: got %v, want ErrBadPIN", err)
	}
	var te *ThrottleError
	if _, _, err := s.Unlock([]byte(testPIN)); !errors.As(err, &te) {
		t.Fatalf("inside the backoff window: got %v, want ThrottleError", err)
	}

	// Restarting the app must not clear the window — a fresh Store over the
	// same dir sees the persisted counter.
	fresh := newTestStore(dir, secret)
	fresh.now = func() time.Time { return now }
	if _, _, err := fresh.Unlock([]byte(testPIN)); !errors.As(err, &te) {
		t.Fatalf("after restart: got %v, want the backoff to still apply", err)
	}

	// Once the window elapses, the correct PIN goes through.
	now = now.Add(maxBackoff)
	if _, _, err := fresh.Unlock([]byte(testPIN)); err != nil {
		t.Fatalf("after the window elapsed: %v", err)
	}
}

func TestAttemptCapWipesTheShortcutOnly(t *testing.T) {
	dir := t.TempDir()
	// An identity file alongside it stands in for the real one: the cap must
	// never touch it.
	identityPath := filepath.Join(dir, "identity.enc")
	if err := os.WriteFile(identityPath, []byte("identity ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	s := newTestStore(dir, bytes.Repeat([]byte{7}, 32))
	s.now = func() time.Time { return now }
	s.mustEnable(t, testPIN, testMnemonic, "")

	var last error
	for i := range MaxAttempts {
		now = now.Add(2 * maxBackoff) // skip past each backoff window
		_, _, last = s.Unlock([]byte("000000"))
		if i < MaxAttempts-1 && !errors.Is(last, ErrBadPIN) {
			t.Fatalf("attempt %d: got %v, want ErrBadPIN", i+1, last)
		}
	}
	if !errors.Is(last, ErrWiped) {
		t.Fatalf("attempt %d: got %v, want ErrWiped", MaxAttempts, last)
	}
	if s.Exists() {
		t.Fatal("the cap must delete pin.enc")
	}
	if _, err := os.Stat(identityPath); err != nil {
		t.Fatalf("the cap must never touch identity.enc: %v", err)
	}
	if _, _, err := s.Unlock([]byte(testPIN)); !errors.Is(err, ErrNotEnabled) {
		t.Fatalf("after the wipe: got %v, want ErrNotEnabled", err)
	}
}

// Firing the guesses in parallel must not let attempts overwrite each other and
// turn the hard cap into no cap. Every attempt has to be counted.
func TestConcurrentAttemptsAllCount(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	s := newTestStore(dir, bytes.Repeat([]byte{7}, 32))
	s.now = func() time.Time { return now }
	s.mustEnable(t, testPIN, testMnemonic, "")

	const parallel = 8
	var wg sync.WaitGroup
	for range parallel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = s.Unlock([]byte("000000"))
		}()
	}
	wg.Wait()

	// Some of those attempts land inside a backoff window and are refused
	// before they count, so the exact total varies — but the counter must have
	// moved past the two free attempts, which a lost-update race would not.
	if got := s.Status().AttemptsLeft; got > MaxAttempts-3 {
		t.Fatalf("parallel attempts were lost: attempts left = %d, want at most %d", got, MaxAttempts-3)
	}
}

func TestDisableRemovesTheBlob(t *testing.T) {
	s := testStore(t)
	s.mustEnable(t, testPIN, testMnemonic, "")
	if err := s.Disable(); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if s.Exists() {
		t.Fatal("Disable must remove pin.enc")
	}
	// Disabling twice is not an error.
	if err := s.Disable(); err != nil {
		t.Fatalf("Disable (already disabled): %v", err)
	}
}

// Editing the attempt counter by hand must not hand an attacker a fresh set of
// guesses.
func TestTamperedCounterIsRejected(t *testing.T) {
	s := testStore(t)
	s.mustEnable(t, testPIN, testMnemonic, "")
	if _, _, err := s.Unlock([]byte("000000")); !errors.Is(err, ErrBadPIN) {
		t.Fatalf("seed a failure: %v", err)
	}

	raw, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	var b map[string]any
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	b["attempts"] = 0
	edited, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Path(), edited, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Unlock([]byte(testPIN)); !errors.Is(err, ErrNotEnabled) {
		t.Fatalf("tampered counter: got %v, want the blob to be refused", err)
	}
}

// The whole point of the two-layer design: nothing sensitive is readable in the
// file itself.
func TestBlobLeaksNoPlaintext(t *testing.T) {
	s := testStore(t)
	s.mustEnable(t, testPIN, testMnemonic, "secret-passphrase")

	raw, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{testMnemonic, "abandon", "secret-passphrase", testPIN} {
		if strings.Contains(string(raw), needle) {
			t.Fatalf("pin.enc leaks %q in the clear", needle)
		}
	}
}

func TestStatus(t *testing.T) {
	s := testStore(t)
	if st := s.Status(); st.Enabled {
		t.Fatal("no shortcut: Status should report disabled")
	}
	s.mustEnable(t, testPIN, testMnemonic, "")
	st := s.Status()
	if !st.Enabled || st.AttemptsLeft != MaxAttempts || st.RetryAfter != 0 {
		t.Fatalf("fresh shortcut: %+v", st)
	}
	if _, _, err := s.Unlock([]byte("000000")); !errors.Is(err, ErrBadPIN) {
		t.Fatal(err)
	}
	if st := s.Status(); st.AttemptsLeft != MaxAttempts-1 {
		t.Fatalf("after one failure: attempts left = %d", st.AttemptsLeft)
	}
}
