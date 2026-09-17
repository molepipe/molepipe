// Package unlockguard tracks failed password-unlock attempts on this device and
// enforces an escalating backoff, plus an optional "erase everything after N
// failed attempts" policy the user turns on explicitly.
//
// It is the password-path analogue of the counter the PIN shortcut already keeps
// in pin.enc: a small, MAC'd state file bound to the device secret, persisted so
// that killing and restarting the app does not hand an attacker a fresh set of
// guesses. It stores no key material of its own — identity.enc stays exactly as
// it was — so a lost or corrupt guard file costs at most the backoff state, never
// the account.
//
// Honest scoping. The counter is authenticated under the device secret, which
// stops a casual text-editor reset of the attempt count or a hand-flipped wipe
// flag. It does NOT defend against someone who can write to the whole data
// directory: they can restore an older copy of this file, and they already hold
// identity.enc for an offline attack, so no online counter is meaningful to
// them. The wipe policy is therefore aimed at the coercion-at-the-keyboard case
// (someone forcing guesses at the unlock screen without file access), the same
// case the PIN cap and the duress code address.
package unlockguard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/molepipe/molepipe/backend/internal/wipe"
)

// FileName is the on-disk state file. Exported so the wipe paths can remove it
// (a directory that still held it would be visibly a used one, not the fresh
// install a duress or account-removal wipe is supposed to present).
const FileName = "unlock_guard.json"

const (
	version = 1

	// maxBackoff caps the escalating delay so a genuine owner who fat-fingers the
	// password a few times isn't locked out for an unbounded stretch.
	maxBackoff = 5 * time.Minute

	// DefaultWipeThreshold and MinWipeThreshold bound the erase-after-N policy.
	// The floor stops a foot-gun (erase after one typo) while still letting a
	// cautious user pick something strict.
	DefaultWipeThreshold = 10
	MinWipeThreshold     = 3
)

// ErrThresholdTooLow rejects a wipe threshold below MinWipeThreshold.
var ErrThresholdTooLow = fmt.Errorf("erase threshold must be at least %d failed attempts", MinWipeThreshold)

// ThrottleError is returned while an attempt lands inside the backoff window.
type ThrottleError struct{ RetryAfter time.Duration }

func (e *ThrottleError) Error() string {
	return fmt.Sprintf("too many attempts — try again in %s", e.RetryAfter.Round(time.Second))
}

// state is the on-disk unlock_guard.json. Everything here is local, non-secret
// metadata; the MAC authenticates it under the device secret.
type state struct {
	Version       int       `json:"version"`
	Attempts      int       `json:"attempts"`
	LastAttempt   time.Time `json:"last_attempt"`
	WipeEnabled   bool      `json:"wipe_enabled"`
	WipeThreshold int       `json:"wipe_threshold"`
	MAC           string    `json:"mac"` // base64, over the fields above
}

// Store guards password unlock for one data directory, bound to that device's
// local secret.
type Store struct {
	dir    string
	secret []byte

	// mu serializes every operation, so ten concurrent wrong passwords cannot
	// each read attempts=0 and each write attempts=1 — the lost-update race that
	// would turn the cap into no cap at all.
	mu sync.Mutex
	// now is the clock, swappable in tests to exercise the backoff schedule
	// without sleeping.
	now func() time.Time
}

// New returns a Store rooted at dir. deviceSecret is this installation's local
// secret (device.Config.LocalSecret); the counter is MAC'd under it.
func New(dir string, deviceSecret []byte) *Store {
	return &Store{dir: dir, secret: deviceSecret, now: time.Now}
}

func (s *Store) path() string { return filepath.Join(s.dir, FileName) }

// Outcome reports what a recorded failure produced.
type Outcome struct {
	// AttemptsLeft before the wipe fires, or -1 when the wipe policy is disabled.
	AttemptsLeft int
	// RetryAfter is the backoff window this failure opened (0 if none yet).
	RetryAfter time.Duration
	// Wipe is true when this failure reached the wipe threshold: the caller must
	// erase the account.
	Wipe bool
}

// Status is a snapshot for the UI and settings screen.
type Status struct {
	WipeEnabled   bool
	WipeThreshold int
	Attempts      int
	AttemptsLeft  int // -1 when the wipe policy is disabled
	RetryAfter    time.Duration
}

// Backoff returns the outstanding backoff delay (0 if none). Callers use it to
// refuse an attempt during the window WITHOUT running the expensive password
// derivation, which is what makes the backoff a real rate limit rather than a
// delay in front of an attempt that still executes.
func (s *Store) Backoff() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, _ := s.load()
	return s.backoffLocked(st)
}

// RecordFailure increments the persisted counter and reports whether the wipe
// threshold was reached. Callers invoke it only for a genuine wrong password —
// not for a backoff refusal (the window already governs) and not for a duress
// code (which triggers its own path and must never advance this counter).
func (s *Store) RecordFailure() (Outcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, _ := s.load()
	st.Attempts++
	st.LastAttempt = s.now()

	out := Outcome{AttemptsLeft: -1, RetryAfter: s.backoffLocked(st)}
	if st.WipeEnabled {
		left := st.WipeThreshold - st.Attempts
		if left < 0 {
			left = 0
		}
		out.AttemptsLeft = left
		out.Wipe = st.Attempts >= st.WipeThreshold
	}
	// Persist even when Wipe fired: the caller wipes the whole directory next
	// (removing this file), but a crash between here and there must not hand back
	// the spent attempts.
	if err := s.write(st); err != nil {
		return out, err
	}
	return out, nil
}

// RecordSuccess clears the failure counter after a correct password. It never
// creates the file when there was nothing to clear, so a device that has never
// had a failed unlock keeps a fresh-install-clean data directory.
func (s *Store) RecordSuccess() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, existed := s.load()
	if st.Attempts == 0 {
		return nil
	}
	st.Attempts = 0
	st.LastAttempt = time.Time{}
	// If the counter was the only reason the file existed, drop it rather than
	// leave an all-default file behind.
	if !st.WipeEnabled {
		if existed {
			return s.remove()
		}
		return nil
	}
	return s.write(st)
}

// SetWipePolicy turns the erase-after-N policy on or off. Turning it fully off
// on a device with no outstanding failures removes the file, so the setting
// leaves no residue when it is not in use.
func (s *Store) SetWipePolicy(enabled bool, threshold int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if enabled && threshold < MinWipeThreshold {
		return ErrThresholdTooLow
	}
	st, existed := s.load()
	st.WipeEnabled = enabled
	if enabled {
		st.WipeThreshold = threshold
	}
	if !st.WipeEnabled && st.Attempts == 0 {
		if existed {
			return s.remove()
		}
		return nil
	}
	return s.write(st)
}

// Status reports the current policy and counter for the UI.
func (s *Store) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, _ := s.load()
	left := -1
	if st.WipeEnabled {
		if left = st.WipeThreshold - st.Attempts; left < 0 {
			left = 0
		}
	}
	return Status{
		WipeEnabled:   st.WipeEnabled,
		WipeThreshold: st.WipeThreshold,
		Attempts:      st.Attempts,
		AttemptsLeft:  left,
		RetryAfter:    s.backoffLocked(st),
	}
}

// backoffLocked mirrors the PIN shortcut's schedule exactly, so the two unlock
// paths feel the same: the first two wrong entries are free (fat fingers), then
// the wait doubles each time up to maxBackoff. Measured against the persisted
// timestamp, so a restart does not clear it; a clock rolled backwards can skip
// the wait, but the wipe threshold still holds, which is the limit that matters.
func (s *Store) backoffLocked(st *state) time.Duration {
	if st.Attempts < 3 {
		return 0
	}
	wait := time.Duration(1<<(st.Attempts-2)) * time.Second
	if wait > maxBackoff {
		wait = maxBackoff
	}
	elapsed := s.now().Sub(st.LastAttempt)
	if elapsed < 0 || elapsed >= wait {
		return 0
	}
	return wait - elapsed
}

// load reads the state, returning a clean default when the file is absent or
// fails authentication.
func (s *Store) load() (st *state, existed bool) {
	data, err := os.ReadFile(s.path())
	if err != nil {
		return s.defaultState(), false
	}
	var got state
	if err := json.Unmarshal(data, &got); err != nil || got.Version != version {
		return s.defaultState(), false
	}
	mac, err := base64.StdEncoding.DecodeString(got.MAC)
	if err != nil || !hmac.Equal(mac, s.mac(&got)) {
		// Tampered, truncated, or copied from another device. Fail SAFE: never
		// erase on a policy we cannot authenticate, and treat the counter as a
		// clean slate. This does mean anyone who can WRITE the data directory can
		// zero the backoff by corrupting the file — but that same write access
		// already permits copying identity.enc for an offline attack and deleting
		// everything outright, so it is not a new capability. What the MAC
		// actually prevents is a casual text-editor reset or a flipped wipe flag.
		return s.defaultState(), true
	}
	return &got, true
}

func (s *Store) defaultState() *state {
	return &state{Version: version, WipeThreshold: DefaultWipeThreshold}
}

// mac authenticates the counter and policy under a key derived from the device
// secret. MAC itself is excluded from the input.
func (s *Store) mac(st *state) []byte {
	m := hmac.New(sha256.New, s.macKey())
	fmt.Fprintf(m, "tormsg-unlock-guard-v%d|%d|%d|%t|%d",
		version, st.Attempts, st.LastAttempt.UnixNano(), st.WipeEnabled, st.WipeThreshold)
	return m.Sum(nil)
}

func (s *Store) macKey() []byte {
	out := make([]byte, 32)
	r := hkdf.New(sha256.New, s.secret, nil, []byte("onion-chat/v1 unlock guard mac"))
	_, _ = io.ReadFull(r, out)
	return out
}

func (s *Store) write(st *state) error {
	st.Version = version
	st.MAC = base64.StdEncoding.EncodeToString(s.mac(st))
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal unlock guard: %w", err)
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	return atomicWrite(s.path(), data, 0o600)
}

func (s *Store) remove() error {
	if err := wipe.File(s.path()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func atomicWrite(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".guard-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	return os.Rename(tmpName, path)
}
