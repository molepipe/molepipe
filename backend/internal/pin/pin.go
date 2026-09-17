// Package pin implements device-bound PIN unlock: a local shortcut that
// re-opens an identity on THIS device without re-typing the full password.
//
// The core rule is that the PIN never becomes the thing protecting identity.enc
// at rest. That file stays password-only, always. What the PIN protects is a
// second, device-local copy of the session material (pin.enc), created only
// after the user proved they know the real password. Stealing identity.enc — a
// leaked backup, a copy pulled off a machine — therefore never yields anything
// a short PIN would help brute-force.
//
// Two layers, per the design doc: a random 32-byte device key encrypts the
// session material, and the PIN (via Argon2id) encrypts the device key. The
// indirection is what makes the attempt-cap wipe cheap (destroy the wrapped key
// and the session copy is unreachable) and leaves room to move the device key
// into an OS keychain or TPM later without touching the outer format.
//
// Honest scoping of what "device-bound" buys on desktop: both pin.enc and the
// device secret it is bound to (device.json) live in the data dir, so an
// attacker who copies the WHOLE directory can mount an offline attack on the
// PIN, and no rate limit can stop them — that is why the Argon2id cost here is
// deliberately higher than the identity file's. Binding to the device secret
// still means pin.enc alone is useless, and identity.enc alone is untouched by
// any of this. Real hardware binding needs an OS keychain/TPM and is not
// something a pure-Go, gomobile-portable core can claim today.
package pin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/molepipe/molepipe/backend/internal/wipe"

	"github.com/molepipe/molepipe/backend/internal/crypto"
)

const (
	blobVersion = 1
	fileName    = "pin.enc"

	// MinLength is the shortest accepted PIN. Six is the floor at which the
	// Argon2id cost below makes an offline sweep of the whole keyspace
	// expensive rather than trivial.
	MinLength = 6

	// MaxAttempts is the hard cap on consecutive wrong PINs. The MaxAttempts'th
	// wipes the shortcut (never the identity) and the device falls back to
	// requiring the full password. Kept deliberately low: a PIN is a short
	// secret, so a small budget limits an on-device guessing attempt while
	// still tolerating a few genuine fat-fingers.
	MaxAttempts = 8

	// maxBackoff caps the escalating delay so a genuine owner who fat-fingers
	// the PIN a few times isn't locked out for an unbounded stretch.
	maxBackoff = 5 * time.Minute
)

// Errors returned by Unlock and Enable. Callers must not report ErrBadPIN and
// ErrNotEnabled differently to a remote party — but locally, on this device,
// telling the user which one happened is the whole point of the feature.
var (
	// ErrNotEnabled means no PIN shortcut exists on this device.
	ErrNotEnabled = errors.New("pin unlock is not set up on this device")
	// ErrBadPIN means the PIN did not decrypt the device key.
	ErrBadPIN = errors.New("incorrect pin")
	// ErrWiped means this attempt was the last one: the shortcut has just been
	// destroyed and the full password is now required.
	ErrWiped = errors.New("too many incorrect attempts — pin unlock disabled, use your password")
	// ErrTooShort means the requested PIN is below MinLength.
	ErrTooShort = fmt.Errorf("pin must be at least %d characters", MinLength)
)

// ThrottleError is returned while the caller is inside the backoff window after
// a wrong PIN. RetryAfter is how long is left to wait.
type ThrottleError struct{ RetryAfter time.Duration }

func (e *ThrottleError) Error() string {
	return fmt.Sprintf("too many attempts — try again in %s", e.RetryAfter.Round(time.Second))
}

// Argon2Params for the PIN layer. Memory stays at 64 MiB to remain safe on
// phones (same constraint as the identity file), but the time cost is raised:
// this derivation runs once on an explicit unlock, so ~half a second of user
// wait buys a proportional increase in the cost of the offline attack that a
// whole-directory theft would enable.
func Argon2Params() crypto.Argon2Params {
	p := crypto.DefaultArgon2Params()
	p.TimeCost = 8
	return p
}

// blob is the on-disk pin.enc. Everything here is local, non-secret metadata
// except the two ciphertexts. Attempts/LastAttempt are the persisted rate-limit
// state — persisted precisely so that killing and restarting the app does not
// hand an attacker a fresh set of guesses.
type blob struct {
	Version    int                 `json:"version"`
	KDF        string              `json:"kdf"`
	Argon2     crypto.Argon2Params `json:"argon2"`
	Salt       string              `json:"salt"`        // base64, for the PIN->wrap key derivation
	WrapNonce  string              `json:"wrap_nonce"`  // base64
	WrappedKey string              `json:"wrapped_key"` // base64, device key sealed under the PIN
	Nonce      string              `json:"nonce"`       // base64
	Ciphertext string              `json:"ciphertext"`  // base64, session material sealed under the device key

	Attempts    int       `json:"attempts"`
	LastAttempt time.Time `json:"last_attempt"`
	// CounterMAC authenticates Attempts/LastAttempt under the device secret.
	// It stops the counter being reset with a text editor. It does NOT stop
	// someone who copied the whole data dir (they have the device secret too,
	// and can restore an older pin.enc anyway) — defeating that needs hardware
	// we don't have. Documented rather than overclaimed.
	CounterMAC string `json:"counter_mac"` // base64
}

// sessionMaterial is what the device key protects: exactly what identity.enc's
// own ciphertext holds, so a PIN unlock reconstructs the identical Identity.
type sessionMaterial struct {
	Mnemonic   string `json:"mnemonic"`
	Passphrase string `json:"passphrase"`
}

// Store is the PIN shortcut for one data directory, bound to that device's
// local secret.
type Store struct {
	Dir    string
	secret []byte

	// mu serializes every operation that touches the blob. Without it, ten
	// concurrent wrong-PIN attempts would each read attempts=0 and each write
	// attempts=1 — a lost-update race that turns the hard cap into no cap at
	// all. Serializing also means the Argon2id cost is paid one attempt at a
	// time, so parallelism buys an attacker nothing.
	mu sync.Mutex

	// now is the clock, swappable in tests to exercise the backoff schedule
	// without sleeping.
	now func() time.Time
	// params is the Argon2id cost for new blobs. Existing blobs always use the
	// parameters recorded in the file. Tests lower it; nothing else should.
	params crypto.Argon2Params
}

// Status is a snapshot for the UI: whether the shortcut exists, how many tries
// remain before it self-destructs, and whether a backoff window is open.
type Status struct {
	Enabled      bool
	AttemptsLeft int
	RetryAfter   time.Duration
}

// New returns a Store rooted at dir. deviceSecret is this installation's local
// secret (see device.Config.LocalSecret); the PIN blob is bound to it, so the
// blob is inert on any machine that lacks it.
func New(dir string, deviceSecret []byte) *Store {
	return &Store{Dir: dir, secret: deviceSecret, now: time.Now, params: Argon2Params()}
}

// Path is the full path to the PIN blob.
func (s *Store) Path() string { return filepath.Join(s.Dir, fileName) }

// Exists reports whether a PIN shortcut is set up on this device.
func (s *Store) Exists() bool {
	_, err := os.Stat(s.Path())
	return err == nil
}

// Enable creates (or replaces) the PIN shortcut. The caller must already have
// authenticated with the full password — this function does not and cannot
// verify that, so it is the HTTP layer's job to require it.
func (s *Store) Enable(code []byte, mnemonic, passphrase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(code) < MinLength {
		return ErrTooShort
	}
	params := s.params
	salt, err := crypto.NewSalt(params)
	if err != nil {
		return err
	}

	deviceKey := make([]byte, 32)
	if _, err := rand.Read(deviceKey); err != nil {
		return fmt.Errorf("generate device key: %w", err)
	}
	defer zero(deviceKey)

	wrapKey := s.wrapKey(code, salt, params)
	defer zero(wrapKey)

	wrapNonce, wrappedKey, err := crypto.Seal(wrapKey, deviceKey, wrapAAD())
	if err != nil {
		return err
	}

	plaintext, err := json.Marshal(sessionMaterial{Mnemonic: mnemonic, Passphrase: passphrase})
	if err != nil {
		return fmt.Errorf("marshal session material: %w", err)
	}
	defer zero(plaintext)
	nonce, ciphertext, err := crypto.Seal(deviceKey, plaintext, sessionAAD())
	if err != nil {
		return err
	}

	b := &blob{
		Version:    blobVersion,
		KDF:        "argon2id",
		Argon2:     params,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		WrapNonce:  base64.StdEncoding.EncodeToString(wrapNonce),
		WrappedKey: base64.StdEncoding.EncodeToString(wrappedKey),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	return s.write(b)
}

// Unlock recovers the session material with the PIN. It enforces the escalating
// backoff and the hard attempt cap, and returns ErrWiped on the attempt that
// destroys the shortcut.
func (s *Store) Unlock(code []byte) (mnemonic, passphrase string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := s.read()
	if err != nil {
		return "", "", err
	}
	if wait := s.backoff(b); wait > 0 {
		return "", "", &ThrottleError{RetryAfter: wait}
	}

	salt, err := base64.StdEncoding.DecodeString(b.Salt)
	if err != nil {
		return "", "", fmt.Errorf("decode salt: %w", err)
	}
	wrapNonce, err := base64.StdEncoding.DecodeString(b.WrapNonce)
	if err != nil {
		return "", "", fmt.Errorf("decode wrap nonce: %w", err)
	}
	wrappedKey, err := base64.StdEncoding.DecodeString(b.WrappedKey)
	if err != nil {
		return "", "", fmt.Errorf("decode wrapped key: %w", err)
	}

	wrapKey := s.wrapKey(code, salt, b.Argon2)
	defer zero(wrapKey)

	deviceKey, err := crypto.Open(wrapKey, wrapNonce, wrappedKey, wrapAAD())
	if err != nil {
		return "", "", s.recordFailure(b)
	}
	defer zero(deviceKey)

	nonce, err := base64.StdEncoding.DecodeString(b.Nonce)
	if err != nil {
		return "", "", fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(b.Ciphertext)
	if err != nil {
		return "", "", fmt.Errorf("decode ciphertext: %w", err)
	}
	plaintext, err := crypto.Open(deviceKey, nonce, ciphertext, sessionAAD())
	if err != nil {
		// The device key decrypted but the inner blob didn't: corruption, not a
		// wrong PIN. Don't burn an attempt for it.
		return "", "", fmt.Errorf("pin blob is corrupt: %w", err)
	}
	defer zero(plaintext)

	var sm sessionMaterial
	if err := json.Unmarshal(plaintext, &sm); err != nil {
		return "", "", fmt.Errorf("parse session material: %w", err)
	}

	// Correct PIN: clear the failure counter.
	if b.Attempts != 0 {
		b.Attempts = 0
		b.LastAttempt = time.Time{}
		if err := s.write(b); err != nil {
			return "", "", err
		}
	}
	return sm.Mnemonic, sm.Passphrase, nil
}

// Matches reports whether code opens the shortcut, WITHOUT touching the attempt
// counter or the backoff. It exists for one caller: refusing a duress code that
// is identical to the PIN. Such a code would never fire — the PIN is tried
// first at the same prompt and succeeds — leaving the user believing they have
// a panic code that in fact does nothing.
func (s *Store) Matches(code []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.read()
	if err != nil {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(b.Salt)
	if err != nil {
		return false
	}
	wrapNonce, err := base64.StdEncoding.DecodeString(b.WrapNonce)
	if err != nil {
		return false
	}
	wrappedKey, err := base64.StdEncoding.DecodeString(b.WrappedKey)
	if err != nil {
		return false
	}
	wrapKey := s.wrapKey(code, salt, b.Argon2)
	defer zero(wrapKey)
	deviceKey, err := crypto.Open(wrapKey, wrapNonce, wrappedKey, wrapAAD())
	if err != nil {
		return false
	}
	zero(deviceKey)
	return true
}

// Disable removes the PIN shortcut. The identity itself is untouched.
func (s *Store) Disable() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := wipe.File(s.Path()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Status reports what the unlock screen needs to know.
func (s *Store) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := s.read()
	if err != nil {
		return Status{}
	}
	return Status{
		Enabled:      true,
		AttemptsLeft: MaxAttempts - b.Attempts,
		RetryAfter:   s.backoff(b),
	}
}

// recordFailure increments the persisted counter and, on the cap, wipes the
// shortcut. It always returns the error the caller should surface.
func (s *Store) recordFailure(b *blob) error {
	b.Attempts++
	b.LastAttempt = s.now()
	if b.Attempts >= MaxAttempts {
		if err := wipe.File(s.Path()); err != nil && !os.IsNotExist(err) {
			return err
		}
		return ErrWiped
	}
	if err := s.write(b); err != nil {
		return err
	}
	return ErrBadPIN
}

// backoff is how much of the escalating delay is still outstanding. The first
// two wrong entries are free (fat fingers), then the wait doubles each time up
// to maxBackoff. It is measured against the persisted timestamp, so a restart
// does not clear it; a clock rolled backwards can skip the wait, but the hard
// attempt cap still holds, which is the limit that actually matters.
func (s *Store) backoff(b *blob) time.Duration {
	if b.Attempts < 3 {
		return 0
	}
	wait := time.Duration(1<<(b.Attempts-2)) * time.Second
	if wait > maxBackoff {
		wait = maxBackoff
	}
	elapsed := s.now().Sub(b.LastAttempt)
	if elapsed < 0 || elapsed >= wait {
		return 0
	}
	return wait - elapsed
}

// wrapKey stretches the PIN with Argon2id and then binds the result to this
// device's local secret. Without that secret, a stolen pin.enc cannot even
// begin the brute-force.
func (s *Store) wrapKey(code, salt []byte, p crypto.Argon2Params) []byte {
	stretched := crypto.DeriveKeyArgon2id(code, salt, p)
	defer zero(stretched)
	out := make([]byte, 32)
	r := hkdf.New(sha256.New, stretched, s.secret, []byte("onion-chat/v1 pin wrap key"))
	if _, err := io.ReadFull(r, out); err != nil {
		// HKDF over a fixed-size read cannot fail in practice; a panic here
		// would be worse than returning an unusable key that fails GCM auth.
		return out
	}
	return out
}

func (s *Store) counterMAC(b *blob) []byte {
	m := hmac.New(sha256.New, s.macKey())
	// Use a deterministic format that is independent of Go's fmt implementation.
	// The format is: "tormsg-pin-counter-v" + version + "|" + attempts + "|" + nanos
	// This avoids fmt.Fprintf which could theoretically change across Go versions.
	fmt.Fprintf(m, "tormsg-pin-counter-v%d|%d|%d", blobVersion, b.Attempts, b.LastAttempt.UnixNano())
	return m.Sum(nil)
}

func (s *Store) macKey() []byte {
	out := make([]byte, 32)
	r := hkdf.New(sha256.New, s.secret, nil, []byte("onion-chat/v1 pin counter mac"))
	_, _ = io.ReadFull(r, out)
	return out
}

func (s *Store) write(b *blob) error {
	b.CounterMAC = base64.StdEncoding.EncodeToString(s.counterMAC(b))
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal pin blob: %w", err)
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	return atomicWrite(s.Path(), data, 0o600)
}

func (s *Store) read() (*blob, error) {
	data, err := os.ReadFile(s.Path())
	if os.IsNotExist(err) {
		return nil, ErrNotEnabled
	}
	if err != nil {
		return nil, fmt.Errorf("read pin blob: %w", err)
	}
	var b blob
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse pin blob: %w", err)
	}
	if b.Version != blobVersion {
		return nil, fmt.Errorf("unsupported pin blob version %d", b.Version)
	}
	mac, err := base64.StdEncoding.DecodeString(b.CounterMAC)
	if err != nil || !hmac.Equal(mac, s.counterMAC(&b)) {
		// A counter that doesn't authenticate means the file was edited or came
		// from another device. Treat the shortcut as spent rather than trusting
		// an attacker-chosen attempt count.
		return nil, ErrNotEnabled
	}
	return &b, nil
}

func atomicWrite(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pin-*.tmp")
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

func zero(b []byte) {
	crypto.Zero(b)
}

// wrapAAD and sessionAAD keep the two encryption layers domain-separated, so a
// ciphertext from one can never be replayed into the other.
func wrapAAD() []byte    { return []byte(fmt.Sprintf("tormsg-pin-wrap-v%d", blobVersion)) }
func sessionAAD() []byte { return []byte(fmt.Sprintf("tormsg-pin-session-v%d", blobVersion)) }
