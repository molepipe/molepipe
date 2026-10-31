package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"sync/atomic"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

const (
	// maxSessionIdle is the maximum time a session can be idle before it is
	// automatically locked. On mobile this prevents a leaked token from giving
	// permanent access if the user walks away.
	maxSessionIdle = 30 * time.Minute
	// maxSessionDuration is the absolute maximum time a session can remain
	// unlocked, regardless of activity. Forces re-authentication periodically.
	maxSessionDuration = 12 * time.Hour
)

// vault holds the single unlocked identity in memory for a single-user local
// app. It is guarded by a mutex because concurrent HTTP handlers touch it.
// There is exactly one session at a time — unlocking again replaces it.
type vault struct {
	mu           sync.RWMutex
	token        string
	id           *identity.Identity
	lastActivity atomic.Int64 // UnixNano of last activity, updated atomically
	createdAt    time.Time
	// gen identifies the current session. Bumped by every unlock, so a teardown
	// queued for an earlier session can tell that it is no longer the session in
	// the vault and leave the new one alone. Guarded by mu like the fields above.
	gen uint64

	// onExpire is the full teardown to run when a session times out — the
	// server installs its LockNow here. Set once in New, before the server is
	// serving and before any goroutine can reach get(), so it needs no
	// locking. Nil in a vault built on its own (tests), which falls back to
	// zeroing the identity and nothing else; see expire.
	onExpire func()
}

func newVault() *vault { return &vault{} }

// unlock stores the identity and returns a fresh random session token. Any
// previous session is replaced (and its keys zeroed).
func (v *vault) unlock(id *identity.Identity) (string, error) {
	tok, err := newToken()
	if err != nil {
		return "", err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.zeroLocked()
	v.token = tok
	v.id = id
	v.gen++
	now := time.Now()
	v.lastActivity.Store(now.UnixNano())
	v.createdAt = now
	return tok, nil
}

// get returns the unlocked identity if token matches the current session and the
// session has not expired. The comparison is constant-time to avoid leaking the
// token via timing.
func (v *vault) get(token string) (*identity.Identity, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.id == nil || token == "" {
		return nil, false
	}
	// Check session expiry: idle timeout or absolute duration.
	now := time.Now()
	if v.expiredLocked(now) {
		// Session expired. Take the whole lock path, the same one the Log out
		// button takes — not just a zeroing of the identity here. Zeroing alone
		// left the onion service published and the session loops and publish
		// watchdog running against an empty vault, and because it armed no
		// lock-grace the next unlock also tore that still-published service
		// down and rebuilt the identical descriptor. The 10/19 run log shows
		// both halves of that: a service still serving 41 hours after its
		// session ended (so StopService's keystore wipe, which exists so the
		// onion key does not outlive the session, had never run), and the
		// unlock that then spent 25s republishing it.
		//
		// In the background because we hold a read lock here and that path
		// needs the write lock. It is handed this session's generation so that
		// it can tell, when it finally gets scheduled, whether it is still the
		// session it was asked to tear down — see expire.
		go v.expire(v.gen)
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(v.token)) != 1 {
		return nil, false
	}
	// Update lastActivity atomically — no lock upgrade needed.
	v.lastActivity.Store(now.UnixNano())
	return v.id, true
}

// unlocked reports whether any identity is currently unlocked.
func (v *vault) unlocked() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.id != nil
}

// lock clears the session and zeroes the in-memory private keys.
func (v *vault) lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.zeroLocked()
}

// expire tears down a session that timed out, via the server's full lock path
// when one is installed (see onExpire). The bare lock() is the fallback for a
// vault constructed without a server around it, which only happens in tests.
//
// gen is the session get() observed expiring. This runs in its own goroutine,
// and on a throttled mobile process it can be a long time between get() seeing
// the expiry and this being scheduled — easily long enough for the user to
// unlock again, which is exactly what happens when a phone that has been idle
// for half an hour wakes up: a background poll notices the expiry and the user
// enters their PIN seconds later. Without this check the queued teardown would
// then hit the fresh session, and because it is the full lock path it would
// zeroize the identity that session is already using, not merely log the user
// out.
//
// The two checks below are redundant today: unlock resets lastActivity and
// createdAt as well as gen, so a fresh session fails both, and either alone
// closes the race. The expiry re-check is the one that bounds the damage — a
// live session is never expired, so its keys are never zeroized. The
// generation makes the intent explicit (end only the session you observed
// expiring) and keeps the guard correct if a future change ever re-arms a
// session's timers without going through unlock. Deleting either half is safe
// today but leaves no second line.
//
// Not watertight: unlock can still land in the few microseconds of
// straight-line code between the check and the teardown. Closing that needs
// unlock and the lock path to be mutually exclusive, which is a wider change
// than this one, and the same window already exists between unlock and the
// Lock button.
//
// The check also collapses the several goroutines that concurrent requests can
// start for one expiry: the first one's vault.lock() clears v.id, so the rest
// fall out here instead of each running a full teardown.
func (v *vault) expire(gen uint64) {
	if !v.stillExpired(gen) {
		return
	}
	if v.onExpire != nil {
		v.onExpire()
		return
	}
	v.lock()
}

// stillExpired reports whether generation gen is still the session in the vault
// and is still timed out. Taken under the read lock, so what it returns is a
// snapshot — see the window expire documents.
func (v *vault) stillExpired(gen uint64) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.id != nil && v.gen == gen && v.expiredLocked(time.Now())
}

// expiredLocked reports whether the current session has timed out, by idle
// timeout or absolute duration. Caller must hold at least the read lock.
func (v *vault) expiredLocked(now time.Time) bool {
	if v.id == nil {
		return false
	}
	last := time.Unix(0, v.lastActivity.Load())
	return now.Sub(last) > maxSessionIdle || now.Sub(v.createdAt) > maxSessionDuration
}

// zeroLocked wipes all sensitive material from the identity and session.
// Caller must hold the write lock. After this call the vault is locked and
// the identity must not be used.
func (v *vault) zeroLocked() {
	if v.id != nil {
		v.id.Zeroize()
		v.id = nil
	}
	v.token = ""
	v.lastActivity.Store(0)
	v.createdAt = time.Time{}
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
