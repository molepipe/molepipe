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
	last := time.Unix(0, v.lastActivity.Load())
	if now.Sub(last) > maxSessionIdle || now.Sub(v.createdAt) > maxSessionDuration {
		// Session expired — zero and lock in the background. We hold a read
		// lock so we can't call zeroLocked (which needs write). Schedule it.
		go v.lock()
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
