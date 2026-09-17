package api

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

const (
	// avatarServeRate/Burst bound the ungated AvatarPath. A face is a few KB and
	// content-addressed (clients cache by hash forever), so legitimate traffic is
	// one fetch per new avatar per contact — tiny. The bucket exists to blunt an
	// anonymous flood on Tor, not to shape real use, so it's generous.
	avatarServeRate   = 20       // tokens per second refill
	avatarServeBurst  = 40       // max burst
	avatarCacheMaxAge = 31536000 // 1 year; safe because the URL is content-addressed by hash
)

// tokenBucket is a minimal global rate limiter: allow() consumes one token,
// refilling at rate tokens/sec up to burst. Cheap and lock-guarded; there is one
// per Server for the ungated avatar endpoint.
type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	rate   float64
	burst  float64
	last   time.Time
}

func newTokenBucket(rate, burst float64) *tokenBucket {
	return &tokenBucket{tokens: burst, rate: rate, burst: burst, last: time.Now()}
}

func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// avatarContentType detects the image content type from the bytes themselves
// (never a client-declared string) and returns it only if it is in the same
// allowlist attachments use. Deriving it from the bytes means the ungated
// endpoint can send an accurate Content-Type with nosniff and never echo an
// attacker-chosen type.
func avatarContentType(data []byte) (string, bool) {
	mime := http.DetectContentType(data) // sniffs magic bytes; never returns params for these
	if !protocol.AllowedImageMIME(mime) {
		return "", false
	}
	return mime, true
}

// serveAvatarBytes writes an avatar's bytes with the detected image content type,
// nosniff, and a long immutable cache (the URL is content-addressed by hash).
func serveAvatarBytes(w http.ResponseWriter, data []byte) {
	mime, ok := avatarContentType(data)
	if !ok {
		http.Error(w, "unsupported", http.StatusUnsupportedMediaType)
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(avatarCacheMaxAge)+", immutable")
	_, _ = w.Write(data)
}

// handleP2PAvatar is the UNGATED avatar-bytes endpoint dialed over Tor by anyone
// who holds the hash (which they got from the signed profile card). It is meant
// to be reachable before friendship, so a stranger can preview a face at add
// time — the deliberate privacy trade decided with the user.
//
// It serves ONLY our OWN avatar (hash == s.avatarHash), never an arbitrary hash
// in the store. The store also caches CONTACTS' avatars (fetched during presence
// sweeps and lookups); serving those by hash would turn this into a social-graph
// oracle — a stranger holding Alice's public avatar hash could learn from 200-vs-
// 404 whether we have Alice as a contact. Restricting to our own hash closes
// that: every legitimate caller reached us via a card that advertised exactly
// this hash, so the check never rejects a real request (a second device fetching
// its own face included). Globally rate-limited.
func (s *Server) handleP2PAvatar(w http.ResponseWriter, r *http.Request) {
	if s.avatarLimiter != nil && !s.avatarLimiter.allow() {
		http.Error(w, "slow down", http.StatusTooManyRequests)
		return
	}
	s.sessMu.Lock()
	store, mine := s.avatarStore, s.avatarHash
	s.sessMu.Unlock()
	if store == nil { // locked
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	hash := r.URL.Query().Get("h")
	if hash == "" || hash != mine {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	data, err := store.Get(hash)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	serveAvatarBytes(w, data)
}

// handleGetAvatar serves an avatar's bytes to the LOCAL first-party UI (auth'd via
// the control token) from this device's cache — our own avatar and any contact
// avatars fetched during a presence sweep or an add-time lookup. It NEVER dials a
// peer: a UI render must resolve strictly from the by-hash cache (initials
// fallback otherwise), so painting the conversation list can't trigger Tor.
func (s *Server) handleGetAvatar(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	s.sessMu.Lock()
	store := s.avatarStore
	s.sessMu.Unlock()
	if store == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	hash := r.URL.Query().Get("h")
	data, err := store.Get(hash)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	serveAvatarBytes(w, data)
}

// GetAvatarBytes returns the decrypted avatar image for the given content hash
// from the local cache, or nil if not found. Used by the notification pipeline
// to attach the sender's profile picture to system notifications.
func (s *Server) GetAvatarBytes(hash string) []byte {
	if hash == "" {
		return nil
	}
	s.sessMu.Lock()
	store := s.avatarStore
	s.sessMu.Unlock()
	if store == nil {
		return nil
	}
	data, err := store.Get(hash)
	if err != nil {
		return nil
	}
	return data
}
