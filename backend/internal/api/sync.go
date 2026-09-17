package api

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// The sync endpoints live on the onion-facing pubMux, so a secondary device
// dialing the account onion (which reaches the primary) can sync. They are gated
// by protocol.SyncVerify: the caller must prove both the account identity key
// AND an enrolled device key. This is the single most sensitive surface in the
// phase — it returns the entire message history — so the gate runs before any
// data is touched, and unenrolled callers are rejected even with a valid
// identity signature.

const (
	syncNonceLen = 32
	syncNonceTTL = 5 * time.Minute
	// maxSyncBody caps a sync upload. It must be read in full before the caller
	// can be authenticated (the nonce and signatures are in the body), so it is
	// the amplification lever an unauthenticated peer on Tor can pull. 8 MiB of
	// chatstore JSON is a very large history (thousands of messages); the cap
	// bounds a single request while the listener's concurrency limit bounds the
	// aggregate. Was 32 MiB, which let 8 anonymous requests pin ~600 MiB.
	maxSyncBody = 8 << 20
	// maxSyncNonces caps the live nonce jar, exactly as protocol.maxNonces caps
	// the peer-messaging one. /sync/challenge and /pair/challenge are BOTH
	// unauthenticated and reachable by anyone on Tor (and, on Android, by any
	// co-installed app on 127.0.0.1 with no Tor latency at all), and each call
	// stores a nonce for syncNonceTTL. pruneLocked only drops EXPIRED entries, so
	// without a ceiling a sustained flood grows the jar to (rate x TTL) — an
	// uncapped memory-exhaustion vector, made worse by pruneLocked being O(N)
	// under the shared mutex that legitimate /sync and /pair/enroll also need. At
	// the cap we evict the oldest outstanding nonce, so a legitimate peer's fresh
	// challenge always succeeds (an attacker's stale nonces are what get dropped;
	// a peer whose nonce was evicted mid-handshake simply re-fetches).
	maxSyncNonces = 4096
)

func (s *Server) handleSyncChallenge(w http.ResponseWriter, r *http.Request) {
	if s.currentPeer() == nil { // locked: nothing to sync
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string][]byte{"nonce": s.syncNonces.issue()})
}

func (s *Server) handleSyncExchange(w http.ResponseWriter, r *http.Request) {
	if s.currentPeer() == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		DevicePub []byte          `json:"device_pub"`
		Nonce     []byte          `json:"nonce"`
		IDSig     []byte          `json:"id_sig"`
		DeviceSig []byte          `json:"device_sig"`
		State     json.RawMessage `json:"state"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSyncBody)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Consume the nonce (single-use) and verify BOTH signatures + enrollment
	// before touching any state.
	if !s.syncNonces.consume(req.Nonce) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.sessMu.Lock()
	account := s.myAccount
	s.sessMu.Unlock()
	if err := protocol.SyncVerify(account, req.Nonce, req.DevicePub, req.IDSig, req.DeviceSig, s.isEnrolledDevice); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var incoming chatstore.Data
	if err := json.Unmarshal(req.State, &incoming); err != nil {
		http.Error(w, "bad state", http.StatusBadRequest)
		return
	}

	// Merge the caller's state into ours, adopt the result, and return it so the
	// caller converges too.
	s.sessMu.Lock()
	merged := chatstore.Merge(s.snapshotLocked(), &incoming)
	s.adoptDataLocked(merged)
	s.sweepOrphanAttachmentsLocked() // reclaim blobs orphaned by a tombstone this merge adopted
	s.sweepOrphanAvatarsLocked()     // reclaim avatars orphaned by a profile picture change this merge adopted
	s.persistLocked()
	s.sessMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"state": merged})
}

// isEnrolledDevice reports whether a device pubkey is in the linked-devices list.
func (s *Server) isEnrolledDevice(pub []byte) bool {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	for _, d := range s.devices {
		if bytes.Equal(d.PubKey, pub) {
			return true
		}
	}
	return false
}

// --- sync nonce jar ---

type syncNonceJar struct {
	mu     sync.Mutex
	nonces map[string]time.Time
}

func newSyncNonceJar() *syncNonceJar { return &syncNonceJar{nonces: map[string]time.Time{}} }

func (j *syncNonceJar) issue() []byte {
	n := make([]byte, syncNonceLen)
	_, _ = rand.Read(n)
	j.mu.Lock()
	j.pruneLocked()
	j.evictOldestLocked()
	j.nonces[string(n)] = time.Now().Add(syncNonceTTL)
	j.mu.Unlock()
	return n
}

func (j *syncNonceJar) consume(n []byte) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.pruneLocked()
	exp, ok := j.nonces[string(n)]
	if !ok || time.Now().After(exp) {
		return false
	}
	delete(j.nonces, string(n))
	return true
}

func (j *syncNonceJar) pruneLocked() {
	now := time.Now()
	for n, exp := range j.nonces {
		if now.After(exp) {
			delete(j.nonces, n)
		}
	}
}

// evictOldestLocked keeps the jar within maxSyncNonces by dropping the
// soonest-to-expire (i.e. oldest-issued, since every nonce shares syncNonceTTL)
// entries until there is room for one more. Normally a no-op; it only bites
// under a challenge flood, where it bounds the jar's memory to ~maxSyncNonces.
// Mirrors protocol.Peer.evictOldestLocked.
func (j *syncNonceJar) evictOldestLocked() {
	for len(j.nonces) >= maxSyncNonces {
		var oldestKey string
		var oldestExp time.Time
		first := true
		for n, exp := range j.nonces {
			if first || exp.Before(oldestExp) {
				oldestKey, oldestExp, first = n, exp, false
			}
		}
		delete(j.nonces, oldestKey)
	}
}
