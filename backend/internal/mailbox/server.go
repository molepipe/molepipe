package mailbox

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

const (
	nonceLen     = 32
	nonceTTL     = 5 * time.Minute
	maxBodyBytes = 64 << 10 // authed checkin/pickup/delete/forget: small bodies
	// maxDropCeiling hard-bounds a drop-off body even when the operator's config
	// allows an unlimited per-blob size, so an unauthenticated drop-off can never
	// send an arbitrarily huge body before its signature is checked. It comfortably
	// covers a maximum image envelope (a 3 MiB image, base64'd inside the sealed
	// payload and again as the envelope's Box, is ~5.5 MiB).
	maxDropCeiling = 8 << 20
	// dropMargin covers the {"envelope":…} wrapper the drop-off body adds over the
	// stored blob that the per-account MaxMessage cap actually bounds.
	dropMargin = 4 << 10
	// maxNonces caps the live challenge jar. GET /mailbox/challenge is
	// unauthenticated and reachable by anyone (this is a public store-and-forward
	// service), each call stores a nonce for nonceTTL, and pruneLocked only drops
	// EXPIRED entries — so without a ceiling a sustained flood grows the jar to
	// (rate x TTL). This server has no in-flight limiter at all (unlike the app's
	// onion listener), so the jar is the whole memory bound. At the cap we evict
	// the oldest outstanding nonce, so a legitimate caller's fresh challenge
	// always succeeds. Same fix as api.syncNonceJar and protocol.Peer.
	maxNonces = 4096
)

// Server is the mailbox's HTTP surface. It authenticates account-owner
// operations with a server-issued nonce signed by the account's identity key,
// and accepts drop-offs whose envelope signature verifies (without decrypting).
type Server struct {
	store         *Store
	jar           *nonceJar
	dropCap       int64 // max message drop-off request body — tracks the configured per-blob cap
	backupDropCap int64 // max backup drop-off request body — tracks the (larger) per-blob backup cap
}

func NewServer(store *Store) *Server {
	// The drop-off body must fit the largest blob any tenant may store, so an
	// operator who raises MaxMessage (to allow images, say) can actually receive
	// them — otherwise a fixed body cap silently rejects them before storage. Bound
	// it by the ceiling (unlimited config ⇒ ceiling) and never below the small-body
	// cap (text always fits).
	drop := store.MaxBlobBytes()
	if drop <= 0 || drop > maxDropCeiling {
		drop = maxDropCeiling
	}
	drop += dropMargin
	if drop < maxBodyBytes {
		drop = maxBodyBytes
	}
	// The backup drop-off carries a full group image, so it is sized off the
	// (larger) per-blob backup ceiling instead of the message ceiling — otherwise
	// an image-sized backup would be rejected by dropCap before it reached the
	// store. Same hard bound (maxDropCeiling comfortably covers a 3 MiB image
	// envelope) so it can never exceed the message path's memory bound.
	backupDrop := store.MaxBackupBlobBytes()
	if backupDrop <= 0 || backupDrop > maxDropCeiling {
		backupDrop = maxDropCeiling
	}
	backupDrop += dropMargin
	if backupDrop < maxBodyBytes {
		backupDrop = maxBodyBytes
	}
	return &Server{store: store, jar: newNonceJar(nonceTTL), dropCap: drop, backupDropCap: backupDrop}
}

// maxInFlight bounds concurrent requests. A drop-off body can be as large as the
// configured per-blob cap (up to maxDropCeiling) and must be read in full before
// the envelope signature can be checked — so on an image-enabled box (a larger
// dropCap) unbounded concurrent large-body reads would be a memory-exhaustion
// vector. This is the server's only concurrency bound; an operator expecting real
// load should also rate-limit at their reverse proxy (see the README).
const maxInFlight = 64

// Handler returns the mux for the mailbox endpoints, wrapped by the concurrency
// limiter.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /mailbox/challenge", s.handleChallenge)
	mux.HandleFunc("POST /mailbox/checkin", s.handleCheckin)
	mux.HandleFunc("POST /mailbox/dropoff", s.handleDropoff)
	mux.HandleFunc("POST /mailbox/pickup", s.handlePickup)
	mux.HandleFunc("POST /mailbox/delete", s.handleDelete)
	mux.HandleFunc("POST /mailbox/forget", s.handleForget)
	mux.HandleFunc("POST /mailbox/backup/dropoff", s.handleBackupDropoff)
	mux.HandleFunc("POST /mailbox/backup/pickup", s.handleBackupPickup)
	mux.HandleFunc("POST /mailbox/backup/list", s.handleBackupList)
	mux.HandleFunc("POST /mailbox/backup/fetch", s.handleBackupFetch)
	mux.HandleFunc("POST /mailbox/backup/purge", s.handleBackupPurge)
	return limitInFlight(maxInFlight, mux)
}

// limitInFlight rejects requests over a concurrency cap with 503 rather than
// queueing them, so a flood of large drop-off bodies cannot pile up in memory.
// Mirrors api.limitInFlight.
func limitInFlight(n int, next http.Handler) http.Handler {
	sem := make(chan struct{}, n)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			next.ServeHTTP(w, r)
		default:
			http.Error(w, "busy", http.StatusServiceUnavailable)
		}
	})
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string][]byte{"nonce": s.jar.Issue()})
}

func (s *Server) handleCheckin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account string `json:"account"`
		Nonce   []byte `json:"nonce"`
		Sig     []byte `json:"sig"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !s.authOp(protocol.MailboxOpCheckin, req.Account, req.Nonce, req.Sig) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	usage, err := s.store.CheckIn(req.Account)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"usage": usage})
}

func (s *Server) handleDropoff(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Envelope protocol.MailEnvelope `json:"envelope"`
	}
	// A drop-off carries the blob, so it uses the larger dropCap (which tracks the
	// operator's per-blob config) rather than the small authed-body cap.
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, s.dropCap)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Verify the sender's signature without decrypting: rejects garbage/forged
	// blobs and binds the drop-off to a real sender key. Content stays opaque.
	if !req.Envelope.VerifySignature() {
		http.Error(w, "invalid envelope", http.StatusBadRequest)
		return
	}
	blob, err := json.Marshal(req.Envelope)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	switch err := s.store.DropOff(req.Envelope.Recipient, req.Envelope.ID(), blob); {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]string{"status": "stored"})
	case errors.Is(err, ErrNoMailbox):
		http.Error(w, "recipient has no mailbox here", http.StatusNotFound)
	case errors.Is(err, ErrOverCap):
		http.Error(w, "mailbox full", http.StatusInsufficientStorage)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (s *Server) handlePickup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account string `json:"account"`
		Nonce   []byte `json:"nonce"`
		Sig     []byte `json:"sig"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !s.authOp(protocol.MailboxOpPickup, req.Account, req.Nonce, req.Sig) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	items, err := s.store.Pickup(req.Account)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		out = append(out, map[string]any{"id": it.ID, "envelope": json.RawMessage(it.Blob)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account string   `json:"account"`
		Nonce   []byte   `json:"nonce"`
		Sig     []byte   `json:"sig"`
		IDs     []string `json:"ids"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !s.authOp(protocol.MailboxOpDelete, req.Account, req.Nonce, req.Sig, protocol.MailboxDeleteBinding(req.IDs)) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := s.store.Delete(req.Account, req.IDs); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleForget(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account string `json:"account"`
		Nonce   []byte `json:"nonce"`
		Sig     []byte `json:"sig"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !s.authOp(protocol.MailboxOpForget, req.Account, req.Nonce, req.Sig) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := s.store.Forget(req.Account); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "forgotten"})
}

// handleBackupDropoff stores a durable self-sealed group-image backup in the
// owner's OWN mailbox. Unlike the message drop-off it is authenticated (only the
// owner may write to its own backup class) AND carries a large image body, so it
// combines the signed-nonce auth with the larger backupDropCap body reader. The
// signature binds the stable blob id and requested budget; the envelope must be
// self-addressed (recipient == sender == account) so this endpoint can never be
// used to write into anyone else's mailbox.
func (s *Server) handleBackupDropoff(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account  string                `json:"account"`
		Nonce    []byte                `json:"nonce"`
		Sig      []byte                `json:"sig"`
		ID       string                `json:"id"`
		Budget   int64                 `json:"budget"`
		Envelope protocol.MailEnvelope `json:"envelope"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, s.backupDropCap)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !s.authOp(protocol.MailboxOpBackupDropoff, req.Account, req.Nonce, req.Sig, protocol.MailboxBackupBinding(req.ID, req.Budget)...) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// A backup is self-addressed: the authenticated owner storing into its own
	// mailbox. Reject anything else so this authed path can't write elsewhere.
	if req.Envelope.Recipient != req.Account || req.Envelope.Sender != req.Account {
		http.Error(w, "backup must be self-addressed", http.StatusBadRequest)
		return
	}
	if !req.Envelope.VerifySignature() {
		http.Error(w, "invalid envelope", http.StatusBadRequest)
		return
	}
	blob, err := json.Marshal(req.Envelope)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	switch err := s.store.DropOffBackup(req.Account, req.ID, blob, req.Budget); {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]string{"status": "stored"})
	case errors.Is(err, ErrNoMailbox):
		http.Error(w, "no mailbox here", http.StatusNotFound)
	case errors.Is(err, ErrBackupDisabled):
		http.Error(w, "backups not offered here", http.StatusForbidden)
	case errors.Is(err, ErrOverCap):
		http.Error(w, "backup too large", http.StatusInsufficientStorage)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// handleBackupPickup returns all durable backup blobs for the authenticated owner,
// non-destructively (a fresh device restores from them without consuming them).
func (s *Server) handleBackupPickup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account string `json:"account"`
		Nonce   []byte `json:"nonce"`
		Sig     []byte `json:"sig"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !s.authOp(protocol.MailboxOpBackupPickup, req.Account, req.Nonce, req.Sig) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	items, err := s.store.PickupBackup(req.Account)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		out = append(out, map[string]any{"id": it.ID, "envelope": json.RawMessage(it.Blob)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// handleBackupList returns just the ids and sizes of the authenticated owner's
// durable backups, no blob bytes. A fresh device lists first, then fetches only
// the ids whose bytes it is missing locally — so restore streams one blob per
// response and never has to pull the whole (potentially tens-of-MB) set through
// a single size-capped body.
func (s *Server) handleBackupList(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account string `json:"account"`
		Nonce   []byte `json:"nonce"`
		Sig     []byte `json:"sig"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !s.authOp(protocol.MailboxOpBackupList, req.Account, req.Nonce, req.Sig) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	metas, err := s.store.ListBackups(req.Account)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": metas})
}

// handleBackupFetch returns exactly one backup blob by id, so a restoring device
// pulls only the ids it is actually missing, one response at a time. The signature
// binds the requested id.
func (s *Server) handleBackupFetch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account string `json:"account"`
		Nonce   []byte `json:"nonce"`
		Sig     []byte `json:"sig"`
		ID      string `json:"id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !s.authOp(protocol.MailboxOpBackupFetch, req.Account, req.Nonce, req.Sig, protocol.MailboxBackupFetchBinding(req.ID)...) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	blob, err := s.store.GetBackup(req.Account, req.ID)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{"id": req.ID, "envelope": json.RawMessage(blob)})
	case errors.Is(err, ErrNotFound):
		http.Error(w, "no such backup", http.StatusNotFound)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// handleBackupPurge removes all durable backup blobs for the authenticated owner.
func (s *Server) handleBackupPurge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account string `json:"account"`
		Nonce   []byte `json:"nonce"`
		Sig     []byte `json:"sig"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !s.authOp(protocol.MailboxOpBackupPurge, req.Account, req.Nonce, req.Sig) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := s.store.PurgeBackups(req.Account); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "purged"})
}

// authOp consumes the nonce and verifies the account owner's signature over the
// operation. The nonce is single-use, so a captured request cannot be replayed.
func (s *Server) authOp(op, account string, nonce, sig []byte, extra ...[]byte) bool {
	pub, err := identity.AccountNumberFromString(account)
	if err != nil {
		return false
	}
	if !s.jar.Consume(nonce) {
		return false
	}
	return ed25519.Verify(pub, protocol.MailboxAuthBlob(op, nonce, account, extra...), sig)
}

// --- nonce jar ---

type nonceJar struct {
	mu     sync.Mutex
	nonces map[string]time.Time
	ttl    time.Duration
}

func newNonceJar(ttl time.Duration) *nonceJar {
	return &nonceJar{nonces: map[string]time.Time{}, ttl: ttl}
}

func (j *nonceJar) Issue() []byte {
	n := make([]byte, nonceLen)
	_, _ = rand.Read(n)
	j.mu.Lock()
	j.pruneLocked()
	j.evictOldestLocked()
	j.nonces[string(n)] = time.Now().Add(j.ttl)
	j.mu.Unlock()
	return n
}

func (j *nonceJar) Consume(n []byte) bool {
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

func (j *nonceJar) pruneLocked() {
	now := time.Now()
	for n, exp := range j.nonces {
		if now.After(exp) {
			delete(j.nonces, n)
		}
	}
}

// evictOldestLocked keeps the jar within maxNonces by dropping the
// soonest-to-expire (oldest-issued, since every nonce shares the same ttl)
// entries until there is room for one more. Normally a no-op; it only bites
// under a challenge flood, bounding the jar to ~maxNonces. Mirrors
// api.syncNonceJar.evictOldestLocked and protocol.Peer.evictOldestLocked.
func (j *nonceJar) evictOldestLocked() {
	for len(j.nonces) >= maxNonces {
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

// --- helpers ---

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(v); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
