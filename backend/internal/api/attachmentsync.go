package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

const (
	// attachSyncMaxWant bounds the ids a secondary requests per round. The primary
	// truncates the response by BYTES (below), so a request for many ids just
	// pulls the first that fit and the rest come next tick — provided the want
	// list is stable (oldest-missing first), so truncation makes forward progress.
	attachSyncMaxWant = 8
	// attachSyncProvideBytes bounds the plaintext bytes served in one response (~2
	// images). Independent of the want COUNT: 8 wanted ids at 3 MiB each is far
	// more intent than one response should carry.
	attachSyncProvideBytes = 2 * protocol.MaxAttachmentBytes
	// attachSyncMaxPush bounds blobs uploaded per round (kept to one so the request
	// body stays close to a single image).
	attachSyncMaxPush = 1
	// attachSyncMaxNeed bounds the ids advertised in a need list.
	attachSyncMaxNeed = 64
	// attachSyncReqCap bounds the request body: at most one pushed image (base64)
	// plus the small want/auth JSON. Same shape as attachBodyCap.
	attachSyncReqCap = 2*protocol.MaxAttachmentBytes + 1<<16
)

// handleAttachmentSync serves the primary side of attachment backfill: it is the
// account onion endpoint an enrolled secondary dials to move image bytes between
// the user's own devices. Gated by SyncVerify (identity key + enrolled device
// key over a single-use nonce) exactly like /sync — the message history this
// backs is already reachable there, so no new trust boundary is crossed.
func (s *Server) handleAttachmentSync(w http.ResponseWriter, r *http.Request) {
	if s.currentPeer() == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		DevicePub []byte                    `json:"device_pub"`
		Nonce     []byte                    `json:"nonce"`
		IDSig     []byte                    `json:"id_sig"`
		DeviceSig []byte                    `json:"device_sig"`
		Want      []string                  `json:"want"`
		Push      []protocol.AttachmentBlob `json:"push"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, attachSyncReqCap)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Consume the nonce and verify both signatures + enrollment before doing any
	// work, mirroring handleSyncExchange.
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

	s.ingestPushedAttachments(req.Push)
	provide := s.provideAttachments(req.Want)
	need := s.neededAttachments()
	writeJSON(w, http.StatusOK, map[string]any{"provide": provide, "need": need})
}

// syncBlobIDForRow returns the single blob id this image row moves over the
// device-to-device sync path, or "" for a row that carries no such blob. It is
// the ONE place the row→id mapping lives, so the want/need builders and the
// resolve gate below can never drift apart (an earlier split — gate keyed on
// ID, want built from AttachID — silently starved group thumbs).
//
//   - 1:1 image: the full blob, stored under AttachID (== ID).
//   - group image: only the small thumbnail (ThumbID, ≤16 KiB). The full moves
//     via the mailbox self-backup, never device-to-device; advertising its
//     AttachID here would list an id this path can never resolve and, oldest
//     first with a hard want cap, starve the thumbs behind it.
func syncBlobIDForRow(m chatMessage) string {
	if m.Kind != chatstore.KindImage {
		return ""
	}
	if m.GroupID != "" {
		return m.ThumbID
	}
	return m.AttachID
}

// resolveSyncBlobLocked reports whether id names a blob this path may move, and
// with what MIME and per-class byte cap. It is the reference gate: an enrolled
// device can only move bytes the synced history mentions, never arbitrary
// blobs. Keyed on syncBlobIDForRow (not a raw field) so the gate and the
// want/need lists resolve the same id by construction. Caller holds sessMu.
func (s *Server) resolveSyncBlobLocked(id string) (mime string, maxBytes int, ok bool) {
	if id == "" {
		return "", 0, false
	}
	for i := range s.messages {
		m := s.messages[i]
		if syncBlobIDForRow(m) != id {
			continue
		}
		if m.GroupID == "" {
			return m.Mime, protocol.MaxAttachmentBytes, true // 1:1 full
		}
		return m.ThumbMime, protocol.MaxGroupThumbBytes, true // group thumbnail
	}
	return "", 0, false
}

// isDeletedLocked reports whether id has a delete tombstone. Caller holds sessMu.
func (s *Server) isDeletedLocked(id string) bool {
	for _, d := range s.deleted {
		if d == id {
			return true
		}
	}
	return false
}

// ingestPushedAttachments stores blobs a peer device uploaded. Each is accepted
// only for an id we have an image row for but no blob yet (need-driven, so the
// row is present) and is never overwritten — a resend can't clobber a good blob.
func (s *Server) ingestPushedAttachments(push []protocol.AttachmentBlob) {
	if len(push) == 0 {
		return
	}
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if s.attach == nil {
		return
	}
	for _, b := range push {
		if len(b.Data) == 0 {
			continue
		}
		_, maxBytes, ok := s.resolveSyncBlobLocked(b.ID)
		if !ok {
			log.Printf("attachment sync: ignoring pushed blob %s with no image row", shortID(b.ID))
			continue
		}
		if len(b.Data) > maxBytes {
			continue
		}
		if s.isDeletedLocked(b.ID) || s.attach.Has(b.ID) {
			continue
		}
		if err := s.attach.Put(b.ID, b.Data); err != nil {
			log.Printf("attachment sync: storing pushed blob %s: %v", shortID(b.ID), err)
		}
	}
}

// provideAttachments returns the blobs we hold for the requested ids, in request
// order, bounded by attachSyncProvideBytes (always at least one, so a lone large
// image still moves). Only ids naming a real image row are served.
func (s *Server) provideAttachments(want []string) []protocol.AttachmentBlob {
	s.sessMu.Lock()
	store := s.attach
	type hit struct{ id, mime string }
	var hits []hit
	seen := map[string]bool{}
	for _, id := range want {
		if len(hits) >= attachSyncMaxWant {
			break
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		if mime, _, ok := s.resolveSyncBlobLocked(id); ok {
			hits = append(hits, hit{id, mime})
		}
	}
	s.sessMu.Unlock()
	if store == nil {
		return nil
	}
	var out []protocol.AttachmentBlob
	var budget int
	for _, h := range hits {
		if !store.Has(h.id) {
			continue
		}
		data, err := store.Get(h.id)
		if err != nil {
			continue
		}
		if len(out) > 0 && budget+len(data) > attachSyncProvideBytes {
			break // byte truncation; the rest come next tick (stable want order)
		}
		out = append(out, protocol.AttachmentBlob{ID: h.id, Mime: h.mime, Data: data})
		budget += len(data)
	}
	return out
}

// neededAttachments lists image ids we have a row for but no blob — i.e. the
// blobs a peer device might hold and could push to us. It is NOT a convergence
// signal: an image whose bytes no device still holds stays listed forever, and
// that is harmless (the list is ids only).
//
// A DELETED image can never appear here: applyTombstones drops a tombstoned id's
// row from s.messages on every load and merge (and a local delete removes the
// row outright), so there is no row left to list. That is what stops a deleted
// image from becoming a blob the peer re-uploads every tick.
func (s *Server) neededAttachments() []string {
	s.sessMu.Lock()
	store := s.attach
	var ids []string
	seen := map[string]bool{}
	for i := range s.messages {
		if bid := syncBlobIDForRow(s.messages[i]); bid != "" && !seen[bid] {
			seen[bid] = true
			ids = append(ids, bid)
		}
	}
	s.sessMu.Unlock()
	if store == nil {
		return nil
	}
	var need []string
	for _, id := range ids {
		if len(need) >= attachSyncMaxNeed {
			break
		}
		if !store.Has(id) {
			need = append(need, id)
		}
	}
	return need
}

// attachmentSyncOnce runs one backfill round from a secondary against the
// primary: it pushes blobs the primary last said it needs, pulls blobs this
// device is missing (oldest-referenced first, a stable order so the primary's
// byte-truncation makes progress), and remembers the primary's fresh need list
// for the next round. Called after syncOnce, so the message rows the ids
// reference are already merged.
func (s *Server) attachmentSyncOnce(ctx context.Context, id *identity.Identity) error {
	d := s.currentDevice()
	if s.onion == nil || d == nil {
		return nil
	}
	s.sessMu.Lock()
	store := s.attach
	var want []string
	if store != nil {
		for i := range s.messages { // append order == oldest first
			if len(want) >= attachSyncMaxWant {
				break
			}
			if bid := syncBlobIDForRow(s.messages[i]); bid != "" && !store.Has(bid) {
				want = append(want, bid)
			}
		}
	}
	prevNeed := s.attachNeed
	s.sessMu.Unlock()
	if store == nil {
		return nil
	}

	// Build the push list from what the primary last asked for and we hold,
	// bounded to roughly one image so the request body stays small.
	var push []protocol.AttachmentBlob
	var pushBytes int
	for _, nid := range prevNeed {
		if len(push) >= attachSyncMaxPush {
			break
		}
		if !store.Has(nid) {
			continue
		}
		s.sessMu.Lock()
		mime, maxBytes, ok := s.resolveSyncBlobLocked(nid)
		s.sessMu.Unlock()
		if !ok {
			continue
		}
		data, err := store.Get(nid)
		if err != nil {
			continue
		}
		if len(data) > maxBytes {
			continue // stored blob outgrew its row's class; don't push it
		}
		if len(push) > 0 && pushBytes+len(data) > protocol.MaxAttachmentBytes {
			break
		}
		push = append(push, protocol.AttachmentBlob{ID: nid, Mime: mime, Data: data})
		pushBytes += len(data)
	}

	if len(want) == 0 && len(push) == 0 && len(prevNeed) == 0 {
		return nil // no images missing here, nothing pending to push
	}

	cctx, cancel := context.WithTimeout(ctx, syncOpTimeout)
	defer cancel()
	provide, need, err := protocol.AttachmentSyncExchange(cctx, s.onion.Dialer(), id, d.PublicKey(), d.Sign, want, push)
	if err != nil {
		return err
	}

	s.ingestProvidedAttachments(provide)

	s.sessMu.Lock()
	// Don't resurrect a need list onto a session that was cleared (locked) while
	// the exchange was in flight — attach==nil is the cleared marker.
	if s.attach != nil {
		s.attachNeed = need
	}
	s.sessMu.Unlock()
	return nil
}

// ingestProvidedAttachments stores blobs the primary served for our want list.
// Same gate as a pushed blob (a real image row, not tombstoned, no overwrite);
// a Put error — a full store being the likely one — STOPS the batch rather than
// re-requesting the same doomed blob every tick.
func (s *Server) ingestProvidedAttachments(provide []protocol.AttachmentBlob) {
	for _, b := range provide {
		if len(b.Data) == 0 {
			continue
		}
		s.sessMu.Lock()
		st := s.attach
		_, maxBytes, ok := s.resolveSyncBlobLocked(b.ID)
		skip := st == nil || !ok || len(b.Data) > maxBytes || s.isDeletedLocked(b.ID) || st.Has(b.ID)
		s.sessMu.Unlock()
		if skip {
			continue
		}
		if err := st.Put(b.ID, b.Data); err != nil {
			log.Printf("attachment sync: storing pulled blob %s: %v (stopping this round)", shortID(b.ID), err)
			return
		}
	}
}

// shortID trims an id for logs (they otherwise name every attachment in full).
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
