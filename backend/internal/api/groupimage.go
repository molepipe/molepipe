package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// groupImageBodyCap bounds the send-image request (one full image + one thumbnail,
// both base64) and the serve response.
const groupImageBodyCap = 2*protocol.MaxAttachmentBytes + 1<<17

// groupThumbID is the deterministic attachment id a group image's thumbnail is
// stored under, derived from the full-image hash so every member (and every one of
// a user's devices) agrees on it without carrying it in the message.
func groupThumbID(fullHash []byte) string {
	h := sha256.Sum256(append([]byte("group-thumb"), fullHash...))
	return hex.EncodeToString(h[:16])
}

// groupMessageFromRowLocked reconstructs the exact author-signed GroupMessage from
// a stored row so gossip can re-seal it for another member. ok is false when it
// cannot be rebuilt: a message with no author signature, or an image whose
// thumbnail blob is gone (so the signed bytes can't be reproduced). Caller holds sessMu.
func (s *Server) groupMessageFromRowLocked(m chatMessage) (protocol.GroupMessage, bool) {
	if len(m.AuthorSig) == 0 {
		return protocol.GroupMessage{}, false
	}
	if m.Kind == chatstore.KindImage {
		if s.attach == nil {
			return protocol.GroupMessage{}, false
		}
		thumb, err := s.attach.Get(m.ThumbID)
		if err != nil {
			return protocol.GroupMessage{}, false
		}
		return protocol.GroupMessage{
			GroupID: m.GroupID, Author: m.Author, At: m.At, Sig: m.AuthorSig,
			Thumb: thumb, ThumbMime: m.ThumbMime, FullID: m.AttachID,
			FullHash: m.FullHash, FullMime: m.Mime, FullSize: m.Size,
		}, true
	}
	// ReplyID is part of the signed blob for a reply, so it MUST be reproduced here
	// or the re-sealed message fails Verify() at the gossip requester and is dropped.
	return protocol.GroupMessage{GroupID: m.GroupID, Author: m.Author, At: m.At, Text: m.Text, ReplyID: m.ReplyID, Sig: m.AuthorSig}, true
}

// deliverGroupImageInboundLocked files a group IMAGE message: it stores the inline
// blurry thumbnail (so the preview shows at once) and an image row referencing the
// full image, which is fetched on demand. Deduped by the group-image sync id, and
// a tombstoned id is refused. Caller holds sessMu.
func (s *Server) deliverGroupImageInboundLocked(gm protocol.GroupMessage, notify bool) bool {
	id := chatstore.GroupImageMessageID(gm.GroupID, gm.Author, gm.At, gm.FullHash)
	for i := range s.messages {
		if s.messages[i].ID == id {
			return false
		}
	}
	for _, d := range s.deleted {
		if d == id {
			return false
		}
	}
	thumbID := groupThumbID(gm.FullHash)
	if s.attach != nil {
		if err := s.attach.Put(thumbID, gm.Thumb); err != nil {
			log.Printf("group thumbnail store %s: %v", shortID(thumbID), err)
			// keep going — the row still records the image; the UI shows a placeholder
		}
	}
	dir := "in"
	if gm.Author == s.myAccount {
		dir = "out"
	}
	s.messages = append(s.messages, chatMessage{
		Direction: dir, GroupID: gm.GroupID, Author: gm.Author, AuthorSig: gm.Sig, At: gm.At, ID: id,
		Kind: chatstore.KindImage, AttachID: gm.FullID, Mime: gm.FullMime, Size: gm.FullSize,
		ThumbID: thumbID, ThumbMime: gm.ThumbMime, FullHash: gm.FullHash,
	})
	if notify && dir == "in" && s.onInbound != nil {
		title := s.groups[gm.GroupID].Name
		if title == "" {
			title = "Group"
		}
		preview := s.groupAuthorNameLocked(gm.GroupID, gm.Author) + ": 📷 Photo"
		avatarHash := ""
		if c, ok := s.contacts[gm.Author]; ok {
			avatarHash = c.AvatarHash
		}
		go s.onInbound(title, preview, gm.At.UnixMilli(), avatarHash)
	}
	return true
}

// handleSendGroupImage authors a group image: it stores the full image locally,
// files the row, and fans out the message carrying only the blurry thumbnail. The
// full bytes are pulled on demand by members who tap download. The client supplies
// the thumbnail (generated on its side, like 1:1 photo send).
func (s *Server) handleSendGroupImage(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		Group     string `json:"group"`
		FullMime  string `json:"full_mime"`
		FullData  string `json:"full_data"`  // base64
		ThumbMime string `json:"thumb_mime"` // base64 image, generated client-side
		ThumbData string `json:"thumb_data"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, groupImageBodyCap)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !protocol.AllowedImageMIME(req.FullMime) || !protocol.AllowedImageMIME(req.ThumbMime) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported image type"})
		return
	}
	full, err := base64.StdEncoding.DecodeString(req.FullData)
	if err != nil || len(full) == 0 || len(full) > protocol.MaxAttachmentBytes {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "image is missing or too large"})
		return
	}
	thumb, err := base64.StdEncoding.DecodeString(req.ThumbData)
	if err != nil || len(thumb) == 0 || len(thumb) > protocol.MaxGroupThumbBytes {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "thumbnail is missing or too large"})
		return
	}

	s.sessMu.Lock()
	g, ok := s.groups[req.Group]
	mine := ok && groupHasMember(g, s.myAccount)
	store := s.attach
	s.sessMu.Unlock()
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no such group"})
		return
	}
	if !mine {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "you are not a member of this group"})
		return
	}
	if s.onion == nil || store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
		return
	}

	fullID := randomID()
	sum := sha256.Sum256(full)
	gm, err := protocol.NewGroupImageMessage(id, req.Group, thumb, req.ThumbMime, fullID, sum[:], req.FullMime, len(full), time.Now())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	msgID := chatstore.GroupImageMessageID(gm.GroupID, gm.Author, gm.At, gm.FullHash)

	// Store the full blob and file its row under a SINGLE sessMu hold, so the blob
	// is never on disk without a live row referencing it. Putting off-lock ahead
	// of the row (as this used to) leaves a window in which the orphan sweep, which
	// runs under sessMu on any concurrent merge, could reap a just-sent image.
	s.sessMu.Lock()
	if err := store.Put(fullID, full); err != nil {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusInsufficientStorage, map[string]string{"error": err.Error()})
		return
	}
	if s.deliverGroupInboundLocked(gm, false) { // own message: stores thumb + row, dir "out"
		s.persistLocked()
	} else {
		// Dedup hit (same group+author+at+hash already filed): the existing row keeps
		// its own full id, so the blob we just stored has no row — drop it to hold the
		// every-blob-has-a-row invariant the sweep relies on.
		store.Delete(fullID)
	}
	s.sessMu.Unlock()
	go s.groupFanOut(id, g, gm)
	go s.backupGroupImage(id, fullID, req.FullMime, full) // durable self-backup (no-op unless opted in)
	writeJSON(w, http.StatusOK, map[string]any{"status": "queued", "id": msgID})
}

// handleP2PGroupImage serves the full bytes of a group image to a member who asks.
// Gated: the requester's signature verifies, we and the requester both currently
// belong to the group, and the id names a group-image row we actually hold (so we
// never serve an arbitrary blob). The response is sealed to the requester.
//
// Serving is safe without re-hashing here because every full-image blob we hold
// was verified on the way in: we authored it (handleSendGroupImage), or we
// downloaded it and checked sha256 == the author-signed FullHash
// (handleDownloadGroupImage), or an enrolled device of our own — which did one of
// those — backfilled it over the authenticated sync path. No unverified bytes can
// reach the attachment store under a full-image id, so we cannot re-serve a
// substituted image.
func (s *Server) handleP2PGroupImage(w http.ResponseWriter, r *http.Request) {
	if s.currentPeer() == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	var req protocol.GroupImageRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !req.Verify() {
		groupReject(w)
		return
	}
	s.sessMu.Lock()
	g, ok := s.groups[req.GroupID]
	var reqDH [32]byte
	haveDH := false
	if ok {
		for _, m := range g.Members {
			if m.Account == req.Requester && len(m.DHPub) == 32 {
				copy(reqDH[:], m.DHPub)
				haveDH = true
				break
			}
		}
	}
	referenced := false
	for i := range s.messages {
		if s.messages[i].GroupID == req.GroupID && s.messages[i].Kind == chatstore.KindImage && s.messages[i].AttachID == req.FullID {
			referenced = true
			break
		}
	}
	serve := ok && groupHasMember(g, s.myAccount) && groupHasMember(g, req.Requester) && haveDH && referenced
	store := s.attach
	id := s.sessID
	s.sessMu.Unlock()
	if !serve || store == nil || id == nil || !store.Has(req.FullID) {
		groupReject(w)
		return
	}
	data, err := store.Get(req.FullID)
	if err != nil {
		groupReject(w)
		return
	}
	env, err := protocol.SealGroupImage(id, req.Requester, reqDH, data)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, env)
}

// handleDownloadGroupImage fetches the full bytes for a group image the user
// tapped, verifies them against the author-signed hash, and stores them so the
// serve endpoint can render the full image. v1 fetches from the AUTHOR; if they're
// offline it fails honestly (the UI keeps the download button).
func (s *Server) handleDownloadGroupImage(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		Group string `json:"group"`
		ID    string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.sessMu.Lock()
	var fullID, author, fullMime string
	var fullHash []byte
	for i := range s.messages {
		m := s.messages[i]
		if m.ID == req.ID && m.GroupID == req.Group && m.Kind == chatstore.KindImage {
			fullID, author, fullMime, fullHash = m.AttachID, m.Author, m.Mime, m.FullHash
			break
		}
	}
	store := s.attach
	have := store != nil && fullID != "" && store.Has(fullID)
	s.sessMu.Unlock()
	if fullID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no such group image"})
		return
	}
	if have {
		writeJSON(w, http.StatusOK, map[string]string{"status": "have"})
		return
	}
	if s.onion == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Tor is disabled"})
		return
	}
	ctx, cancel := deliveryContext(imageSendTimeout)
	defer cancel()
	data, err := protocol.FetchGroupImage(ctx, s.onion.Dialer(), id, author, req.Group, fullID)
	if err != nil {
		// The author is unreachable. On a secondary, our OWN primary may already
		// hold the full — we (or another of our devices) downloaded or authored it
		// there. Dial our own account onion, which the primary hosts, and ask it
		// over the same holder-gated serve path (handleP2PGroupImage): the primary
		// seals the bytes to our account's DH key, which this device can open with
		// the shared identity, and the hash check below still guards what we store.
		// Skipped when the author already IS our account (that first fetch went to
		// the primary) or on the primary itself (a self-dial reaches no other
		// device), so no wasted round trip in those cases.
		// The primary is a single self-onion hop we either reach or don't, so give
		// this leg a shorter budget rather than a second full image-relay timeout —
		// two 90s legs in series would block this control-port handler for 3 minutes.
		if d := s.currentDevice(); d != nil && !d.IsPrimary() && author != id.AccountNumber() {
			ctx2, cancel2 := deliveryContext(primaryFetchTimeout)
			data, err = protocol.FetchGroupImage(ctx2, s.onion.Dialer(), id, id.AccountNumber(), req.Group, fullID)
			cancel2()
		}
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "couldn't fetch the image (the sender may be offline)"})
			return
		}
	}
	sum := sha256.Sum256(data)
	if len(data) == 0 || len(data) > protocol.MaxAttachmentBytes || !bytes.Equal(sum[:], fullHash) {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "the fetched image did not match its signature"})
		return
	}
	s.sessMu.Lock()
	if s.attach != nil {
		_ = s.attach.Put(fullID, data)
	}
	s.sessMu.Unlock()
	go s.backupGroupImage(id, fullID, fullMime, data) // durable self-backup (no-op unless opted in)
	writeJSON(w, http.StatusOK, map[string]string{"status": "downloaded"})
}
