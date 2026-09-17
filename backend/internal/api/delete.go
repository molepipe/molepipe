package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// "Delete for everyone" (security doc §3).
//
// What this is NOT: a remote wipe. It removes ONE message the sender sent, from
// the recipient's view, because the recipient's client chooses to honour the
// request. A modified client can ignore it, an offline recipient may never see
// it, and a screenshot is already beyond reach. The UI is worded to match.

// deleteWindow is how long after sending the option stays available. Matching
// the mental model from other messengers matters more than the exact number:
// an unbounded reach into someone else's history is a different, larger claim
// than the one this feature makes.
const deleteWindow = time.Hour

// hookOnDeleteMessage applies a verified delete request from a peer.
//
// The signature proves WHO is asking; it says nothing about what they are
// entitled to delete. That check is here, and it is the whole security of the
// feature: a request may only remove a message that arrived FROM this sender.
// Without the direction test, a contact could compute the ID of a message we
// sent THEM and delete our own copy of our own words.
func (s *Server) hookOnDeleteMessage(from, messageID string) error {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()

	for i, m := range s.messages {
		if m.ID != messageID {
			continue
		}
		if m.Direction != "in" || m.Peer != from {
			return fmt.Errorf("not the sender of that message")
		}
		// Enforce the window against OUR OWN record of when it arrived, not a
		// timestamp the requester controls, so this cannot be used to reach
		// back into old history.
		if time.Since(m.At) > deleteWindow {
			return fmt.Errorf("too late")
		}
		s.deleteAttachmentsLocked(m) // while the row is still here (see the helper)
		s.messages = append(s.messages[:i], s.messages[i+1:]...)
		s.deleteTombstone(messageID)
		s.persistLocked()
		return nil
	}
	// Nothing to delete. Report success: whether we hold a given message is not
	// something a peer gets to probe for by watching which requests fail.
	return nil
}

// deleteTombstone records the removal so a later sync cannot resurrect it.
// Caller holds sessMu.
func (s *Server) deleteTombstone(messageID string) {
	for _, id := range s.deleted {
		if id == messageID {
			return
		}
	}
	s.deleted = append(s.deleted, messageID)
	// A 1:1 image's attachment id IS its message id, so deleting the blob named by
	// the tombstone cleans it up (a no-op for text, which has no blob). This also
	// covers a tombstone that arrived via sync, where the row is already gone.
	// GROUP image blobs live under different ids (AttachID + ThumbID), so those are
	// cleaned by deleteAttachmentsLocked at the row-present delete paths. A group
	// image deleted on ANOTHER device arrives here as a tombstone with no row, so
	// this Delete(messageID) can't reach its blobs — sweepOrphanAttachmentsLocked,
	// run after every merge that adopts such a tombstone, reclaims them instead
	// (the store never evicts, so an unswept group blob would leak permanently).
	if s.attach != nil {
		s.attach.Delete(messageID)
	}
}

// sweepOrphanAttachmentsLocked deletes every stored blob that no live image row
// references. It is the durable backstop for cross-device deletes: a group image
// deleted on another device reaches us as a tombstone (no row), so its full and
// thumbnail blobs — keyed by AttachID/ThumbID, neither equal to the message id —
// can't be found by the tombstone's own Delete. This rebuilds the keep-set from
// the current rows and drops anything else.
//
// It is SAFE to delete an unreferenced blob because every legitimate Put files or
// already has a live row referencing the blob under the SAME sessMu hold (local
// send, 1:1 inbound, group send, sync-push ingest, on-demand full, backup
// restore) — so an on-disk blob with no row is a genuine orphan, never a blob
// whose row simply hasn't arrived yet.
//
// Caller holds sessMu. Call ONLY on paths where s.messages is authoritative
// (after a successful Load, or after a sync/pair merge) — never on the load-error
// "starting empty" fallback, which would make the empty keep-set delete every
// blob. The len==0 guard is a second line of defence against exactly that.
func (s *Server) sweepOrphanAttachmentsLocked() {
	if s.attach == nil {
		return
	}
	// No rows at all almost always means a failed/empty load, not a genuine
	// full delete; refuse to sweep rather than risk wiping a recoverable store.
	if len(s.messages) == 0 {
		return
	}
	keep := make(map[string]struct{}, len(s.messages))
	for _, m := range s.messages {
		// Gate: only KindImage rows own blobs today. A future attachment-bearing
		// kind MUST add its blob ids here, or the sweep will reclaim them.
		if m.Kind != chatstore.KindImage {
			continue
		}
		if m.AttachID != "" {
			keep[m.AttachID] = struct{}{}
		}
		if m.ThumbID != "" {
			keep[m.ThumbID] = struct{}{}
		}
	}
	ids, err := s.attach.List()
	if err != nil {
		log.Printf("attachment sweep: list store: %v", err)
		return
	}
	for _, id := range ids {
		if _, ok := keep[id]; !ok {
			s.attach.Delete(id)
		}
	}
}

// sweepOrphanAvatarsLocked deletes every stored avatar that neither our own
// profile nor any contact references. The avatar store is content-addressed and
// never evicts, so a contact rotating their picture — or us changing ours — leaves
// the superseded bytes on disk forever; left unchecked they eventually fill the
// 32 MiB cap and Put starts failing for everything, including setting our own
// avatar (the "walled-off store" failure). This rebuilds the keep-set from the
// current profile + contacts and drops anything else.
//
// Unlike sweepOrphanAttachmentsLocked, this needs no len-guard against a wipe:
// every avatar is content-addressed and re-obtainable — a contact's re-fetches on
// the next presence sweep, our own rides the profile sync (and s.avatarBytesOwn) —
// so an over-eager reclaim self-heals rather than losing data. It is still called
// only on authoritative paths (post-Load, post-merge) to avoid pointless churn.
// Caller holds sessMu.
func (s *Server) sweepOrphanAvatarsLocked() {
	if s.avatarStore == nil {
		return
	}
	keep := make(map[string]struct{}, len(s.contacts)+1)
	if s.avatarHash != "" {
		keep[s.avatarHash] = struct{}{}
	}
	for _, c := range s.contacts {
		if c.AvatarHash != "" {
			keep[c.AvatarHash] = struct{}{}
		}
	}
	hashes, err := s.avatarStore.List()
	if err != nil {
		log.Printf("avatar sweep: list store: %v", err)
		return
	}
	for _, h := range hashes {
		if _, ok := keep[h]; !ok {
			s.avatarStore.Delete(h)
		}
	}
}

// deleteAttachmentsLocked removes the blob(s) a message row referenced. It must be
// called WHILE the row is still present, because a group image's blobs live under
// AttachID (full) and ThumbID (thumbnail) — neither is the row id, so the tombstone
// alone can't find them. A no-op for text. For a 1:1 image AttachID == the row id,
// so this and deleteTombstone's cleanup are the same blob. Caller holds sessMu.
func (s *Server) deleteAttachmentsLocked(m chatMessage) {
	if s.attach == nil || m.Kind != chatstore.KindImage {
		return
	}
	if m.AttachID != "" {
		s.attach.Delete(m.AttachID)
	}
	if m.ThumbID != "" {
		s.attach.Delete(m.ThumbID)
	}
}

// handleP2PDeleteMessage is the peer-facing endpoint.
func (s *Server) handleP2PDeleteMessage(w http.ResponseWriter, r *http.Request) {
	peer := s.currentPeer()
	if peer == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	var req protocol.DeleteRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := peer.ReceiveDeleteRequest(req); err != nil {
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleDeleteMessage is the sender-side control API: remove one message we
// sent, here and on the recipient's device.
func (s *Server) handleDeleteMessage(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		ID    string `json:"id"`
		Local bool   `json:"local"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Local delete ("delete for me"): remove this copy from my devices without
	// telling the peer. Works on any message — theirs or mine, any age — because
	// nothing leaves this account. The tombstone stops a later sync from
	// resurrecting it on my other devices.
	if req.Local {
		s.sessMu.Lock()
		for i := range s.messages {
			if s.messages[i].ID == req.ID {
				s.deleteAttachmentsLocked(s.messages[i])
				s.messages = append(s.messages[:i], s.messages[i+1:]...)
				break
			}
		}
		s.deleteTombstone(req.ID)
		s.persistLocked()
		s.sessMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "local": true})
		return
	}

	s.sessMu.Lock()
	var found *chatMessage
	for i := range s.messages {
		if s.messages[i].ID == req.ID {
			found = &s.messages[i]
			break
		}
	}
	if found == nil || found.Direction != "out" {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "you can only delete messages you sent"})
		return
	}
	if time.Since(found.At) > deleteWindow {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "that message is too old to delete for everyone",
		})
		return
	}
	peerAccount := found.Peer
	s.sessMu.Unlock()

	// Ask them first, then remove ours. Doing it in this order means a failure
	// leaves both copies in place — a consistent state the user can retry —
	// rather than a message gone here and still on their screen.
	reached := false
	if s.onion != nil {
		ctx, cancel := deliveryContext(2 * time.Minute)
		defer cancel()
		if err := protocol.SendDeleteMessage(ctx, s.onion.Dialer(), id, req.ID, peerAccount); err == nil {
			reached = true
		}
	}

	s.sessMu.Lock()
	for i := range s.messages {
		if s.messages[i].ID == req.ID {
			s.deleteAttachmentsLocked(s.messages[i]) // while the row is still here
			s.messages = append(s.messages[:i], s.messages[i+1:]...)
			break
		}
	}
	s.deleteTombstone(req.ID)
	s.persistLocked()
	s.sessMu.Unlock()

	// Say plainly whether it actually reached them. "Deleted" with no
	// qualification would be a claim this feature cannot make.
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "reached": reached})
}

// snapshotDeleted copies the tombstone list for persistence. Caller holds sessMu.
func (s *Server) snapshotDeleted() []string {
	return append([]string(nil), s.deleted...)
}
