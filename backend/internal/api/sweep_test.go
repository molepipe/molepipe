package api

import (
	"bytes"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// TestSweepReclaimsGroupTombstoneBlobs is the core of the fix. A group image deleted
// on ANOTHER device reaches us as a tombstone with NO row (applyTombstones drops the
// row during the merge that adopts it). Its full (AttachID) and thumbnail (ThumbID)
// blobs are keyed by ids that are neither the message id, so the tombstone's own
// Delete(messageID) can't reach them — the store never evicts, so they would leak
// permanently. The orphan sweep must reclaim both.
func TestSweepReclaimsGroupTombstoneBlobs(t *testing.T) {
	s, _ := syncPrimary(t)

	// The tombstoned group image's two blobs: on disk, but no row references them.
	orphanFull := randomID()
	orphanThumb := randomID()
	// A live 1:1 image whose blob must survive — and which keeps len(s.messages) > 0
	// so the empty-store guard doesn't short-circuit the sweep.
	liveID := randomID()

	s.sessMu.Lock()
	for _, id := range []string{orphanFull, orphanThumb, liveID} {
		if err := s.attach.Put(id, bytes.Repeat([]byte{0x11}, 512)); err != nil {
			s.sessMu.Unlock()
			t.Fatal(err)
		}
	}
	s.messages = append(s.messages, imageRow(liveID, "image/png", 1))
	s.deleted = append(s.deleted, "group-tombstone-message-id") // the message id, not a blob id
	s.sweepOrphanAttachmentsLocked()
	s.sessMu.Unlock()

	if s.attach.Has(orphanFull) {
		t.Error("group image FULL blob leaked past the sweep")
	}
	if s.attach.Has(orphanThumb) {
		t.Error("group image THUMBNAIL blob leaked past the sweep")
	}
	if !s.attach.Has(liveID) {
		t.Error("sweep reaped a live 1:1 image blob")
	}
}

// TestSweepKeepsSentGroupImageBlobs guards the send path against the sweep. A group
// image this device authored files a thumbnail (under ThumbID) and a full blob (under
// AttachID) beneath one live row. BOTH ids must be in the sweep's keep-set, or a
// merge's sweep running concurrently with a send would reap a just-sent image. It
// drives the real filing seam (deliverGroupImageInboundLocked) plus the under-lock
// full Put that handleSendGroupImage does.
func TestSweepKeepsSentGroupImageBlobs(t *testing.T) {
	s, _ := syncPrimary(t)
	full := randomID()
	fullHash := []byte("full-hash-of-the-image")
	gm := protocol.GroupMessage{
		GroupID: "g", Author: s.myAccount, At: time.Unix(1000, 0),
		Thumb: bytes.Repeat([]byte{0x22}, 256), ThumbMime: "image/jpeg",
		FullID: full, FullHash: fullHash, FullMime: "image/jpeg", FullSize: 4096,
		Sig: []byte("sig"),
	}

	s.sessMu.Lock()
	// Mirror handleSendGroupImage: the full blob Put and the row filing happen under
	// one hold, so the blob is never on disk without its row.
	if err := s.attach.Put(full, bytes.Repeat([]byte{0x33}, 4096)); err != nil {
		s.sessMu.Unlock()
		t.Fatal(err)
	}
	if !s.deliverGroupImageInboundLocked(gm, false) {
		s.sessMu.Unlock()
		t.Fatal("own group image was not filed")
	}
	thumbID := groupThumbID(fullHash)
	if !s.attach.Has(full) || !s.attach.Has(thumbID) {
		s.sessMu.Unlock()
		t.Fatalf("blobs missing right after filing: full=%v thumb=%v", s.attach.Has(full), s.attach.Has(thumbID))
	}
	s.sweepOrphanAttachmentsLocked()
	s.sessMu.Unlock()

	if !s.attach.Has(full) {
		t.Error("sweep reaped a just-sent group image FULL blob (AttachID missing from keep-set)")
	}
	if !s.attach.Has(thumbID) {
		t.Error("sweep reaped a just-sent group image THUMBNAIL blob (ThumbID missing from keep-set)")
	}
}

// TestSweepNoopWhenNoRows pins the empty-store guard. len(s.messages)==0 almost always
// means a failed/empty load, not a genuine full delete, so the sweep must reclaim
// NOTHING against the empty keep-set rather than wipe a recoverable store.
func TestSweepNoopWhenNoRows(t *testing.T) {
	s, _ := syncPrimary(t)
	blob := randomID()

	s.sessMu.Lock()
	if err := s.attach.Put(blob, bytes.Repeat([]byte{0x44}, 128)); err != nil {
		s.sessMu.Unlock()
		t.Fatal(err)
	}
	// s.messages is empty here.
	s.sweepOrphanAttachmentsLocked()
	s.sessMu.Unlock()

	if !s.attach.Has(blob) {
		t.Fatal("sweep wiped a blob when there were no rows (empty-store guard failed)")
	}
}

// TestSweepKeepsSharedThumb: the same image sent to two groups yields two rows sharing
// a deterministic ThumbID. The keep-set is a set, so the shared thumbnail — and each
// row's distinct full — must all survive a sweep.
func TestSweepKeepsSharedThumb(t *testing.T) {
	s, _ := syncPrimary(t)
	sharedThumb := randomID()
	rowA := groupImageRow("a", "groupA", sharedThumb, "image/jpeg", 1)
	rowB := groupImageRow("b", "groupB", sharedThumb, "image/jpeg", 2)

	s.sessMu.Lock()
	for _, id := range []string{sharedThumb, rowA.AttachID, rowB.AttachID} {
		if err := s.attach.Put(id, bytes.Repeat([]byte{0x55}, 128)); err != nil {
			s.sessMu.Unlock()
			t.Fatal(err)
		}
	}
	s.messages = append(s.messages, rowA, rowB)
	s.sweepOrphanAttachmentsLocked()
	s.sessMu.Unlock()

	for _, id := range []string{sharedThumb, rowA.AttachID, rowB.AttachID} {
		if !s.attach.Has(id) {
			t.Errorf("sweep reaped referenced blob %s", id)
		}
	}
}
