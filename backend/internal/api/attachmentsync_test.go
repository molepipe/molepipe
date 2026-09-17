package api

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

func imageRow(id, mime string, at int64) chatMessage {
	return chatMessage{Direction: "in", Peer: "c", At: time.Unix(at, 0), ID: id,
		Kind: chatstore.KindImage, AttachID: id, Mime: mime, Size: 256}
}

func sliceHas(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestAttachmentSyncPullAndPush drives the real /sync/attachment endpoint from an
// enrolled secondary: it pulls a blob the primary holds, and pushes a blob for a
// row the primary has but lacks. Both directions are byte-exact.
func TestAttachmentSyncPullAndPush(t *testing.T) {
	primary, id := syncPrimary(t)
	dialer := syncFakeDialer{addr: primary.pubLn.Addr().String()}
	secPub, secSign := newDeviceKey(t)

	haveID := randomID() // primary holds this blob; secondary pulls it
	needID := randomID() // primary has the row but no blob; secondary pushes it
	haveBytes := bytes.Repeat([]byte{0x11}, 4096)
	pushBytes := bytes.Repeat([]byte{0x22}, 8192)

	primary.sessMu.Lock()
	primary.devices = append(primary.devices, chatstore.Device{PubKey: secPub, Name: "secondary", AddedAt: time.Now()})
	if err := primary.attach.Put(haveID, haveBytes); err != nil {
		primary.sessMu.Unlock()
		t.Fatal(err)
	}
	primary.messages = append(primary.messages,
		chatMessage{Direction: "in", Peer: "contactA", At: time.Unix(1000, 0), ID: haveID, Kind: chatstore.KindImage, AttachID: haveID, Mime: "image/png", Size: len(haveBytes)},
		chatMessage{Direction: "out", Peer: "contactA", At: time.Unix(2000, 0), ID: needID, Kind: chatstore.KindImage, AttachID: needID, Mime: "image/jpeg", Size: len(pushBytes)},
	)
	primary.persistLocked()
	primary.sessMu.Unlock()

	// Round 1: request the blob we lack.
	provide, need, err := protocol.AttachmentSyncExchange(context.Background(), dialer, id, secPub, secSign, []string{haveID}, nil)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(provide) != 1 || provide[0].ID != haveID || !bytes.Equal(provide[0].Data, haveBytes) {
		t.Fatalf("provide mismatch: got %d blobs", len(provide))
	}
	if !sliceHas(need, needID) || sliceHas(need, haveID) {
		t.Fatalf("need = %v; want it to list %s (missing blob) but not %s (present)", need, needID, haveID)
	}

	// Round 2: push the blob the primary needs.
	if _, _, err := protocol.AttachmentSyncExchange(context.Background(), dialer, id, secPub, secSign, nil,
		[]protocol.AttachmentBlob{{ID: needID, Mime: "image/jpeg", Data: pushBytes}}); err != nil {
		t.Fatalf("push exchange: %v", err)
	}
	got, err := primary.attach.Get(needID)
	if err != nil || !bytes.Equal(got, pushBytes) {
		t.Fatalf("primary did not store the pushed blob byte-exact (err=%v)", err)
	}

	// The primary no longer needs it.
	if _, need2, _ := protocol.AttachmentSyncExchange(context.Background(), dialer, id, secPub, secSign, nil, nil); sliceHas(need2, needID) {
		t.Fatalf("primary still lists %s in need after the push", needID)
	}
}

// groupImageRow is a group-image row: the full lives under a random AttachID
// (moved via the mailbox self-backup, never this path), the blurry thumbnail
// under ThumbID (the only blob this path carries for a group image).
func groupImageRow(id, group, thumbID, thumbMime string, at int64) chatMessage {
	return chatMessage{Direction: "in", GroupID: group, At: time.Unix(at, 0), ID: id,
		Kind: chatstore.KindImage, AttachID: randomID(), Mime: "image/jpeg",
		ThumbID: thumbID, ThumbMime: thumbMime, FullHash: []byte("h")}
}

// TestSyncBlobIDForRow pins the row→blob-id mapping the want/need lists and the
// resolve gate both draw from: 1:1 → the full (AttachID == ID), group → the
// thumbnail (ThumbID, never the on-demand full), non-image → nothing.
func TestSyncBlobIDForRow(t *testing.T) {
	full := randomID()
	thumb := randomID()
	cases := []struct {
		name string
		m    chatMessage
		want string
	}{
		{"1:1 image", imageRow(full, "image/png", 1), full},
		{"group image", groupImageRow("gid", "g", thumb, "image/jpeg", 2), thumb},
		{"text row", chatMessage{ID: "t", GroupID: "g"}, ""},
		{"group image, no thumb id yet", chatMessage{Kind: chatstore.KindImage, GroupID: "g", AttachID: randomID()}, ""},
	}
	for _, c := range cases {
		if got := syncBlobIDForRow(c.m); got != c.want {
			t.Errorf("%s: syncBlobIDForRow = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestResolveSyncBlobLocked pins the dual gate: a 1:1 full resolves at the 3 MiB
// cap with the row MIME, a group thumbnail at the 16 KiB cap with the THUMB
// MIME, a group image's on-demand full id does NOT resolve (it never moves over
// this path), and an unknown id is rejected.
func TestResolveSyncBlobLocked(t *testing.T) {
	s, _ := syncPrimary(t)
	oneToOne := randomID()
	thumb := randomID()
	grp := groupImageRow("gid", "g", thumb, "image/webp", 2)

	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	s.messages = append(s.messages, imageRow(oneToOne, "image/png", 1), grp)

	if mime, max, ok := s.resolveSyncBlobLocked(oneToOne); !ok || mime != "image/png" || max != protocol.MaxAttachmentBytes {
		t.Fatalf("1:1 full: got (%q, %d, %v); want (image/png, %d, true)", mime, max, ok, protocol.MaxAttachmentBytes)
	}
	if mime, max, ok := s.resolveSyncBlobLocked(thumb); !ok || mime != "image/webp" || max != protocol.MaxGroupThumbBytes {
		t.Fatalf("group thumb: got (%q, %d, %v); want (image/webp, %d, true)", mime, max, ok, protocol.MaxGroupThumbBytes)
	}
	if _, _, ok := s.resolveSyncBlobLocked(grp.AttachID); ok {
		t.Fatal("a group image's on-demand full id must NOT resolve on the device-sync path")
	}
	if _, _, ok := s.resolveSyncBlobLocked(randomID()); ok {
		t.Fatal("an unknown id must not resolve")
	}
	if _, _, ok := s.resolveSyncBlobLocked(""); ok {
		t.Fatal("the empty id must not resolve (guards against matching a no-blob row)")
	}
}

// TestNeededAttachmentsGroupThumb: a secondary that has a group-image row but no
// thumbnail blob advertises the THUMB id in its need list — never the full's
// AttachID, which this path can never serve. The full's absence must not starve
// the thumb behind it.
func TestNeededAttachmentsGroupThumb(t *testing.T) {
	s, _ := syncPrimary(t)
	thumb := randomID()
	grp := groupImageRow("gid", "g", thumb, "image/jpeg", 1)

	s.sessMu.Lock()
	s.messages = append(s.messages, grp) // no thumb blob, no full blob stored
	s.sessMu.Unlock()

	need := s.neededAttachments()
	if !sliceHas(need, thumb) {
		t.Fatalf("need = %v; want it to advertise the thumb id %s", need, thumb)
	}
	if sliceHas(need, grp.AttachID) {
		t.Fatalf("need = %v; must NOT advertise the on-demand full id %s", need, grp.AttachID)
	}
}

// TestGroupThumbnailSyncEndToEnd drives the real endpoint: an enrolled secondary
// pulls a group image's thumbnail blob (16 KiB class) from the primary that
// holds it, byte-exact — the cross-device preview backfill.
func TestGroupThumbnailSyncEndToEnd(t *testing.T) {
	primary, id := syncPrimary(t)
	dialer := syncFakeDialer{addr: primary.pubLn.Addr().String()}
	secPub, secSign := newDeviceKey(t)

	thumbID := randomID()
	thumbBytes := bytes.Repeat([]byte{0x55}, 4096)

	primary.sessMu.Lock()
	primary.devices = append(primary.devices, chatstore.Device{PubKey: secPub, Name: "secondary", AddedAt: time.Now()})
	if err := primary.attach.Put(thumbID, thumbBytes); err != nil {
		primary.sessMu.Unlock()
		t.Fatal(err)
	}
	primary.messages = append(primary.messages, groupImageRow("gid", "g", thumbID, "image/jpeg", 1000))
	primary.persistLocked()
	primary.sessMu.Unlock()

	provide, _, err := protocol.AttachmentSyncExchange(context.Background(), dialer, id, secPub, secSign, []string{thumbID}, nil)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(provide) != 1 || provide[0].ID != thumbID || !bytes.Equal(provide[0].Data, thumbBytes) {
		t.Fatalf("group thumbnail not served byte-exact: got %d blobs", len(provide))
	}
}

// TestAttachmentSyncRejectsUnenrolledDevice: a caller with the real identity key
// but an unenrolled device cannot move blobs — the same second-factor property
// /sync has.
func TestAttachmentSyncRejectsUnenrolledDevice(t *testing.T) {
	primary, id := syncPrimary(t)
	dialer := syncFakeDialer{addr: primary.pubLn.Addr().String()}
	strangerPub, strangerSign := newDeviceKey(t) // never enrolled
	if _, _, err := protocol.AttachmentSyncExchange(context.Background(), dialer, id, strangerPub, strangerSign, []string{randomID()}, nil); err == nil {
		t.Fatal("unenrolled device was allowed to sync attachments")
	}
}

// TestAttachmentSyncGatesOnMessageRow: even an enrolled device can only move
// blobs that a real image row references — a blob with no row is never served,
// and a pushed blob with no row is never stored.
func TestAttachmentSyncGatesOnMessageRow(t *testing.T) {
	primary, id := syncPrimary(t)
	dialer := syncFakeDialer{addr: primary.pubLn.Addr().String()}
	secPub, secSign := newDeviceKey(t)

	orphan := randomID() // blob on disk but NO message row references it
	pushOrphan := randomID()
	primary.sessMu.Lock()
	primary.devices = append(primary.devices, chatstore.Device{PubKey: secPub, Name: "secondary", AddedAt: time.Now()})
	if err := primary.attach.Put(orphan, bytes.Repeat([]byte{0x33}, 1024)); err != nil {
		primary.sessMu.Unlock()
		t.Fatal(err)
	}
	primary.sessMu.Unlock()

	provide, _, err := protocol.AttachmentSyncExchange(context.Background(), dialer, id, secPub, secSign, []string{orphan}, nil)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(provide) != 0 {
		t.Fatalf("served %d blobs for an id with no message row; want 0", len(provide))
	}

	if _, _, err := protocol.AttachmentSyncExchange(context.Background(), dialer, id, secPub, secSign, nil,
		[]protocol.AttachmentBlob{{ID: pushOrphan, Mime: "image/png", Data: bytes.Repeat([]byte{0x44}, 1024)}}); err != nil {
		t.Fatalf("push exchange: %v", err)
	}
	if primary.attach.Has(pushOrphan) {
		t.Fatal("stored a pushed blob that no message row references")
	}
}

// TestAttachmentIngestProvidedGating covers the store-side gate for blobs pulled
// from the primary: a referenced-but-missing id is stored, an existing blob is
// never overwritten, an id with no image row is skipped, and a tombstoned id is
// refused even if a row is (artificially) still present.
func TestAttachmentIngestProvidedGating(t *testing.T) {
	s, _ := syncPrimary(t)
	refID, haveID, orphanID, tombID := randomID(), randomID(), randomID(), randomID()
	orig := bytes.Repeat([]byte{0xAA}, 512)

	s.sessMu.Lock()
	if err := s.attach.Put(haveID, orig); err != nil {
		s.sessMu.Unlock()
		t.Fatal(err)
	}
	s.messages = append(s.messages,
		imageRow(refID, "image/png", 1),
		imageRow(haveID, "image/png", 2),
		imageRow(tombID, "image/png", 3), // row present but...
	)
	s.deleted = append(s.deleted, tombID) // ...tombstoned
	s.sessMu.Unlock()

	s.ingestProvidedAttachments([]protocol.AttachmentBlob{
		{ID: refID, Mime: "image/png", Data: bytes.Repeat([]byte{0xBB}, 256)},
		{ID: haveID, Mime: "image/png", Data: bytes.Repeat([]byte{0xCC}, 256)}, // would overwrite
		{ID: orphanID, Mime: "image/png", Data: bytes.Repeat([]byte{0xDD}, 256)},
		{ID: tombID, Mime: "image/png", Data: bytes.Repeat([]byte{0xEE}, 256)},
	})

	if got, err := s.attach.Get(refID); err != nil || !bytes.Equal(got, bytes.Repeat([]byte{0xBB}, 256)) {
		t.Fatalf("referenced-missing blob not stored: err=%v", err)
	}
	if got, _ := s.attach.Get(haveID); !bytes.Equal(got, orig) {
		t.Fatal("existing blob was overwritten by a provided one")
	}
	if s.attach.Has(orphanID) {
		t.Fatal("stored a provided blob with no message row")
	}
	if s.attach.Has(tombID) {
		t.Fatal("stored a provided blob for a tombstoned id")
	}
}

// TestAttachmentIngestStopsOnStorageError proves the full-store branch: with the
// attachment dir blocked (a file where the dir must be, so every Put errors),
// ingest stores nothing and does not panic, rather than churning the same blob.
func TestAttachmentIngestStopsOnStorageError(t *testing.T) {
	s, _ := syncPrimary(t)
	// A file where <dir>/attachments should be makes Put's MkdirAll fail ("not a
	// directory") for every write — even when the test runs as root.
	if err := os.WriteFile(filepath.Join(s.store.Dir, "attachments"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, b := randomID(), randomID()
	s.sessMu.Lock()
	s.messages = append(s.messages, imageRow(a, "image/png", 1), imageRow(b, "image/png", 2))
	s.sessMu.Unlock()

	s.ingestProvidedAttachments([]protocol.AttachmentBlob{
		{ID: a, Mime: "image/png", Data: bytes.Repeat([]byte{1}, 128)},
		{ID: b, Mime: "image/png", Data: bytes.Repeat([]byte{2}, 128)},
	})
	if s.attach.Has(a) || s.attach.Has(b) {
		t.Fatal("a blob was stored despite the storage error")
	}
}
