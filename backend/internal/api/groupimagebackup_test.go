package api

import (
	"testing"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
)

// TestMissingGroupImagesLocked pins the row-selection that gates restore: only a
// group image (Kind image + a group id) with an attach id whose blob we lack is
// "missing". 1:1 images, text rows, rows without an attach id, and group images
// whose blob we already hold must all be excluded — otherwise restore either
// skips real gaps or lists the mailbox for blobs it can never match.
func TestMissingGroupImagesLocked(t *testing.T) {
	s, _ := syncPrimary(t)
	s.sessMu.Lock()
	defer s.sessMu.Unlock()

	have := randomID()
	if err := s.attach.Put(have, []byte("present")); err != nil {
		t.Fatal(err)
	}
	missing := randomID()

	s.messages = []chatMessage{
		{ID: "1", Kind: chatstore.KindImage, GroupID: "g", AttachID: missing, FullHash: []byte("h")}, // wanted
		{ID: "2", Kind: chatstore.KindImage, GroupID: "g", AttachID: have},                           // blob present → skip
		{ID: "3", Kind: chatstore.KindImage, GroupID: "", AttachID: randomID()},                      // 1:1 image → skip
		{ID: "4", Kind: "", GroupID: "g", AttachID: randomID()},                                      // text row → skip
		{ID: "5", Kind: chatstore.KindImage, GroupID: "g", AttachID: ""},                             // no attach id → skip
	}

	want := s.missingGroupImagesLocked()
	if len(want) != 1 {
		t.Fatalf("want exactly 1 missing image, got %d: %v", len(want), want)
	}
	if got, ok := want[missing]; !ok {
		t.Fatalf("the missing group image %s is not in the want set", missing)
	} else if string(got) != "h" {
		t.Fatalf("the author-signed hash was not carried through: got %q", got)
	}
}
