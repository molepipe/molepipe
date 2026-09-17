package api

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
)

func acceptContact(s *Server, account string) {
	s.sessMu.Lock()
	s.contacts[account] = chatstore.Contact{Account: account, Status: chatstore.StatusAccepted}
	s.sessMu.Unlock()
}

func imageMsgID(s *Server, dir string) (string, bool) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	for _, m := range s.messages {
		if m.Kind == chatstore.KindImage && m.Direction == dir {
			return m.ID, true
		}
	}
	return "", false
}

// TestImageSendReceive walks the phase-B path over the in-process routing: alice
// sends an image to bob (direct), bob verifies+stores+files it, alice's message
// flips to delivered, and the stored blob is served back through the attachment
// endpoint.
func TestImageSendReceive(t *testing.T) {
	alice, aliceID := syncPrimary(t)
	bob, bobID := syncPrimary(t)
	acceptContact(alice, bobID.AccountNumber())
	acceptContact(bob, aliceID.AccountNumber())
	alice.onion = routeTo(bob)

	img := make([]byte, 20000)
	_, _ = rand.Read(img)
	body := `{"to":"` + bobID.AccountNumber() + `","mime":"image/png","data":"` + base64.StdEncoding.EncodeToString(img) + `"}`
	w := httptest.NewRecorder()
	alice.handleSendImage(w, httptest.NewRequest("POST", "/api/messages/image", strings.NewReader(body)), aliceID)
	if w.Code != 200 {
		t.Fatalf("send image failed: %d %s", w.Code, w.Body)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	id := resp["id"].(string)

	// Alice stored the blob locally right away.
	if !alice.attach.Has(id) {
		t.Fatal("sender did not store its own attachment")
	}
	// Bob receives it over the (async) direct send.
	waitFor(t, 3*time.Second, func() bool {
		rid, ok := imageMsgID(bob, "in")
		return ok && rid == id && bob.attach.Has(id)
	})
	// Alice's message flips from pending to delivered.
	waitFor(t, 3*time.Second, func() bool {
		alice.sessMu.Lock()
		defer alice.sessMu.Unlock()
		for _, m := range alice.messages {
			if m.ID == id {
				return m.Delivery == ""
			}
		}
		return false
	})

	// Bob can serve the decrypted image back, with the right content type.
	gw := httptest.NewRecorder()
	bob.handleGetAttachment(gw, httptest.NewRequest("GET", "/api/attachment?id="+id, nil), bobID)
	if gw.Code != 200 {
		t.Fatalf("serve attachment failed: %d", gw.Code)
	}
	if ct := gw.Header().Get("Content-Type"); ct != "image/png" {
		t.Fatalf("wrong content type: %q", ct)
	}
	if gw.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing nosniff on served image")
	}
	if !bytes.Equal(gw.Body.Bytes(), img) {
		t.Fatal("served image bytes differ from what was sent")
	}
}

// TestImageDeleteRemovesBlob: deleting an image message (its tombstone) removes
// the blob, so a multi-MB file never outlives its row.
func TestImageDeleteRemovesBlob(t *testing.T) {
	me, _ := syncPrimary(t)
	id := "0123456789abcdef0123456789abcdef"
	if err := me.attach.Put(id, []byte("image bytes")); err != nil {
		t.Fatal(err)
	}
	me.sessMu.Lock()
	me.messages = append(me.messages, chatMessage{
		Direction: "out", Peer: "peer", ID: id, Kind: chatstore.KindImage, AttachID: id, Mime: "image/png",
	})
	me.deleteTombstone(id) // the choke point every delete passes through
	me.sessMu.Unlock()

	if me.attach.Has(id) {
		t.Fatal("blob survived its message's tombstone")
	}
}
