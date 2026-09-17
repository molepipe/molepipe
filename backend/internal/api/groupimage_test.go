package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/device"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

func groupWith(members ...*identity.Identity) chatstore.Group {
	g := chatstore.Group{ID: "gimg", Name: "Photos", Epoch: 1, Policy: chatstore.InvitePolicyAdmins}
	for i, m := range members {
		role := chatstore.GroupRoleMember
		if i == 0 {
			role = chatstore.GroupRoleAdmin
		}
		g.Members = append(g.Members, chatstore.GroupMember{Account: m.AccountNumber(), DHPub: dhBytes(m), Role: role})
	}
	return g
}

// authorHoldsGroupImage stores a full image on the author and files the outbound
// row, returning the gm to fan out and the full bytes + hash + id.
func authorHoldsGroupImage(t *testing.T, author *Server, authorID *identity.Identity) (protocol.GroupMessage, []byte, [32]byte, string) {
	t.Helper()
	full := bytes.Repeat([]byte{0xCD}, 300_000)
	sum := sha256.Sum256(full)
	thumb := bytes.Repeat([]byte{0x11}, 4000)
	fullID := randomID()
	author.sessMu.Lock()
	if err := author.attach.Put(fullID, full); err != nil {
		author.sessMu.Unlock()
		t.Fatal(err)
	}
	author.sessMu.Unlock()
	gm, err := protocol.NewGroupImageMessage(authorID, "gimg", thumb, "image/jpeg", fullID, sum[:], "image/png", len(full), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	author.sessMu.Lock()
	author.deliverGroupInboundLocked(gm, false)
	author.sessMu.Unlock()
	return gm, full, sum, fullID
}

// TestGroupImageSendReceiveDownload is the phase-B path: an author fans out a
// group image (thumbnail only), a member receives the blurry thumbnail + row, and
// then pulls the full bytes on demand and verifies them against the author-signed
// hash.
func TestGroupImageSendReceiveDownload(t *testing.T) {
	alice, aliceID := syncPrimary(t)
	bob, bobID := syncPrimary(t)
	g := groupWith(aliceID, bobID)
	injectGroup(t, alice, g)
	injectGroup(t, bob, g)
	alice.onion = &groupTestOnion{fakeOnion: &fakeOnion{}, dial: syncFakeDialer{addr: bob.pubLn.Addr().String()}}
	bob.onion = &groupTestOnion{fakeOnion: &fakeOnion{}, dial: syncFakeDialer{addr: alice.pubLn.Addr().String()}}

	gm, full, sum, fullID := authorHoldsGroupImage(t, alice, aliceID)
	alice.groupFanOut(aliceID, g, gm)

	// Bob received the thumbnail + an image row, but NOT the full image.
	thumbID := groupThumbID(sum[:])
	bob.sessMu.Lock()
	var row *chatMessage
	for i := range bob.messages {
		if bob.messages[i].Kind == chatstore.KindImage && bob.messages[i].GroupID == "gimg" {
			row = &bob.messages[i]
		}
	}
	store := bob.attach
	bob.sessMu.Unlock()
	if row == nil {
		t.Fatal("bob received no group image row")
	}
	if row.AttachID != fullID || row.ThumbID != thumbID || !bytes.Equal(row.FullHash, sum[:]) || row.Author != aliceID.AccountNumber() {
		t.Fatalf("bob's row is wrong: %+v", row)
	}
	gotThumb, err := store.Get(thumbID)
	if err != nil || !bytes.Equal(gotThumb, bytes.Repeat([]byte{0x11}, 4000)) {
		t.Fatal("bob's thumbnail is not byte-exact")
	}
	if store.Has(fullID) {
		t.Fatal("bob should not hold the full image before downloading")
	}

	// On-demand download from the author, verified against the signed hash.
	fetched, err := protocol.FetchGroupImage(context.Background(), bob.onion.Dialer(), bobID, aliceID.AccountNumber(), "gimg", fullID)
	if err != nil {
		t.Fatalf("fetch full image: %v", err)
	}
	if fsum := sha256.Sum256(fetched); !bytes.Equal(fsum[:], sum[:]) || !bytes.Equal(fetched, full) {
		t.Fatal("fetched full image is not byte-exact / hash mismatch")
	}
}

// TestGroupImageServeRejectsNonMember: the full-image serve endpoint is roster-
// gated — an account not in the group cannot pull the bytes even with a valid
// signature over its request.
func TestGroupImageServeRejectsNonMember(t *testing.T) {
	alice, aliceID := syncPrimary(t)
	stranger, strangerID := syncPrimary(t)
	g := groupWith(aliceID) // alice only; stranger is not a member
	injectGroup(t, alice, g)
	_, _, _, fullID := authorHoldsGroupImage(t, alice, aliceID)

	stranger.onion = &groupTestOnion{fakeOnion: &fakeOnion{}, dial: syncFakeDialer{addr: alice.pubLn.Addr().String()}}
	if _, err := protocol.FetchGroupImage(context.Background(), stranger.onion.Dialer(), strangerID, aliceID.AccountNumber(), "gimg", fullID); err == nil {
		t.Fatal("a non-member fetched a group full image")
	}
}

// TestGroupImageDeleteCleansBlobs: deleting a group image removes BOTH its blobs
// (thumbnail + full), which live under ids that are not the row id.
func TestGroupImageDeleteCleansBlobs(t *testing.T) {
	alice, aliceID := syncPrimary(t)
	injectGroup(t, alice, groupWith(aliceID))
	_, _, sum, fullID := authorHoldsGroupImage(t, alice, aliceID)
	thumbID := groupThumbID(sum[:])

	if !alice.attach.Has(fullID) || !alice.attach.Has(thumbID) {
		t.Fatal("group image blobs were not stored")
	}
	alice.sessMu.Lock()
	var row chatMessage
	for _, m := range alice.messages {
		if m.GroupID == "gimg" && m.Kind == chatstore.KindImage {
			row = m
		}
	}
	alice.deleteAttachmentsLocked(row)
	alice.sessMu.Unlock()

	if alice.attach.Has(fullID) || alice.attach.Has(thumbID) {
		t.Fatal("group image blobs orphaned after delete")
	}
}

// onionRouter routes an onion dial by its "<account>.onion:80" host: a mapped
// account reaches its listener; an unmapped one (or one mapped to "") is offline.
type onionRouter map[string]string

func (r onionRouter) DialOnion(_ context.Context, onion string) (net.Conn, error) {
	if addr, ok := r[onion]; ok && addr != "" {
		return net.Dial("tcp", addr)
	}
	return nil, fmt.Errorf("holder offline: %s", onion)
}

// twoDeviceGroupImage builds two servers that SHARE one identity (account): a
// primary that holds a foreign-authored group image's full bytes, and a second
// device (role set by the caller) that holds the row + thumbnail but not the
// full. The second device's dialer reaches the (offline) author nowhere and its
// own account onion at the primary. Returns the second device, the shared
// identity, the row id, the full id, and the full bytes.
func twoDeviceGroupImage(t *testing.T, role device.Role) (*Server, *identity.Identity, string, string, []byte) {
	t.Helper()
	primary, pw := newTestServer(t)
	ourID, err := primary.store.Load([]byte(pw))
	if err != nil {
		t.Fatal(err)
	}
	primary.startSession(ourID)
	t.Cleanup(primary.clearSession)

	dev, _ := newTestServer(t)
	dev.startSession(ourID) // same identity, separate (empty) blob store
	t.Cleanup(dev.clearSession)

	carolID, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	// The group has our own account (a member, so the primary will seal the full
	// to us) and Carol, the author.
	g := chatstore.Group{ID: "gimg", Name: "Photos", Epoch: 1, Policy: chatstore.InvitePolicyAdmins}
	g.Members = append(g.Members,
		chatstore.GroupMember{Account: ourID.AccountNumber(), DHPub: dhBytes(ourID), Role: chatstore.GroupRoleAdmin},
		chatstore.GroupMember{Account: carolID.AccountNumber(), DHPub: dhBytes(carolID), Role: chatstore.GroupRoleMember},
	)
	injectGroup(t, primary, g)
	injectGroup(t, dev, g)

	full := bytes.Repeat([]byte{0xAB}, 250_000)
	sum := sha256.Sum256(full)
	thumb := bytes.Repeat([]byte{0x22}, 3000)
	fullID := randomID()
	gm, err := protocol.NewGroupImageMessage(carolID, "gimg", thumb, "image/jpeg", fullID, sum[:], "image/png", len(full), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Both devices receive the row + thumbnail; only the primary holds the full.
	for _, srv := range []*Server{primary, dev} {
		srv.sessMu.Lock()
		srv.deliverGroupInboundLocked(gm, false)
		srv.sessMu.Unlock()
	}
	primary.sessMu.Lock()
	if err := primary.attach.Put(fullID, full); err != nil {
		primary.sessMu.Unlock()
		t.Fatal(err)
	}
	primary.sessMu.Unlock()

	var rowID string
	dev.sessMu.Lock()
	for _, m := range dev.messages {
		if m.GroupID == "gimg" && m.Kind == chatstore.KindImage {
			rowID = m.ID
		}
	}
	dev.sessMu.Unlock()
	if rowID == "" {
		t.Fatal("group image row was not filed on the second device")
	}

	dev.devMu.Lock()
	dev.device = &device.Config{Role: role}
	dev.devMu.Unlock()
	dev.onion = &groupTestOnion{fakeOnion: &fakeOnion{}, dial: onionRouter{
		carolID.AccountNumber() + ".onion:80": "",                            // author offline
		ourID.AccountNumber() + ".onion:80":   primary.pubLn.Addr().String(), // own onion -> primary
	}}
	return dev, ourID, rowID, fullID, full
}

func downloadGroupImage(t *testing.T, s *Server, id *identity.Identity, rowID string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"group": "gimg", "id": rowID})
	req := httptest.NewRequest(http.MethodPost, "/api/group/image/download", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleDownloadGroupImage(rec, req, id)
	return rec
}

// TestGroupImageDownloadFallsBackToOwnPrimary: when the author is offline, a
// secondary that lacks a group image's full bytes fetches them from its OWN
// primary (which holds them), over the same holder-gated serve path — verified
// against the author-signed hash before storing. This is the "it's on my other
// device, just get it" path for foreign-authored group images.
func TestGroupImageDownloadFallsBackToOwnPrimary(t *testing.T) {
	dev, ourID, rowID, fullID, full := twoDeviceGroupImage(t, device.RoleSecondary)
	if dev.attach.Has(fullID) {
		t.Fatal("secondary should not hold the full before downloading")
	}
	rec := downloadGroupImage(t, dev, ourID, rowID)
	if rec.Code != http.StatusOK {
		t.Fatalf("download failed: %d %s", rec.Code, rec.Body.String())
	}
	got, err := dev.attach.Get(fullID)
	if err != nil || !bytes.Equal(got, full) {
		t.Fatalf("secondary did not store the full byte-exact after fallback (err=%v)", err)
	}
}

// TestGroupImageDownloadNoFallbackForPrimary: the own-primary fallback is for
// secondaries only — a primary never dials its own onion (that reaches no other
// device), so with the author offline the download fails honestly instead of
// wasting a self-dial.
func TestGroupImageDownloadNoFallbackForPrimary(t *testing.T) {
	dev, ourID, rowID, fullID, _ := twoDeviceGroupImage(t, device.RolePrimary)
	rec := downloadGroupImage(t, dev, ourID, rowID)
	if rec.Code == http.StatusOK {
		t.Fatalf("a primary should not fall back to its own onion; got %d %s", rec.Code, rec.Body.String())
	}
	if dev.attach.Has(fullID) {
		t.Fatal("primary fetched the full despite the no-self-dial guard")
	}
}
