package api

import (
	"bytes"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
)

// The ungated AvatarPath must serve ONLY our own avatar, never an arbitrary hash
// in the store — the store also caches CONTACTS' avatars, so serving those by
// hash would let an anonymous caller over Tor learn from 200-vs-404 whether we
// have a given person as a contact (a social-graph oracle, the same class of
// leak the gated mailbox change closed). This hits the real handler, since the
// gate lives in handleP2PAvatar, not in the store.
func TestP2PAvatarServesOnlyOwn(t *testing.T) {
	s, _ := mailboxTestServer(t, "127.0.0.1:1")
	// A real, detectable image so the 200 path can set a Content-Type.
	own := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0, 1, 1, 0}
	ownHash := chatstore.AvatarHashBytes(own)
	// A contact's cached avatar — different bytes, different hash — as a presence
	// sweep or lookup would have stored it.
	contact := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0, 1, 1, 9}
	contactHash := chatstore.AvatarHashBytes(contact)

	s.sessMu.Lock()
	if err := s.avatarStore.Put(ownHash, own); err != nil {
		t.Fatal(err)
	}
	if err := s.avatarStore.Put(contactHash, contact); err != nil {
		t.Fatal(err)
	}
	s.avatarHash = ownHash
	s.sessMu.Unlock()

	get := func(h string) int {
		rec := httptest.NewRecorder()
		s.handleP2PAvatar(rec, httptest.NewRequest("GET", "/p2p/avatar?h="+h, nil))
		return rec.Code
	}

	if code := get(ownHash); code != 200 {
		t.Errorf("own avatar: got %d, want 200", code)
	}
	if code := get(contactHash); code != 404 {
		t.Errorf("contact avatar leaked via ungated endpoint: got %d, want 404 (social-graph oracle)", code)
	}
	if code := get(""); code != 404 {
		t.Errorf("empty hash: got %d, want 404", code)
	}
}

// Cross-device own-avatar: bytes ride chatstore.Profile over /sync (Profile swaps
// as a whole unit on UpdatedAt, so hash and bytes never desync). Adopting such a
// Profile must land the bytes in THIS device's avatar store (so it can serve and
// render its own face by hash), and a subsequent snapshot must carry them back
// out for the next sync round.
func TestAdoptOwnAvatarRoundTrips(t *testing.T) {
	s, _ := mailboxTestServer(t, "127.0.0.1:1")
	data := []byte("\xFF\xD8\xFF\xE0 a jpeg-ish own avatar")
	hash := chatstore.AvatarHashBytes(data)

	s.sessMu.Lock()
	s.adoptDataLocked(&chatstore.Data{Profile: chatstore.Profile{
		AvatarHash: hash, AvatarBytes: data, UpdatedAt: time.Now(),
	}})
	hasIt := s.avatarStore.Has(hash)
	gotHash := s.avatarHash
	snap := s.snapshotLocked()
	s.sessMu.Unlock()

	if !hasIt {
		t.Error("adopted own-avatar bytes were not written to the avatar store")
	}
	if gotHash != hash {
		t.Errorf("avatarHash = %q, want %q", gotHash, hash)
	}
	if !bytes.Equal(snap.Profile.AvatarBytes, data) {
		t.Error("snapshot did not carry own-avatar bytes back out for the next sync")
	}
	if snap.Profile.AvatarHash != hash {
		t.Errorf("snapshot avatar_hash = %q, want %q", snap.Profile.AvatarHash, hash)
	}
}

// avatarContentType must recognize all four allowlisted formats from their magic
// bytes alone (never a client-declared string). WebP is the one the advisor
// flagged: http.DetectContentType only returns "image/webp" for a well-formed
// RIFF/WEBP header, and the client crop pipeline most likely emits WebP or PNG,
// so a silent mis-detection here would reject exactly what the picker produces.
func TestAvatarContentTypeDetectsAllowedFormats(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"jpeg", []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F'}, "image/jpeg"},
		{"png", []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0}, "image/png"},
		{"gif", []byte("GIF89a\x01\x00\x01\x00"), "image/gif"},
		// Go's webp matcher keys on "RIFF"+size+"WEBPVP" (14 bytes), not just
		// "WEBP" — a real webp from any encoder (canvas included) always carries a
		// VP8/VP8L/VP8X chunk, so this mirrors a genuine file, not a stub header.
		{"webp", append([]byte("RIFF\x1a\x00\x00\x00WEBPVP8 "), make([]byte, 8)...), "image/webp"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := avatarContentType(c.data)
			if !ok {
				t.Fatalf("%s: not detected as an allowed image type", c.name)
			}
			if got != c.want {
				t.Fatalf("%s: detected %q, want %q", c.name, got, c.want)
			}
		})
	}
}

// A non-image (or a disguised HTML payload) must be rejected, so the ungated
// endpoint can never be tricked into serving an attacker-chosen Content-Type.
func TestAvatarContentTypeRejectsNonImage(t *testing.T) {
	for _, bad := range [][]byte{
		[]byte("<html><script>alert(1)</script>"),
		[]byte("plain text"),
		[]byte("%PDF-1.4"),
		nil,
	} {
		if _, ok := avatarContentType(bad); ok {
			t.Errorf("accepted non-image payload %q", bad)
		}
	}
}

// The avatar store is content-addressed and never evicts, so an avatar no longer
// referenced by our own profile or any contact (a contact rotated their picture,
// or we changed ours) must be reclaimed by the sweep — otherwise superseded bytes
// accumulate until they fill the 32 MiB cap and Put starts failing for everything,
// including setting our own avatar (the "walled-off store" failure).
func TestSweepOrphanAvatarsReclaimsUnreferenced(t *testing.T) {
	s, _ := mailboxTestServer(t, "127.0.0.1:1")
	own := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0, 1, 1, 0}
	ownHash := chatstore.AvatarHashBytes(own)
	contact := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0, 1, 1, 9}
	contactHash := chatstore.AvatarHashBytes(contact)
	// A superseded avatar — the bytes a contact used before rotating their picture —
	// that nothing references any more.
	orphan := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0, 1, 1, 7}
	orphanHash := chatstore.AvatarHashBytes(orphan)
	// A PENDING (not yet accepted) contact whose avatar was cached at add-time via
	// handleLookup. The keep-set must span every status, not just accepted, or the
	// sweep would reap the add-time face preview before the request is accepted.
	pending := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0, 1, 1, 3}
	pendingHash := chatstore.AvatarHashBytes(pending)

	s.sessMu.Lock()
	for _, a := range [][]byte{own, contact, orphan, pending} {
		if err := s.avatarStore.Put(chatstore.AvatarHashBytes(a), a); err != nil {
			t.Fatal(err)
		}
	}
	s.avatarHash = ownHash
	s.contacts["peer"] = chatstore.Contact{Account: "peer", Status: chatstore.StatusAccepted, AvatarHash: contactHash}
	s.contacts["req"] = chatstore.Contact{Account: "req", Status: chatstore.StatusPendingOut, AvatarHash: pendingHash}
	s.sweepOrphanAvatarsLocked()
	haveOwn := s.avatarStore.Has(ownHash)
	haveContact := s.avatarStore.Has(contactHash)
	havePending := s.avatarStore.Has(pendingHash)
	haveOrphan := s.avatarStore.Has(orphanHash)
	s.sessMu.Unlock()

	if !haveOwn {
		t.Error("own avatar was reclaimed but is still referenced by our profile")
	}
	if !haveContact {
		t.Error("contact avatar was reclaimed but is still referenced by a contact")
	}
	if !havePending {
		t.Error("pending contact's add-time avatar was reclaimed (keep-set must span all statuses)")
	}
	if haveOrphan {
		t.Error("orphaned avatar was NOT reclaimed (store would wall off at the cap)")
	}
}

func TestTokenBucketLimits(t *testing.T) {
	b := newTokenBucket(1000, 3) // 3 burst
	if !b.allow() || !b.allow() || !b.allow() {
		t.Fatal("burst of 3 should be allowed")
	}
	if b.allow() {
		t.Fatal("4th immediate request should be denied")
	}
	// After refill time, at least one more is allowed (1000/sec => ~1ms per token).
	time.Sleep(5 * time.Millisecond)
	if !b.allow() {
		t.Fatal("token should have refilled")
	}
}
