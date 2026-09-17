package protocol

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

func fakeFull(t *testing.T, n int) (data []byte, hash []byte) {
	t.Helper()
	data = bytes.Repeat([]byte{0x5a}, n)
	h := sha256.Sum256(data)
	return data, h[:]
}

func TestGroupImageRoundTrip(t *testing.T) {
	author, _ := identity.New()
	member, _ := identity.New()
	thumb := bytes.Repeat([]byte{0x11}, 4000)
	full, hash := fakeFull(t, 500_000)

	gm, err := NewGroupImageMessage(author, "grp1", thumb, "image/jpeg", "abc123", hash, "image/png", len(full), time.Unix(1000, 0))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	env, err := SealGroupMessage(author, gm, member.AccountNumber(), member.Keys.DH.Public)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := OpenGroupEnvelope(member, env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !got.isImage() || got.Author != author.AccountNumber() || got.FullID != "abc123" ||
		got.FullMime != "image/png" || got.FullSize != len(full) ||
		!bytes.Equal(got.Thumb, thumb) || !bytes.Equal(got.FullHash, hash) {
		t.Fatalf("image fields did not round-trip: %+v", got)
	}
}

// TestGroupImageSignatureCoversContent is the security property: the author
// signature covers the thumbnail AND the full-image hash, so a forwarding member
// can substitute neither — in particular they cannot serve a different full image
// behind the thumbnail the group already saw.
func TestGroupImageSignatureCoversContent(t *testing.T) {
	author, _ := identity.New()
	thumb := bytes.Repeat([]byte{0x11}, 4000)
	_, hash := fakeFull(t, 500_000)
	gm, err := NewGroupImageMessage(author, "grp1", thumb, "image/jpeg", "abc123", hash, "image/png", 500_000, time.Unix(1000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !gm.Verify() {
		t.Fatal("a freshly signed image message should verify")
	}
	// Swap the full-image hash (what a malicious server would do to serve a
	// different image) — verification must fail.
	tampered := gm
	_, otherHash := fakeFull(t, 400_000)
	tampered.FullHash = otherHash
	if tampered.Verify() {
		t.Fatal("substituting the full-image hash still verified")
	}
	// Tamper the thumbnail — must fail too.
	tampered = gm
	tampered.Thumb = bytes.Repeat([]byte{0x22}, 4000)
	if tampered.Verify() {
		t.Fatal("tampering the thumbnail still verified")
	}
}

// TestGroupImageCapsOnOpen: a member who forges an oversize thumbnail or bad MIME
// (re-sealing after tampering) is rejected on open, before verification even.
func TestGroupImageCapsOnOpen(t *testing.T) {
	author, _ := identity.New()
	member, _ := identity.New()
	_, hash := fakeFull(t, 500_000)

	// Build a legit message, then re-seal a mutated copy from a "malicious carrier"
	// (still the author here — we only need OpenGroupEnvelope to reject on caps).
	good, _ := NewGroupImageMessage(author, "grp1", bytes.Repeat([]byte{1}, 4000), "image/jpeg", "abc123", hash, "image/png", 500_000, time.Unix(1000, 0))

	oversize := good
	oversize.Thumb = bytes.Repeat([]byte{1}, MaxGroupThumbBytes+1)
	if _, err := SealGroupMessage(author, oversize, member.AccountNumber(), member.Keys.DH.Public); err == nil {
		t.Fatal("sealed an oversize thumbnail")
	}
	badMime := good
	badMime.FullMime = "text/html"
	badMime.Sig = nil // it would fail Verify anyway; we're checking the open-side cap
	env, _ := SealGroupMessage(author, badMime, member.AccountNumber(), member.Keys.DH.Public)
	if _, err := OpenGroupEnvelope(member, env); err == nil {
		t.Fatal("opened a message with a disallowed full-image MIME")
	}
}

func TestNewGroupImageMessageRejectsBad(t *testing.T) {
	author, _ := identity.New()
	_, hash := fakeFull(t, 100)
	thumb := bytes.Repeat([]byte{1}, 4000)
	cases := []struct {
		name                       string
		thumb                      []byte
		thumbMime, fullID, fullMim string
		hash                       []byte
		size                       int
	}{
		{"oversize-thumb", bytes.Repeat([]byte{1}, MaxGroupThumbBytes+1), "image/jpeg", "id", "image/png", hash, 100},
		{"empty-thumb", nil, "image/jpeg", "id", "image/png", hash, 100},
		{"bad-thumb-mime", thumb, "text/html", "id", "image/png", hash, 100},
		{"bad-full-mime", thumb, "image/jpeg", "id", "application/zip", hash, 100},
		{"empty-full-id", thumb, "image/jpeg", "", "image/png", hash, 100},
		{"bad-hash", thumb, "image/jpeg", "id", "image/png", []byte{1, 2, 3}, 100},
		{"zero-size", thumb, "image/jpeg", "id", "image/png", hash, 0},
		{"oversize-full", thumb, "image/jpeg", "id", "image/png", hash, MaxAttachmentBytes + 1},
	}
	for _, c := range cases {
		if _, err := NewGroupImageMessage(author, "grp1", c.thumb, c.thumbMime, c.fullID, c.hash, c.fullMim, c.size, time.Now()); err == nil {
			t.Errorf("%s: expected rejection", c.name)
		}
	}
}
