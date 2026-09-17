package protocol

import (
	"bytes"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

func attachPeer(t *testing.T, allowSender bool) (*Peer, *identity.Identity, *identity.Identity) {
	t.Helper()
	alice, _ := identity.New()
	bob, _ := identity.New()
	allow := func(a string) bool { return allowSender && a == alice.AccountNumber() }
	peer := NewPeer(bob, msgHooks(allow, make(chan [2]string, 1)))
	return peer, alice, bob
}

func sealFor(t *testing.T, peer *Peer, from *identity.Identity, to string, msgID, mime string, data []byte) (AttachmentEnvelope, error) {
	t.Helper()
	ch := peer.Challenge()
	var dh [32]byte
	copy(dh[:], ch.DHPub)
	return SealAttachment(from, to, dh, ch.Nonce, msgID, mime, data)
}

// TestAttachmentRoundTrip: a sealed image from an accepted contact decrypts back
// to the exact bytes, id and MIME.
func TestAttachmentRoundTrip(t *testing.T) {
	peer, alice, bob := attachPeer(t, true)
	img := bytes.Repeat([]byte{0xAB, 0x12, 0x00, 0xFF}, 4096) // 16 KiB of "image"
	env, err := sealFor(t, peer, alice, bob.AccountNumber(), "msg-1", "image/png", img)
	if err != nil {
		t.Fatal(err)
	}
	id, mime, data, err := peer.ReceiveAttachment(env)
	if err != nil {
		t.Fatal(err)
	}
	if id != "msg-1" || mime != "image/png" || !bytes.Equal(data, img) {
		t.Fatalf("round trip mismatch: id=%s mime=%s len=%d", id, mime, len(data))
	}
}

// TestAttachmentSizeCap: the sender refuses an over-cap image before it ever
// hits the wire.
func TestAttachmentSizeCap(t *testing.T) {
	peer, alice, bob := attachPeer(t, true)
	if _, err := sealFor(t, peer, alice, bob.AccountNumber(), "m", "image/jpeg", make([]byte, MaxAttachmentBytes+1)); err == nil {
		t.Fatal("an over-cap attachment was sealed")
	}
}

// TestAttachmentMIMEAllowlist: a non-image type is refused on both seal and
// receive (so no endpoint can be tricked into serving attacker HTML as an image).
func TestAttachmentMIMEAllowlist(t *testing.T) {
	peer, alice, bob := attachPeer(t, true)
	if _, err := sealFor(t, peer, alice, bob.AccountNumber(), "m", "text/html", []byte("<script>")); err == nil {
		t.Fatal("a non-image MIME was sealed")
	}
	// A valid seal whose MIME is then tampered to text/html is rejected on receipt.
	env, err := sealFor(t, peer, alice, bob.AccountNumber(), "m", "image/png", []byte("PNGDATA"))
	if err != nil {
		t.Fatal(err)
	}
	env.Mime = "text/html"
	if _, _, _, err := peer.ReceiveAttachment(env); err == nil {
		t.Fatal("a tampered-MIME attachment was accepted")
	}
}

// TestAttachmentNonContactRejected: an image from a non-contact is refused (same
// contacts-only gate as text).
func TestAttachmentNonContactRejected(t *testing.T) {
	peer, alice, bob := attachPeer(t, false)
	env, err := sealFor(t, peer, alice, bob.AccountNumber(), "m", "image/png", []byte("PNGDATA"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := peer.ReceiveAttachment(env); err == nil {
		t.Fatal("an image from a non-contact was accepted")
	}
}

// TestAttachmentTamperAndReplay: a flipped signature is rejected, and a nonce is
// single-use (replay refused).
func TestAttachmentTamperAndReplay(t *testing.T) {
	peer, alice, bob := attachPeer(t, true)

	env, _ := sealFor(t, peer, alice, bob.AccountNumber(), "m", "image/png", []byte("PNGDATA"))
	bad := env
	bad.Sig = append([]byte(nil), env.Sig...)
	bad.Sig[0] ^= 0xFF
	if _, _, _, err := peer.ReceiveAttachment(bad); err == nil {
		t.Fatal("a tampered signature was accepted")
	}

	env2, _ := sealFor(t, peer, alice, bob.AccountNumber(), "m2", "image/png", []byte("PNGDATA2"))
	if _, _, _, err := peer.ReceiveAttachment(env2); err != nil {
		t.Fatalf("first receive failed: %v", err)
	}
	if _, _, _, err := peer.ReceiveAttachment(env2); err == nil {
		t.Fatal("a replayed attachment (reused nonce) was accepted")
	}
}
