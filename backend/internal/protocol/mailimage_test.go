package protocol

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/crypto"
	"github.com/molepipe/molepipe/backend/internal/identity"
)

// sealRawMailPayload seals an ARBITRARY plaintext into a valid, correctly-signed
// mail envelope, bypassing the seal-side checks — so a test can act as a
// malicious sender and prove the OPEN side re-enforces the caps and allowlist.
func sealRawMailPayload(t *testing.T, from *identity.Identity, recipient string, recipientDH [32]byte, pt []byte) MailEnvelope {
	t.Helper()
	shared, err := crypto.SharedSecret(from.Keys.DH.Private, recipientDH)
	if err != nil {
		t.Fatal(err)
	}
	key := crypto.DeriveDirectionalKey(shared, msgKeyInfo(from.AccountNumber(), recipient))
	box, err := crypto.SealMessage(key, pt, aad(from.AccountNumber(), recipient))
	if err != nil {
		t.Fatal(err)
	}
	myDH := from.Keys.DH.Public
	m := MailEnvelope{Recipient: recipient, Sender: from.AccountNumber(), SenderDHPub: myDH[:], SentAt: time.Now().Unix(), Box: box}
	m.Sig = ed25519.Sign(from.Keys.Signing.Private, m.signingBlob())
	return m
}

func TestMailImageRoundTrip(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	data := bytes.Repeat([]byte{0xAB}, 200_000)

	env, err := SealMailImageEnvelope(alice, bob.AccountNumber(), bob.Keys.DH.Public, "img-1", "image/png", data, time.Unix(1000, 0))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	c, err := OpenMailContent(bob, env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if c.Kind != MailKindImage || c.MsgID != "img-1" || c.Mime != "image/png" || !bytes.Equal(c.Data, data) {
		t.Fatalf("image round-trip mismatch: kind=%q id=%q mime=%q bytes=%d", c.Kind, c.MsgID, c.Mime, len(c.Data))
	}
	if c.Sender != alice.AccountNumber() {
		t.Fatalf("sender mismatch")
	}
}

// TestMailImageRejectedOnTextPath: the text-only OpenMailEnvelope (which the
// friend-relay path uses) must refuse an image, so images never travel via relay.
func TestMailImageRejectedOnTextPath(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	env, _ := SealMailImageEnvelope(alice, bob.AccountNumber(), bob.Keys.DH.Public, "img-1", "image/png", []byte{1, 2, 3, 4}, time.Unix(1000, 0))
	if _, _, _, _, err := OpenMailEnvelope(bob, env); err == nil {
		t.Fatal("OpenMailEnvelope accepted an image payload on the text path")
	}
	// And Peer.OpenMail (the relay entry) rejects it too.
	if _, _, _, _, err := NewPeer(bob, Hooks{}).OpenMail(env); err == nil {
		t.Fatal("relay OpenMail accepted an image payload")
	}
}

// TestMailImageOpenSideEnforcement proves the caps and MIME allowlist are
// enforced on OPEN, not only at seal: a malicious sender who crafts an oversize
// or wrong-type image payload is rejected by the recipient.
func TestMailImageOpenSideEnforcement(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	rdh := bob.Keys.DH.Public

	// Wrong MIME (an "image" of text/html).
	badMime := sealRawMailPayload(t, alice, bob.AccountNumber(), rdh, EncodeImagePayload("m", "text/html", []byte{1, 2, 3}))
	if _, err := OpenMailContent(bob, badMime); err == nil {
		t.Fatal("open accepted a disallowed image MIME")
	}
	// Oversize image (past MaxAttachmentBytes).
	oversize := sealRawMailPayload(t, alice, bob.AccountNumber(), rdh, EncodeImagePayload("m", "image/png", bytes.Repeat([]byte{9}, MaxAttachmentBytes+1)))
	if _, err := OpenMailContent(bob, oversize); err == nil {
		t.Fatal("open accepted an oversize image")
	}
	// Empty image.
	empty := sealRawMailPayload(t, alice, bob.AccountNumber(), rdh, EncodeImagePayload("m", "image/png", nil))
	if _, err := OpenMailContent(bob, empty); err == nil {
		t.Fatal("open accepted an empty image")
	}
}

func TestSealMailImageRejectsBad(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	rdh := bob.Keys.DH.Public
	if _, err := SealMailImageEnvelope(alice, bob.AccountNumber(), rdh, "m", "text/html", []byte{1}, time.Now()); err == nil {
		t.Fatal("sealed a disallowed MIME")
	}
	if _, err := SealMailImageEnvelope(alice, bob.AccountNumber(), rdh, "m", "image/png", bytes.Repeat([]byte{1}, MaxAttachmentBytes+1), time.Now()); err == nil {
		t.Fatal("sealed an oversize image")
	}
	if _, err := SealMailImageEnvelope(alice, bob.AccountNumber(), rdh, "m", "image/png", nil, time.Now()); err == nil {
		t.Fatal("sealed an empty image")
	}
}

// TestMailImageAndTextDistinctID guards the mailbox dedup: a text and an image
// envelope for the same msgID must hash to different envelope IDs (the ID covers
// the sealed Box, which differs), so neither collapses the other on drop-off.
func TestMailImageAndTextDistinctID(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	txt, _ := SealMailEnvelope(alice, bob.AccountNumber(), bob.Keys.DH.Public, "same", "hello", time.Unix(1000, 0))
	img, _ := SealMailImageEnvelope(alice, bob.AccountNumber(), bob.Keys.DH.Public, "same", "image/png", []byte{1, 2, 3, 4}, time.Unix(1000, 0))
	if txt.ID() == img.ID() {
		t.Fatal("text and image envelopes with the same msgID collide on ID")
	}
}
