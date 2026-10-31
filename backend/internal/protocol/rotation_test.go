package protocol

import (
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

func testIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// A rotation payload must survive encode→decode with every field intact.
func TestRotationPayloadRoundTrip(t *testing.T) {
	onion := testIdentity(t).AccountNumber()
	in := AddressRotation{NewOnion: onion, AliasIndex: 7, ValidFrom: 1234567890}
	out, ok := DecodeRotationPayload(EncodeRotationPayload(in))
	if !ok {
		t.Fatal("rotation payload did not decode")
	}
	if out != in {
		t.Fatalf("round trip changed the rotation: %+v -> %+v", in, out)
	}
}

// A rotation-ack payload survives encode→decode, and does NOT cross-decode with
// a rotation announcement or a text message (each Kind is dispatched on its own
// branch, so a mismatch would mis-route the payload).
func TestRotationAckPayloadRoundTrip(t *testing.T) {
	got, ok := DecodeRotationAckPayload(EncodeRotationAckPayload(9))
	if !ok || got != 9 {
		t.Fatalf("ack round trip = (%d, %v), want (9, true)", got, ok)
	}
	// An ack is not a rotation, and a rotation is not an ack.
	onion := testIdentity(t).AccountNumber()
	if _, ok := DecodeRotationPayload(EncodeRotationAckPayload(1)); ok {
		t.Error("a rotation ack wrongly decoded as a rotation announcement")
	}
	if _, ok := DecodeRotationAckPayload(EncodeRotationPayload(AddressRotation{NewOnion: onion, AliasIndex: 1})); ok {
		t.Error("a rotation announcement wrongly decoded as a rotation ack")
	}
	if _, ok := DecodeRotationAckPayload(EncodePayload("id1", "hello")); ok {
		t.Error("a text message wrongly decoded as a rotation ack")
	}
}

// Non-rotation plaintexts (text, image, legacy bare text) must NOT decode as a
// rotation — the Kind discriminator gates it.
func TestDecodeRotationRejectsNonRotation(t *testing.T) {
	onion := testIdentity(t).AccountNumber()
	cases := map[string][]byte{
		"text":   EncodePayload("id1", "hello"),
		"image":  EncodeImagePayload("id2", "image/png", []byte{1, 2, 3}),
		"legacy": []byte("bare text"),
		"empty":  nil,
	}
	for name, pt := range cases {
		if _, ok := DecodeRotationPayload(pt); ok {
			t.Errorf("%s plaintext wrongly decoded as a rotation", name)
		}
	}
	// Sanity: a real rotation over the same codec still decodes.
	if _, ok := DecodeRotationPayload(EncodeRotationPayload(AddressRotation{NewOnion: onion, AliasIndex: 1})); !ok {
		t.Error("valid rotation failed to decode")
	}
}

// A malformed NewOnion must be rejected at decode — the onion is peer-supplied
// and validated before the caller migrates a contact to it.
func TestDecodeRotationRejectsBadOnion(t *testing.T) {
	bad := EncodeRotationPayload(AddressRotation{NewOnion: "not-a-real-onion", AliasIndex: 1})
	if _, ok := DecodeRotationPayload(bad); ok {
		t.Error("rotation with a malformed onion should not decode")
	}
}

// End-to-end over the static-DH mailbox channel: a rotation sealed to a
// recipient must open as Kind==rotation with the announcement intact, and its
// authenticating SenderDHPub must be the sender's stable DH key (the continuity
// anchor), NOT dependent on the sender account string.
func TestRotationOverMailboxChannel(t *testing.T) {
	sender := testIdentity(t)
	recipient := testIdentity(t)
	newOnion := testIdentity(t).AccountNumber()

	var rdh [32]byte
	copy(rdh[:], recipient.Keys.DH.Public[:])
	env, err := SealMailRotationEnvelope(sender, recipient.AccountNumber(), rdh, AddressRotation{NewOnion: newOnion, AliasIndex: 3}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// The envelope's SenderDHPub is the sender's stable DH identity key.
	if len(env.SenderDHPub) != 32 {
		t.Fatalf("SenderDHPub wrong length: %d", len(env.SenderDHPub))
	}
	sdh := sender.Keys.DH.Public
	if string(env.SenderDHPub) != string(sdh[:]) {
		t.Error("mailbox rotation SenderDHPub is not the sender's stable DH key")
	}

	c, err := OpenMailContent(recipient, env)
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != MailKindRotation {
		t.Fatalf("opened kind = %q, want %q", c.Kind, MailKindRotation)
	}
	if c.Rotation.NewOnion != newOnion || c.Rotation.AliasIndex != 3 {
		t.Fatalf("rotation content lost: %+v", c.Rotation)
	}

	// The text/relay path must refuse a rotation rather than deliver it as text.
	if _, _, _, _, err := OpenMailEnvelope(recipient, env); err == nil {
		t.Error("text path accepted a rotation payload")
	}
}
