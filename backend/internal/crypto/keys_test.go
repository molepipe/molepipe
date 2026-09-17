package crypto

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func testSeed(t *testing.T) []byte {
	t.Helper()
	m, err := NewMnemonic()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := SeedFromMnemonic(m, "")
	if err != nil {
		t.Fatal(err)
	}
	return seed
}

// The same seed must always derive identical keys — the basis of recovery.
func TestDeriveKeysDeterministic(t *testing.T) {
	seed := testSeed(t)
	a, err := DeriveKeys(seed)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveKeys(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Signing.Private, b.Signing.Private) {
		t.Error("signing keys not deterministic")
	}
	if a.DH.Private != b.DH.Private {
		t.Error("dh keys not deterministic")
	}
}

// Signing and DH keys must be distinct — no key reuse across sign and agree.
func TestSigningAndDHKeysDiffer(t *testing.T) {
	kb, err := DeriveKeys(testSeed(t))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(kb.Signing.Private.Seed(), kb.DH.Private[:]) {
		t.Error("signing seed and dh scalar are identical — keys reused")
	}
}

func TestEd25519SignVerify(t *testing.T) {
	kb, err := DeriveKeys(testSeed(t))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("phase 1 message")
	sig := ed25519.Sign(kb.Signing.Private, msg)
	if !ed25519.Verify(kb.Signing.Public, msg, sig) {
		t.Error("valid signature failed to verify")
	}
	if ed25519.Verify(kb.Signing.Public, []byte("tampered"), sig) {
		t.Error("signature verified over the wrong message")
	}
}

// Alice and Bob must compute the same X25519 shared secret — proves the
// reused-as-scalar DH keys are usable for key agreement.
func TestX25519DHRoundTrip(t *testing.T) {
	alice, err := DeriveKeys(testSeed(t))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := DeriveKeys(testSeed(t))
	if err != nil {
		t.Fatal(err)
	}

	aShared, err := curve25519.X25519(alice.DH.Private[:], bob.DH.Public[:])
	if err != nil {
		t.Fatal(err)
	}
	bShared, err := curve25519.X25519(bob.DH.Private[:], alice.DH.Public[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aShared, bShared) {
		t.Error("X25519 shared secrets do not match")
	}
	var zero [32]byte
	if bytes.Equal(aShared, zero[:]) {
		t.Error("shared secret is all zero")
	}
}

// The stored DH scalar must be properly clamped per RFC 7748.
func TestX25519ScalarClamped(t *testing.T) {
	kb, err := DeriveKeys(testSeed(t))
	if err != nil {
		t.Fatal(err)
	}
	s := kb.DH.Private
	if s[0]&0b111 != 0 {
		t.Error("low 3 bits of scalar not cleared")
	}
	if s[31]&0b1000_0000 != 0 {
		t.Error("high bit of scalar not cleared")
	}
	if s[31]&0b0100_0000 == 0 {
		t.Error("bit 254 of scalar not set")
	}
}
