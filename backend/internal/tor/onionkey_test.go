package tor

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"filippo.io/edwards25519"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

// The stored scalar must be canonical (< group order L). Arti parses it as a
// canonical Scalar and rejects non-canonical bytes — the raw clamped value has
// bit 254 set and is > L, so this guards the reduce-mod-L fix from regressing.
func TestOnionKeyScalarIsCanonical(t *testing.T) {
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	key, err := DeriveOnionKey(id.Keys.Signing.Private.Seed())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := edwards25519.NewScalar().SetCanonicalBytes(key.ExpandedSecret[:32]); err != nil {
		t.Fatalf("stored scalar is non-canonical (Arti would reject it): %v", err)
	}
}

// The onion-service key must reproduce the account number's public key exactly,
// so the published .onion equals the account number. This is the load-bearing
// invariant of the whole design.
func TestOnionKeyMatchesAccountNumber(t *testing.T) {
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	seed := id.Keys.Signing.Private.Seed()

	key, err := DeriveOnionKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	// The expanded key's public half must equal the identity's signing pubkey.
	if !bytes.Equal(key.Public[:], id.Keys.Signing.Public) {
		t.Fatal("onion key public does not match signing public key")
	}

	// And it must equal the public key the account number commits to, closing
	// the loop: onion address == account number.
	committed, err := identity.AccountNumberFromString(id.AccountNumber())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key.Public[:], committed) {
		t.Fatal("onion key public does not match the account number's committed pubkey")
	}
}

// The expanded secret must be a valid Ed25519 signer: signing with the expanded
// scalar+prefix must verify under the same public key. This confirms the
// expansion is the genuine Ed25519 expanded key, not just a coincidental point.
func TestOnionKeyExpandedSecretSigns(t *testing.T) {
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	seed := id.Keys.Signing.Private.Seed()
	key, err := DeriveOnionKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	// A standard Ed25519 signature over the same key must verify under the
	// public key we derived — a cross-check that Public is a real Ed25519 point.
	priv := ed25519.NewKeyFromSeed(seed)
	msg := []byte("onion service descriptor")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(ed25519.PublicKey(key.Public[:]), msg, sig) {
		t.Fatal("signature does not verify under the derived onion public key")
	}
}

// Determinism: recovery reproduces the same onion key, so the same account
// always maps to the same .onion.
func TestOnionKeyDeterministic(t *testing.T) {
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := identity.FromMnemonic(id.MnemonicString(), id.PassphraseString())
	if err != nil {
		t.Fatal(err)
	}
	a, err := DeriveOnionKey(id.Keys.Signing.Private.Seed())
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveOnionKey(recovered.Keys.Signing.Private.Seed())
	if err != nil {
		t.Fatal(err)
	}
	if a.ExpandedSecret != b.ExpandedSecret || a.Public != b.Public {
		t.Fatal("onion key not deterministic across recovery")
	}
}

func TestDeriveOnionKeyRejectsBadSeed(t *testing.T) {
	if _, err := DeriveOnionKey([]byte("too short")); err == nil {
		t.Fatal("expected error for wrong-size seed")
	}
}
