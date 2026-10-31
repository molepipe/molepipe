package crypto

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// A given seed + index must always derive the same alias key — the basis for
// regenerating the current alias after a seed restore.
func TestDeriveAliasSigningKeyDeterministic(t *testing.T) {
	seed := testSeed(t)
	a, err := DeriveAliasSigningKey(seed, 7)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveAliasSigningKey(seed, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Private, b.Private) {
		t.Error("alias signing key not deterministic for the same index")
	}
	if !bytes.Equal(a.Public, b.Public) {
		t.Error("alias public key not deterministic for the same index")
	}
}

// Distinct indices must yield distinct keys — otherwise rotation would reuse
// the same onion address across aliases.
func TestDeriveAliasSigningKeyDistinctPerIndex(t *testing.T) {
	seed := testSeed(t)
	seen := map[string]uint32{}
	for i := uint32(0); i < 8; i++ {
		kp, err := DeriveAliasSigningKey(seed, i)
		if err != nil {
			t.Fatal(err)
		}
		k := string(kp.Public)
		if prev, ok := seen[k]; ok {
			t.Errorf("alias %d collides with alias %d", i, prev)
		}
		seen[k] = i
	}
}

// The durable identity keys (m/0'/0' signing, m/0'/1' DH) must be unaffected by
// the alias branch — an alias must never equal the real signing/identity key.
func TestAliasDistinctFromIdentityKeys(t *testing.T) {
	seed := testSeed(t)
	kb, err := DeriveKeys(seed)
	if err != nil {
		t.Fatal(err)
	}
	for i := uint32(0); i < 4; i++ {
		alias, err := DeriveAliasSigningKey(seed, i)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(alias.Private.Seed(), kb.Signing.Private.Seed()) {
			t.Errorf("alias %d seed equals the durable signing seed — identity leaked", i)
		}
		if bytes.Equal(alias.Public, kb.Signing.Public) {
			t.Errorf("alias %d public equals the durable signing public key", i)
		}
		if bytes.Equal(alias.Private.Seed(), kb.DH.Private[:]) {
			t.Errorf("alias %d seed equals the DH scalar — key reuse", i)
		}
	}
}

// The alias key must actually sign and verify as a normal Ed25519 key so it can
// serve as a v3 onion service key.
func TestAliasSignVerify(t *testing.T) {
	kp, err := DeriveAliasSigningKey(testSeed(t), 3)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("alias rotation announcement")
	sig := ed25519.Sign(kp.Private, msg)
	if !ed25519.Verify(kp.Public, msg, sig) {
		t.Error("alias signature failed to verify")
	}
}

// Two different seeds must not produce the same alias at the same index.
func TestDeriveAliasSigningKeyDistinctPerSeed(t *testing.T) {
	a, err := DeriveAliasSigningKey(testSeed(t), 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveAliasSigningKey(testSeed(t), 0)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Public, b.Public) {
		t.Error("different seeds produced the same alias key")
	}
}
