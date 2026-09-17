package crypto

import (
	"crypto/ed25519"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// Derivation paths from the BIP39 seed. Both are hardened SLIP-0010 Ed25519
// paths under a common app purpose (index 0). We derive the signing and DH keys
// at distinct indices so a single key is never reused across signing and key
// agreement.
var (
	signingPath = []uint32{0, 0} // m/0'/0' — Ed25519 signing / identity key
	dhPath      = []uint32{0, 1} // m/0'/1' — X25519 key-agreement key
)

// SigningKeyPair is an Ed25519 identity keypair. Its public key is the account
// identity and, in Phase 3, the v3 onion service key.
type SigningKeyPair struct {
	Private ed25519.PrivateKey // 64 bytes (seed ‖ public)
	Public  ed25519.PublicKey  // 32 bytes
}

// DHKeyPair is an X25519 key-agreement keypair.
type DHKeyPair struct {
	Private [32]byte // clamped Curve25519 scalar
	Public  [32]byte
}

// KeyBundle is the full set of keys derived from one seed.
type KeyBundle struct {
	Signing SigningKeyPair
	DH      DHKeyPair
}

// Zeroize clears all private key material from memory. After this call the
// KeyBundle must not be used for signing or key agreement.
func (kb *KeyBundle) Zeroize() {
	Zero(kb.Signing.Private)
	Zero(kb.DH.Private[:])
}

// DeriveKeys deterministically derives the signing and DH keypairs from a
// BIP39 seed. The same seed always yields the same keys, which is what makes
// recovery from the phrase reproduce the identity exactly.
func DeriveKeys(seed []byte) (KeyBundle, error) {
	var kb KeyBundle

	signSeed, err := DeriveSLIP10Ed25519(seed, signingPath...)
	if err != nil {
		return kb, fmt.Errorf("derive signing key: %w", err)
	}
	kb.Signing.Private = ed25519.NewKeyFromSeed(signSeed)
	kb.Signing.Public = kb.Signing.Private.Public().(ed25519.PublicKey)

	// The SLIP-0010 leaf is specified as an Ed25519 seed; here we reuse those
	// 32 bytes as a Curve25519 scalar. That reuse is non-standard, so we clamp
	// explicitly per RFC 7748 and verify DH agreement in the tests.
	dhScalar, err := DeriveSLIP10Ed25519(seed, dhPath...)
	if err != nil {
		return kb, fmt.Errorf("derive dh key: %w", err)
	}
	dhScalar[0] &= 248
	dhScalar[31] &= 127
	dhScalar[31] |= 64
	copy(kb.DH.Private[:], dhScalar)

	pub, err := curve25519.X25519(kb.DH.Private[:], curve25519.Basepoint)
	if err != nil {
		return kb, fmt.Errorf("derive dh public key: %w", err)
	}
	copy(kb.DH.Public[:], pub)

	return kb, nil
}
