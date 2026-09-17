package tor

import (
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"

	"filippo.io/edwards25519"

	"github.com/molepipe/molepipe/backend/internal/crypto"
)

// OnionKey is a Tor v3 onion-service identity key (KS_hs_id) derived from our
// Ed25519 signing key.
//
// A Tor onion-service identity key is not a 32-byte Ed25519 seed but an
// "expanded" secret: the clamped scalar and the 32-byte prefix that standard
// Ed25519 already computes internally as SHA-512(seed) (RFC 8032). Because the
// public key A = scalar·B is unchanged by this expansion, the .onion address
// the service publishes is identical to our Phase 1 account number. That is the
// whole point: our BIP39-derived identity IS the onion service.
type OnionKey struct {
	// ExpandedSecret is the ed25519-expanded@spec.torproject.org secret:
	// clamped scalar (32) ‖ prefix (32). This is what goes into Arti's keystore.
	ExpandedSecret [64]byte
	// Public is the 32-byte Ed25519 public key — the same bytes the account
	// number commits to.
	Public [32]byte
}

// Zeroize clears the expanded secret from memory. After this call the key
// must not be used.
func (k *OnionKey) Zeroize() {
	crypto.Zero(k.ExpandedSecret[:])
}

// DeriveOnionKey expands an Ed25519 signing seed (id.Keys.Signing.Private.Seed())
// into a Tor v3 onion-service identity key. It verifies that the expanded
// scalar reproduces the expected public key, so a clamping or endianness bug
// fails here rather than silently publishing under the wrong .onion.
func DeriveOnionKey(signingSeed []byte) (OnionKey, error) {
	if len(signingSeed) != ed25519.SeedSize {
		return OnionKey{}, fmt.Errorf("signing seed must be %d bytes, got %d", ed25519.SeedSize, len(signingSeed))
	}

	h := sha512.Sum512(signingSeed)

	// Clamp per RFC 8032, then reduce mod the group order L. The raw clamped
	// value has bit 254 set and is therefore > L (non-canonical); Tor's keystore
	// parses the scalar as a canonical Scalar and rejects non-canonical bytes.
	// Reducing yields the same public key ((k mod L)·B = k·B) and the same HS
	// signatures, but in the canonical form Arti accepts.
	scalar, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		return OnionKey{}, fmt.Errorf("clamp scalar: %w", err)
	}

	var k OnionKey
	copy(k.ExpandedSecret[:32], scalar.Bytes()) // canonical reduced scalar (< L)
	copy(k.ExpandedSecret[32:], h[32:])         // prefix (Ed25519 nonce material)

	// Confirm A = scalar·B matches the public key standard Ed25519 derives from
	// the same seed, so a clamping/endianness bug fails here.
	a := new(edwards25519.Point).ScalarBaseMult(scalar)
	copy(k.Public[:], a.Bytes())

	want := ed25519.NewKeyFromSeed(signingSeed).Public().(ed25519.PublicKey)
	if subtle.ConstantTimeCompare(want[:], k.Public[:]) != 1 {
		return OnionKey{}, fmt.Errorf("expanded key public mismatch: derivation is wrong")
	}
	return k, nil
}
