package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Prekey protocol version and domain separation prefixes.
const (
	PrekeyProtocolVersion = 2
	signedPrekeyDomain    = "Molepipe-Signed-Prekey-v1"
)

// SignedPrekey is a persistent but periodically replaceable X25519 keypair,
// signed by the permanent Ed25519 identity key. It is used for asynchronous
// session establishment (X3DH).
type SignedPrekey struct {
	ID        uint32
	PublicKey [32]byte
	CreatedAt time.Time
	Signature []byte // Ed25519 signature over the signed prekey data
}

// signedPrekeySignData returns the canonical byte sequence that the Ed25519
// identity key signs. The domain separation prefix prevents cross-protocol
// signature reuse.
func signedPrekeySignData(identityPub []byte, id uint32, pubKey [32]byte, createdAt int64) []byte {
	return signParts(
		[]byte(signedPrekeyDomain),
		identityPub,
		u32Bytes(id),
		pubKey[:],
		i64Bytes(createdAt),
	)
}

// x25519PublicKey computes the X25519 public key from a private key.
func x25519PublicKey(privKey []byte) [32]byte {
	pub, _ := curve25519.X25519(privKey, curve25519.Basepoint)
	var out [32]byte
	copy(out[:], pub)
	return out
}

// GenerateSignedPrekey generates a new X25519 keypair and signs it with the
// permanent Ed25519 identity key. The signature binds the prekey to the identity
// and includes a monotonic ID and creation timestamp.
func GenerateSignedPrekey(signingKey ed25519.PrivateKey, identityPub []byte, id uint32, createdAt time.Time) (*SignedPrekey, []byte, error) {
	privKey, err := generateX25519Key()
	if err != nil {
		return nil, nil, fmt.Errorf("generate x25519 key: %w", err)
	}
	pubKey := x25519PublicKey(privKey)

	ts := createdAt.UnixMilli()
	sigData := signedPrekeySignData(identityPub, id, pubKey, ts)
	sig := ed25519.Sign(signingKey, sigData)

	return &SignedPrekey{
		ID:        id,
		PublicKey: pubKey,
		CreatedAt: createdAt,
		Signature: sig,
	}, privKey, nil
}

// ReSignBundleForIdentity returns a copy of bundle presenting identityPub as the
// signing identity: IdentityPub is set to identityPub and the signed prekey is
// re-signed with signPriv (which MUST be identityPub's private half) over the SAME
// signed-prekey material (id, pub, createdAt). It exists for account rotation — an
// alias-of-us serves the shared signed prekey under the alias key so a client that
// dialed the alias (and therefore runs VerifyBundle against the alias account, not
// bundle.IdentityPub) accepts it, without ever exposing the primary identity. Only
// the Ed identity and its signature change; the X25519 signed-prekey and one-time
// prekey material — which is what X3DH actually keys off, so re-signing needs no
// responder-side change — is untouched. The input is never mutated: IdentityPub and
// SignedPrekeySig are replaced with fresh slices, so a caller's stored SignedPrekey
// (and every subsequent fetch of it) stays intact.
func ReSignBundleForIdentity(bundle PrekeyBundle, identityPub ed25519.PublicKey, signPriv ed25519.PrivateKey) (PrekeyBundle, error) {
	if len(bundle.SignedPrekeyPub) != 32 {
		return PrekeyBundle{}, fmt.Errorf("invalid signed prekey public key length: %d", len(bundle.SignedPrekeyPub))
	}
	var spPub [32]byte
	copy(spPub[:], bundle.SignedPrekeyPub)
	sigData := signedPrekeySignData(identityPub, bundle.SignedPrekeyID, spPub, bundle.SignedPrekeyCreated)
	out := bundle // struct value copy; slice fields still share backing arrays…
	out.IdentityPub = append([]byte(nil), identityPub...)     // …so replace the two we change
	out.SignedPrekeySig = ed25519.Sign(signPriv, sigData)      // with fresh slices, mutating nothing shared.
	return out, nil
}

// VerifySignedPrekey verifies that a signed prekey was signed by the given
// identity key. Returns nil if valid, error otherwise.
func VerifySignedPrekey(sp *SignedPrekey, identityPub ed25519.PublicKey) error {
	if len(sp.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: %d", len(sp.Signature))
	}
	ts := sp.CreatedAt.UnixMilli()
	sigData := signedPrekeySignData(identityPub, sp.ID, sp.PublicKey, ts)
	if !ed25519.Verify(identityPub, sigData, sp.Signature) {
		return fmt.Errorf("signed prekey signature verification failed")
	}
	return nil
}

// OneTimePrekey is a single-use X25519 keypair for asynchronous session
// establishment. Once consumed, its private key must be deleted.
type OneTimePrekey struct {
	ID        uint32
	PublicKey [32]byte
}

// GenerateOneTimePrekey generates a single one-time prekey. The private key
// is returned separately so the caller can store it securely and publish only
// the public key.
func GenerateOneTimePrekey(id uint32) (*OneTimePrekey, []byte, error) {
	privKey, err := generateX25519Key()
	if err != nil {
		return nil, nil, fmt.Errorf("generate x25519 key: %w", err)
	}
	pubKey := x25519PublicKey(privKey)
	return &OneTimePrekey{ID: id, PublicKey: pubKey}, privKey, nil
}

// PrekeyBundle is the public information required to establish a new session
// via X3DH. It is served by the recipient's onion service and consumed by the
// initiator.
type PrekeyBundle struct {
	IdentityPub         []byte  `json:"identity_pub"`          // 32-byte Ed25519 public key
	SignedPrekeyID      uint32  `json:"signed_prekey_id"`       // monotonic ID
	SignedPrekeyPub     []byte  `json:"signed_prekey_pub"`      // 32-byte X25519 public key
	SignedPrekeySig     []byte  `json:"signed_prekey_sig"`      // Ed25519 signature
	SignedPrekeyCreated int64   `json:"signed_prekey_created"`  // creation timestamp (UnixMilli)
	OneTimePrekeyID     *uint32 `json:"one_time_prekey_id,omitempty"`   // nil if unavailable
	OneTimePrekeyPub    []byte  `json:"one_time_prekey_pub,omitempty"`  // 32-byte X25519 (nil if unavailable)
	DeviceID            []byte  `json:"device_id,omitempty"`    // device identifier
	Version             uint16  `json:"version"`                // protocol version
}

// VerifyBundle verifies the integrity and authenticity of a prekey bundle.
// It checks:
// 1. Key formats and lengths
// 2. Signed prekey signature against the identity key
// 3. Protocol version
func VerifyBundle(bundle PrekeyBundle, identityPub ed25519.PublicKey) error {
	if len(bundle.IdentityPub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid identity public key length: %d", len(bundle.IdentityPub))
	}
	if len(bundle.SignedPrekeyPub) != 32 {
		return fmt.Errorf("invalid signed prekey public key length: %d", len(bundle.SignedPrekeyPub))
	}
	if len(bundle.SignedPrekeySig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signed prekey signature length: %d", len(bundle.SignedPrekeySig))
	}
	if bundle.Version < 1 || bundle.Version > 2 {
		return fmt.Errorf("unsupported protocol version: %d", bundle.Version)
	}

	var signedPub [32]byte
	copy(signedPub[:], bundle.SignedPrekeyPub)
	sp := &SignedPrekey{
		ID:        bundle.SignedPrekeyID,
		PublicKey: signedPub,
		CreatedAt: time.UnixMilli(bundle.SignedPrekeyCreated),
		Signature: bundle.SignedPrekeySig,
	}
	return VerifySignedPrekey(sp, identityPub)
}

// X3DHInitiate performs the initiator side of the X3DH key agreement.
// It computes four DH operations and derives the initial root secret.
//
// DH1 = DH(IK_A, SPK_B)   — identity of initiator with signed prekey of responder
// DH2 = DH(EK_A, IK_B)     — ephemeral of initiator with identity of responder
// DH3 = DH(EK_A, SPK_B)    — ephemeral of initiator with signed prekey of responder
// DH4 = DH(EK_A, OPK_B)    — ephemeral of initiator with one-time prekey of responder (optional)
//
// IK_A and IK_B are X25519 identity keys (from the BIP39 seed at m/0'/1').
// The signature keys (Ed25519) are separate and only used for signing prekeys.
func X3DHInitiate(
	ikA [32]byte,            // initiator's X25519 identity private key
	spkB [32]byte,           // responder's signed prekey public key
	ikBPub [32]byte,         // responder's X25519 identity public key
	opkB *[32]byte,          // responder's one-time prekey (nil if unavailable)
) (ephemeralPriv [32]byte, ephemeralPub [32]byte, sharedSecret []byte, err error) {
	// Generate ephemeral keypair
	ephPriv, err := generateX25519Key()
	if err != nil {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	ephPub := x25519PublicKey(ephPriv)
	copy(ephemeralPriv[:], ephPriv)
	ephemeralPub = ephPub

	// DH1 = DH(IK_A, SPK_B)
	dh1, err := curve25519.X25519(ikA[:], spkB[:])
	if err != nil {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("dh1: %w", err)
	}

	// DH2 = DH(EK_A, IK_B)
	dh2, err := curve25519.X25519(ephPriv, ikBPub[:])
	if err != nil {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("dh2: %w", err)
	}

	// DH3 = DH(EK_A, SPK_B)
	dh3, err := curve25519.X25519(ephPriv, spkB[:])
	if err != nil {
		return [32]byte{}, [32]byte{}, nil, fmt.Errorf("dh3: %w", err)
	}

	// Combine DH outputs
	dhOutputs := append(dh1, dh2...)
	dhOutputs = append(dhOutputs, dh3...)

	// DH4 = DH(EK_A, OPK_B) — optional
	if opkB != nil {
		dh4, err := curve25519.X25519(ephPriv, opkB[:])
		if err != nil {
			return [32]byte{}, [32]byte{}, nil, fmt.Errorf("dh4: %w", err)
		}
		dhOutputs = append(dhOutputs, dh4...)
	}

	// Derive shared secret via HKDF — use public keys for domain separation
	ikAPubComputed := x25519PublicKey(ikA[:])
	sharedSecret = deriveX3DHSecret(dhOutputs, ikAPubComputed, ikBPub, ephPub, opkB != nil)

	// Zero intermediate values (defense in depth — these are stack-allocated
	// and would be garbage collected, but explicit zeroing prevents them from
	// surviving in a core dump or memory snapshot).
	Zero(ephPriv)
	Zero(dhOutputs)

	return ephemeralPriv, ephemeralPub, sharedSecret, nil
}

// X3DHRespond performs the responder side of the X3DH key agreement.
// It takes the responder's X25519 identity and prekey private keys, and the
// initiator's ephemeral public key, to derive the same shared secret.
func X3DHRespond(
	ikB [32]byte,           // responder's X25519 identity private key
	spkBPriv []byte,        // responder's signed prekey private key (32 bytes)
	opkBPriv []byte,        // responder's one-time prekey private key (nil if unused)
	ephPub [32]byte,        // initiator's ephemeral public key
	ikAPub [32]byte,        // initiator's X25519 identity public key
	hasOneTimePrekey bool,  // whether an one-time prekey was used
) (sharedSecret []byte, err error) {
	// DH1 = DH(SPK_B, IK_A) = DH(IK_A, SPK_B)
	dh1, err := curve25519.X25519(spkBPriv, ikAPub[:])
	if err != nil {
		return nil, fmt.Errorf("dh1: %w", err)
	}

	// DH2 = DH(IK_B, EK_A) = DH(EK_A, IK_B)
	dh2, err := curve25519.X25519(ikB[:], ephPub[:])
	if err != nil {
		return nil, fmt.Errorf("dh2: %w", err)
	}

	// DH3 = DH(SPK_B, EK_A) = DH(EK_A, SPK_B)
	dh3, err := curve25519.X25519(spkBPriv, ephPub[:])
	if err != nil {
		return nil, fmt.Errorf("dh3: %w", err)
	}

	dhOutputs := append(dh1, dh2...)
	dhOutputs = append(dhOutputs, dh3...)

	// DH4 = DH(OPK_B, EK_A) = DH(EK_A, OPK_B) — optional
	if opkBPriv != nil && hasOneTimePrekey {
		dh4, err := curve25519.X25519(opkBPriv, ephPub[:])
		if err != nil {
			return nil, fmt.Errorf("dh4: %w", err)
		}
		dhOutputs = append(dhOutputs, dh4...)
	}

	// Use public keys for domain separation
	ikBPubComputed := x25519PublicKey(ikB[:])
	sharedSecret = deriveX3DHSecret(dhOutputs, ikAPub, ikBPubComputed, ephPub, hasOneTimePrekey)

	// Zero intermediate values (defense in depth).
	Zero(dhOutputs)

	return sharedSecret, nil
}

// deriveX3DHSecret derives the initial root secret from the combined DH outputs
// using HKDF-SHA256 with domain separation.
func deriveX3DHSecret(dhOutputs []byte, ikAPub, ikBPub [32]byte, ephPub [32]byte, hasOneTime bool) []byte {
	info := signParts(
		[]byte("Molepipe-X3DH-v1"),
		ikAPub[:],
		ikBPub[:],
		ephPub[:],
		[]byte{boolToByte(hasOneTime)},
	)
	r := hkdf.New(sha256.New, dhOutputs, nil, info)
	key := make([]byte, 32)
	_, _ = io.ReadFull(r, key)
	return key
}

// generateX25519Key generates a random 32-byte X25519 private key, clamped
// per RFC 7748.
func generateX25519Key() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	return key, nil
}

// signParts length-prefixes each part so distinct field sequences can never
// collide into the same signed bytes. This is the crypto-internal version of
// the protocol package's signBlob — kept separate to avoid circular imports.
func signParts(parts ...[]byte) []byte {
	var b []byte
	var l [4]byte
	for _, part := range parts {
		binary.BigEndian.PutUint32(l[:], uint32(len(part)))
		b = append(b, l[:]...)
		b = append(b, part...)
	}
	return b
}

// u32Bytes encodes a uint32 as 4 big-endian bytes.
func u32Bytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// i64Bytes encodes an int64 as 8 big-endian bytes.
func i64Bytes(v int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	return b
}

func boolToByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}
