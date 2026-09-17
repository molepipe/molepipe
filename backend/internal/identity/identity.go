// Package identity ties the crypto primitives into a usable account: a recovery
// phrase, the derived keys, an account number, and encrypted on-disk storage.
package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"

	"github.com/molepipe/molepipe/backend/internal/crypto"
)



// onionVersion is the v3 onion address version byte.
const onionVersion byte = 0x03

// b32 is lowercase, unpadded base32 — the encoding used by onion addresses.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Identity is an unlocked account held in memory. The mnemonic is the single
// root of truth; the keys are derived from it and reproduced exactly on
// recovery. Hold this only while unlocked and call Zeroize on lock.
//
// Mnemonic and Passphrase are []byte (not string) so they can be explicitly
// zeroed from memory. Go strings are immutable and cannot be wiped; using
// byte slices allows crypto.Zero to reliably clear the backing memory.
type Identity struct {
	Mnemonic   []byte
	Passphrase []byte // BIP39 passphrase ("25th word"); usually empty
	Keys       crypto.KeyBundle
}

// Zeroize clears all sensitive fields from memory. Call this when the identity
// is no longer needed (lock, timeout, error path). After Zeroize the Identity
// must not be used.
func (id *Identity) Zeroize() {
	if id == nil {
		return
	}
	crypto.Zero(id.Mnemonic)
	crypto.Zero(id.Passphrase)
	id.Keys.Zeroize()
	id.Mnemonic = nil
	id.Passphrase = nil
}

// MnemonicString returns the mnemonic as a string for display or serialization.
// WARNING: The returned string is an immutable Go string that cannot be zeroed.
// Callers must never store, log, or pass it to third-party code. Use only for
// immediate rendering (UI display, recovery phrase screen).
func (id *Identity) MnemonicString() string {
	return string(id.Mnemonic)
}

// PassphraseString returns the passphrase as a string for display or serialization.
func (id *Identity) PassphraseString() string {
	return string(id.Passphrase)
}

// StoreKey derives a stable 32-byte key for encrypting local app data (contacts,
// message history) at rest. It is derived from the BIP39 seed, so it is
// available only while unlocked and the data is protected exactly as strongly
// as the identity itself. Deterministic: the same identity always yields the
// same key, so the store reopens across sessions.
func (id *Identity) StoreKey() ([]byte, error) {
	seed, err := crypto.SeedFromMnemonic(string(id.Mnemonic), string(id.Passphrase))
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(seed)
	r := hkdf.New(sha256.New, seed, nil, []byte("onion-chat/v1 local-store key"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// New creates a brand-new identity with a fresh 24-word recovery phrase.
func New() (*Identity, error) {
	mnemonic, err := crypto.NewMnemonic()
	if err != nil {
		return nil, err
	}
	return FromMnemonic(mnemonic, "")
}

// FromMnemonic reconstructs an identity from a recovery phrase. This is the
// recovery path: it derives keys directly from the phrase and is completely
// independent of any stored file or Argon2 parameters.
func FromMnemonic(mnemonic, passphrase string) (*Identity, error) {
	seed, err := crypto.SeedFromMnemonic(mnemonic, passphrase)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(seed)
	keys, err := crypto.DeriveKeys(seed)
	if err != nil {
		return nil, err
	}
	return &Identity{Mnemonic: []byte(mnemonic), Passphrase: []byte(passphrase), Keys: keys}, nil
}

// AccountNumber is the v3-onion-style encoding of the Ed25519 public key:
// base32(pubkey ‖ checksum ‖ version). Because it commits to the full public
// key it is collision-resistant and is the authoritative identity — the same
// value that becomes the onion address in Phase 3. Always exchange this in
// full; never a truncation of it.
func (id *Identity) AccountNumber() string {
	return accountNumber(id.Keys.Signing.Public)
}

// OnionAddress is the account number with the ".onion" suffix.
func (id *Identity) OnionAddress() string {
	return id.AccountNumber() + ".onion"
}

// AccountNumberForPub encodes a raw Ed25519 public key as an account number.
// Exposed so the Tor sidecar can render the .onion for a key without
// duplicating the v3 encoding.
func AccountNumberForPub(pub ed25519.PublicKey) string {
	return accountNumber(pub)
}

func accountNumber(pub ed25519.PublicKey) string {
	checksum := onionChecksum(pub)
	var buf []byte
	buf = append(buf, pub...)
	buf = append(buf, checksum...)
	buf = append(buf, onionVersion)
	return strings.ToLower(b32.EncodeToString(buf))
}

// onionChecksum computes the 2-byte v3 onion checksum:
// SHA3-256(".onion checksum" ‖ pubkey ‖ version)[:2].
func onionChecksum(pub ed25519.PublicKey) []byte {
	h := sha3.New256()
	h.Write([]byte(".onion checksum"))
	h.Write(pub)
	h.Write([]byte{onionVersion})
	sum := h.Sum(nil)
	return sum[:2]
}

// AccountNumberFromString validates an account number and returns the public
// key it commits to. Used later for contact adding.
func AccountNumberFromString(account string) (ed25519.PublicKey, error) {
	account = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(account)), ".onion")
	raw, err := b32.DecodeString(strings.ToUpper(account))
	if err != nil {
		return nil, fmt.Errorf("decode account number: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize+3 {
		return nil, fmt.Errorf("account number wrong length: %d bytes", len(raw))
	}
	pub := ed25519.PublicKey(raw[:ed25519.PublicKeySize])
	gotChecksum := raw[ed25519.PublicKeySize : ed25519.PublicKeySize+2]
	version := raw[ed25519.PublicKeySize+2]
	if version != onionVersion {
		return nil, fmt.Errorf("unsupported version byte 0x%02x", version)
	}
	want := onionChecksum(pub)
	if subtle.ConstantTimeCompare(want, gotChecksum) != 1 {
		return nil, fmt.Errorf("account number checksum mismatch")
	}
	return pub, nil
}
