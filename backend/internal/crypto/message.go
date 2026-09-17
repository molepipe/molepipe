package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// SharedSecret computes the X25519 ECDH shared secret between our DH private key
// and a peer's DH public key. Both sides compute the same value.
func SharedSecret(myDHPriv, theirDHPub [32]byte) ([]byte, error) {
	s, err := curve25519.X25519(myDHPriv[:], theirDHPub[:])
	if err != nil {
		return nil, fmt.Errorf("x25519: %w", err)
	}
	return s, nil
}

// DeriveDirectionalKey derives a 32-byte AEAD key from the ECDH shared secret
// for one direction of a conversation. info MUST differ per direction (it
// encodes sender→receiver), so the two directions never share a key — with a
// static shared secret, a single shared key plus random nonces risks nonce
// reuse across the pair.
func DeriveDirectionalKey(shared []byte, info string) []byte {
	r := hkdf.New(sha256.New, shared, nil, []byte(info))
	key := make([]byte, chacha20poly1305.KeySize)
	_, _ = io.ReadFull(r, key)
	return key
}

// SealMessage encrypts plaintext with XChaCha20-Poly1305, returning
// nonce‖ciphertext. XChaCha's 192-bit nonce makes random nonces collision-safe
// even without a counter.
func SealMessage(key, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

// OpenMessage decrypts nonce‖ciphertext produced by SealMessage. A wrong key or
// any tampering fails authentication.
func OpenMessage(key, box, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(box) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := box[:aead.NonceSize()], box[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed (wrong key or tampered): %w", err)
	}
	return pt, nil
}
