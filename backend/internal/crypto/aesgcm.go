package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// Seal encrypts plaintext with AES-256-GCM under key (which must be 32 bytes).
// It returns a fresh random nonce and the ciphertext (including GCM tag).
// aad is authenticated but not encrypted — used to bind the envelope header.
func Seal(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("read nonce: %w", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

// Open decrypts and authenticates ciphertext produced by Seal. A wrong password
// (wrong derived key) or any tampering fails authentication and returns an
// error rather than garbage plaintext.
func Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("bad nonce length %d", len(nonce))
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed (wrong password or corrupt data): %w", err)
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("aes key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	return cipher.NewGCM(block)
}
