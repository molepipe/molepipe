package session

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// generateStaticX25519Key generates a random 32-byte X25519 private key,
// clamped per RFC 7748.
func generateStaticX25519Key() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate random key: %w", err)
	}
	// Clamp per RFC 7748
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	return key, nil
}

// x25519PublicKey computes the X25519 public key from a private key.
func x25519PublicKey(privKey []byte) [32]byte {
	pub, _ := curve25519.X25519(privKey, curve25519.Basepoint)
	var out [32]byte
	copy(out[:], pub)
	return out
}

// signParts length-prefixes each part to prevent ambiguity.
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
