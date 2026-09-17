package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Argon2Params holds the Argon2id cost parameters. They are stored alongside
// the ciphertext so the file can always be reopened even if the defaults change
// later, and so the same params are reproduced on unlock.
type Argon2Params struct {
	TimeCost   uint32 `json:"time"`   // iterations
	MemoryKiB  uint32 `json:"memory"` // memory in KiB
	Threads    uint8  `json:"threads"`
	SaltLength uint32 `json:"salt_len"`
	KeyLength  uint32 `json:"key_len"`
}

// DefaultArgon2Params are tuned to be strong yet safe across desktop and the
// eventual Android build: 64 MiB keeps memory within mobile limits. Do not
// raise memory to 256 MiB+/1 GiB — that would break on phones.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		TimeCost:   3,
		MemoryKiB:  64 * 1024, // 64 MiB
		Threads:    4,
		SaltLength: 16,
		KeyLength:  32, // AES-256 key
	}
}

// NewSalt returns a fresh random salt of the configured length.
func NewSalt(p Argon2Params) ([]byte, error) {
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("read salt: %w", err)
	}
	return salt, nil
}

// DeriveKeyArgon2id stretches a password into a symmetric key using the given
// salt and parameters. Same inputs → same key, which is what lets unlock
// reproduce the AES key.
func DeriveKeyArgon2id(password, salt []byte, p Argon2Params) []byte {
	return argon2.IDKey(password, salt, p.TimeCost, p.MemoryKiB, p.Threads, p.KeyLength)
}
