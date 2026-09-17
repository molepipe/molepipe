// Package crypto contains the identity primitives for the messenger:
// BIP39 recovery phrases, SLIP-0010 key derivation, an Argon2id password KDF,
// and AES-256-GCM sealing. It has no networking and no OS/UI assumptions so it
// stays portable to the eventual gomobile Android build.
package crypto

import (
	"fmt"

	"github.com/tyler-smith/go-bip39"
)

// MnemonicEntropyBits is the entropy size for a new recovery phrase.
// 256 bits produces a 24-word phrase — the high-security default.
const MnemonicEntropyBits = 256

// NewMnemonic generates a fresh BIP39 recovery phrase.
func NewMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(MnemonicEntropyBits)
	if err != nil {
		return "", fmt.Errorf("generate entropy: %w", err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("encode mnemonic: %w", err)
	}
	return mnemonic, nil
}

// ValidMnemonic reports whether a phrase is a well-formed BIP39 mnemonic
// (correct word list membership and checksum).
func ValidMnemonic(mnemonic string) bool {
	return bip39.IsMnemonicValid(mnemonic)
}

// SeedFromMnemonic derives the 64-byte BIP39 seed from a phrase. The optional
// passphrase is the BIP39 "25th word"; empty is the common case. This is the
// single root of all derived keys, so it is deterministic: the same phrase
// always yields the same seed and therefore the same identity.
func SeedFromMnemonic(mnemonic, passphrase string) ([]byte, error) {
	if !ValidMnemonic(mnemonic) {
		return nil, fmt.Errorf("invalid recovery phrase")
	}
	return bip39.NewSeed(mnemonic, passphrase), nil
}
