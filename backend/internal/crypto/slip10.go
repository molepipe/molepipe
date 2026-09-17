package crypto

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
)

// SLIP-0010 key derivation over the Ed25519 curve.
//
// Reference: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
// Ed25519 supports hardened derivation only. Each step outputs 64 bytes from
// HMAC-SHA512: the left 32 bytes are the key material, the right 32 the chain
// code. The 32-byte key material at a leaf is used directly as an Ed25519 seed.
// It is pinned to the SLIP-0010 official Ed25519 test vectors in slip10_test.go.

// HardenedOffset is added to a path index to mark it hardened (bit 31 set).
const HardenedOffset uint32 = 0x80000000

type slip10Key struct {
	key       []byte // 32 bytes of derivable key material
	chainCode []byte // 32 bytes
}

func slip10Master(seed []byte) slip10Key {
	h := hmac.New(sha512.New, []byte("ed25519 seed"))
	h.Write(seed)
	sum := h.Sum(nil)
	return slip10Key{key: sum[:32], chainCode: sum[32:]}
}

// deriveHardened derives one hardened child. index must already include
// HardenedOffset.
func (k slip10Key) deriveHardened(index uint32) (slip10Key, error) {
	if index < HardenedOffset {
		return slip10Key{}, fmt.Errorf("slip10 ed25519 requires hardened derivation, got index %d", index)
	}
	var data [37]byte
	data[0] = 0x00
	copy(data[1:33], k.key)
	binary.BigEndian.PutUint32(data[33:], index)

	h := hmac.New(sha512.New, k.chainCode)
	h.Write(data[:])
	sum := h.Sum(nil)
	return slip10Key{key: sum[:32], chainCode: sum[32:]}, nil
}

// DeriveSLIP10Ed25519 walks the given path from the master key derived from
// seed and returns the 32-byte leaf key material. Path elements are plain child
// numbers; the hardened bit is applied automatically (Ed25519 is always
// hardened). For example DeriveSLIP10Ed25519(seed, 0, 0) walks m/0'/0'.
func DeriveSLIP10Ed25519(seed []byte, path ...uint32) ([]byte, error) {
	k := slip10Master(seed)
	for depth, index := range path {
		child, err := k.deriveHardened(index + HardenedOffset)
		if err != nil {
			return nil, fmt.Errorf("derive at depth %d: %w", depth, err)
		}
		k = child
	}
	out := make([]byte, 32)
	copy(out, k.key)
	return out, nil
}
