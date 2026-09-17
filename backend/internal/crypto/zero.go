package crypto

import "runtime"

// Zero overwrites b with zeros. The write is protected against dead-store
// elimination by a compiler barrier (runtime.KeepAlive after the loop), so
// the Go compiler cannot elide the zeroing even when b is never read again.
//
// Use this for all sensitive key material (mnemonics, private keys, shared
// secrets, derived keys). Calling Zero on a nil or zero-length slice is safe.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	// Force the compiler to treat b as live after the zeroing loop, preventing
	// dead-store elimination. runtime.KeepAlive is a compiler hint with zero
	// runtime cost.
	runtime.KeepAlive(b)
}
