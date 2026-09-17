package api

import (
	"sync"
	"testing"
)

// A wipe (forget / duress / failed-attempts erase) swaps s.device/s.pin/s.guard
// via reloadDeviceState while request handlers read them. Both sides must go
// through devMu, or the read on the unlock hot path (currentGuard/currentPin in
// guardedLoad, pinEnabled) races the swap. Run under -race; it panicked the
// detector before the devMu guard was added.
func TestReloadDeviceStateHasNoFieldRace(t *testing.T) {
	s, _ := newTestServer(t)

	const iters = 3000
	var wg sync.WaitGroup
	wg.Add(2)

	// Writer: exactly what removeAccountFromDevice runs at the end of a wipe.
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			s.reloadDeviceState()
		}
	}()

	// Reader: the cheap per-device pointer reads the request paths perform
	// (guardedLoad's backoff check, pinEnabled), minus the Argon2 that store.Load
	// would add — the field access is what races, not the derivation.
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			if g := s.currentGuard(); g != nil {
				_ = g.Backoff()
			}
			_ = s.pinEnabled()
			_ = s.currentDevice()
		}
	}()

	wg.Wait()
}
