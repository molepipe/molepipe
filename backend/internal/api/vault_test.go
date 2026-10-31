package api

import (
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

// newVaultSession unlocks v with a fresh identity and returns the session token
// and the generation that unlock produced.
func newVaultSession(t *testing.T, v *vault) (string, uint64) {
	t.Helper()
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := v.unlock(id)
	if err != nil {
		t.Fatal(err)
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return tok, v.gen
}

// idleOut backdates the session past maxSessionIdle, the same way
// expireSession does for the server-level tests.
func idleOut(v *vault) {
	v.lastActivity.Store(time.Now().Add(-2 * maxSessionIdle).UnixNano())
}

// get() notices an expiry under a read lock and hands the teardown to a
// goroutine, which on a throttled process can be scheduled long after the user
// has unlocked again. The teardown is the full lock path, so landing on the
// wrong session does not merely log the user out — it zeroizes the identity
// that session is already using. The generation it carries is what stops it.
func TestAStaleExpiryLeavesTheNewSessionAlone(t *testing.T) {
	v := &vault{}
	tok1, gen1 := newVaultSession(t, v)

	idleOut(v)
	if _, ok := v.get(tok1); ok {
		t.Fatal("an idled-out session still validated")
	}

	// The user unlocks again before the queued teardown gets scheduled.
	tok2, gen2 := newVaultSession(t, v)
	if gen2 == gen1 {
		t.Fatalf("unlock did not advance the generation (still %d)", gen2)
	}
	id2, ok := v.get(tok2)
	if !ok {
		t.Fatal("the fresh session did not validate")
	}
	alias2, err := id2.AliasAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	// Now it runs, still asking for the session it saw expire.
	v.expire(gen1)

	id, ok := v.get(tok2)
	if !ok {
		t.Fatal("a stale expiry tore down the session unlocked after it")
	}
	// Not just still validating: the key material the live session is using
	// must not have been zeroized underneath it. AliasAccount recomputes the
	// seed from the mnemonic, which is exactly what Zeroize nils, so it fails
	// (or answers differently) on an identity the teardown has been through.
	if got, err := id.AliasAccount(0); err != nil || got != alias2 {
		t.Fatalf("the live identity was zeroized by the stale expiry: %q, %v", got, err)
	}
	if _, ok := v.get(tok1); ok {
		t.Fatal("the expired session's token still validates")
	}
}

// A genuine expiry must still tear the session down, and the several goroutines
// that concurrent requests can start for one expiry must add up to a single
// teardown — the first one clears the identity, so the rest fall out of the
// same check that stops a stale one.
func TestAGenuineExpiryTearsDownExactlyOnce(t *testing.T) {
	v := &vault{}
	calls := 0
	v.onExpire = func() {
		calls++
		v.lock()
	}

	tok, gen := newVaultSession(t, v)
	idleOut(v)

	for i := 0; i < 3; i++ {
		v.expire(gen)
	}
	if calls != 1 {
		t.Fatalf("three observers of one expiry ran %d teardowns, want 1", calls)
	}
	if v.unlocked() {
		t.Fatal("an expired session was left unlocked")
	}
	if _, ok := v.get(tok); ok {
		t.Fatal("an expired session still validates after teardown")
	}
}
