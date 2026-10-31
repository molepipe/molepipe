package api

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/tor"
)

// servingOnion models the part of artihost.Host that matters here: it remembers
// which key the live service is published under, the way the real host now
// does, and counts the teardowns and publishes a caller provokes.
type servingOnion struct {
	stuckOnion
	pub     atomic.Value // [32]byte
	addr    atomic.Value // string
	running atomic.Bool
}

func newServingOnion(pub [32]byte, addr string) *servingOnion {
	o := &servingOnion{}
	o.pub.Store(pub)
	o.addr.Store(addr)
	o.running.Store(true)
	o.alive.Store(true)
	return o
}

func (o *servingOnion) ServingKey() ([32]byte, string, bool) {
	if !o.running.Load() {
		return [32]byte{}, "", false
	}
	return o.pub.Load().([32]byte), o.addr.Load().(string), true
}

func (o *servingOnion) StopService() error {
	o.running.Store(false)
	return o.stuckOnion.StopService()
}

func (o *servingOnion) Start(ctx context.Context, key tor.OnionKey, addr string) (string, error) {
	o.pub.Store(key.Public)
	o.addr.Store("republished.onion")
	o.running.Store(true)
	return o.stuckOnion.Start(ctx, key, addr)
}

func keyWithPublic(b byte) tor.OnionKey {
	var k tor.OnionKey
	k.Public[0] = b
	return k
}

// The waste this closes, from the 10/19 emulator run log: a PIN unlock at
// 17:11:28 tore down a service that had been published for 41 hours and spent
// 25s rebuilding the identical descriptor — 17:11:31 Shutdown, 17:11:31
// Bootstrapping, 17:11:56 Running. Only two Shutdown events occurred in 42.7
// hours and both were the two unlocks; nothing else ever tore the service down.
// A republish throws away the established intro points and both HSDir rings to
// arrive back at the same .onion.
func TestUnlockKeepsAServiceAlreadyPublishedUnderTheSameKey(t *testing.T) {
	key := keyWithPublic(1)
	o := newServingOnion(key.Public, "already.onion")
	s := newServerOnOnion(t, o)

	if err := s.startOnion(key); err != nil {
		t.Fatalf("startOnion: %v", err)
	}

	if got := o.stops.Load(); got != 0 {
		t.Errorf("tore down a service already published under this key: %d StopService calls", got)
	}
	if got := o.starts.Load(); got != 0 {
		t.Errorf("re-published a service that was already up: %d Start calls", got)
	}
	s.onionMu.Lock()
	addr := s.onionAddr
	s.onionMu.Unlock()
	if addr != "already.onion" {
		t.Errorf("onionAddr = %q, want the address the live service is published under", addr)
	}
}

// Reuse keeps the SAME descriptor on the HSDirs, so evidence that peers could
// reach it still describes something that is out there — the same reasoning the
// grace path already relies on. Dropping it here would report "publishing your
// address" for a service that never stopped being published.
func TestReusingAPublishedServiceKeepsReachEvidence(t *testing.T) {
	key := keyWithPublic(1)
	s := newServerOnOnion(t, newServingOnion(key.Public, "already.onion"))
	if err := hitOnionListener(s); err != nil {
		t.Fatalf("peer request to the onion listener: %v", err)
	}
	if !s.reachProven.Load() {
		t.Fatal("peer hit not recorded — the test cannot show the reuse")
	}

	if err := s.startOnion(key); err != nil {
		t.Fatalf("startOnion: %v", err)
	}

	if !s.reachProven.Load() {
		t.Error("reuse forgot the reach evidence, so a re-unlock onto a still-published service reports unreachable")
	}
}

// The reuse must be keyed on WHICH service is published, not merely on whether
// something is. Re-unlocking the same account is not the only way into
// startOnion: handleDuress calls finishUnlock with a decoy identity, and a
// restore and a pairing each arrive with a different one, all in the same
// process. Reusing there would leave the previous account's descriptor serving
// under a service the caller believes it replaced — for the duress decoy, it
// would keep publishing the very account the user just tried to make disappear.
func TestADifferentIdentityRepublishesInsteadOfReusing(t *testing.T) {
	o := newServingOnion(keyWithPublic(1).Public, "real.onion")
	s := newServerOnOnion(t, o)
	if err := hitOnionListener(s); err != nil {
		t.Fatalf("peer request to the onion listener: %v", err)
	}

	if err := s.startOnion(keyWithPublic(2)); err != nil { // the decoy
		t.Fatalf("startOnion: %v", err)
	}

	if got := o.stops.Load(); got == 0 {
		t.Error("kept the previous identity's published service when asked to publish a different key")
	}
	if got := o.starts.Load(); got == 0 {
		t.Error("never published the new key")
	}
	if s.reachProven.Load() {
		t.Error("reach evidence from the previous service survived a republish under a different key")
	}
}

// Nothing published means nothing to reuse: the pair the host reports is only
// meaningful while a service is live, and a stopped host reports running=false
// precisely so a stale pair cannot vouch for a service that is gone.
func TestNoLiveServiceMeansAFullPublish(t *testing.T) {
	key := keyWithPublic(1)
	o := newServingOnion(key.Public, "gone.onion")
	o.running.Store(false) // e.g. a grace teardown already fired
	s := newServerOnOnion(t, o)

	if err := s.startOnion(key); err != nil {
		t.Fatalf("startOnion: %v", err)
	}

	if got := o.starts.Load(); got == 0 {
		t.Error("skipped the publish although nothing was published")
	}
}

// A host that cannot answer the question keeps the old behaviour rather than
// guessing — the desktop sidecar does not implement ServingKey, and silently
// treating "cannot tell" as "already published" would leave it never publishing
// at all.
func TestAHostThatCannotReportItsServiceStillPublishes(t *testing.T) {
	o := newStatefulOnion(tor.StateRunning) // no ServingKey method
	s := newServerOnOnion(t, o)

	if err := s.startOnion(keyWithPublic(1)); err != nil {
		t.Fatalf("startOnion: %v", err)
	}

	if got := o.starts.Load(); got == 0 {
		t.Error("a host that cannot report its serving key was treated as already published")
	}
}

// Only the primary publishes the account onion — a secondary publishing the
// same key would collide with it on the HSDir hashring. So a device that holds
// a published service and is then demoted must still fall through to the
// secondary path and stop serving, never reuse.
func TestASecondaryDoesNotReuseAPublishedService(t *testing.T) {
	key := keyWithPublic(1)
	o := newServingOnion(key.Public, "already.onion")
	s := newServerOnOnion(t, o)
	s.devMu.Lock()
	s.device.Role = "secondary"
	s.devMu.Unlock()
	if s.currentDevice().IsPrimary() {
		t.Fatal("device still reports primary — the test cannot show the secondary path")
	}

	if err := s.startOnion(key); err != nil {
		t.Fatalf("startOnion: %v", err)
	}

	if got := o.stops.Load(); got == 0 {
		t.Error("a demoted device kept publishing the account onion")
	}
}

// unlockOn unlocks a server built by newServerOnOnion and returns the session
// token, waiting for the background Tor bring-up so nothing is still writing to
// the server when the caller starts poking at it.
func unlockOn(t *testing.T, s *Server) string {
	t.Helper()
	r := s.do(t, "POST", "/api/unlock", `{"password":"pw"}`, map[string]string{"Origin": s.origin()})
	tok, _ := decode(t, r.Body)["session_token"].(string)
	if tok == "" {
		t.Fatalf("unlock returned no token (%d)", r.Code)
	}
	s.ready.Wait()
	return tok
}

// expireSession idles the session past maxSessionIdle and then touches it the
// way any authenticated request does, which is what notices the expiry.
func expireSession(t *testing.T, s *Server, tok string) {
	t.Helper()
	s.vault.lastActivity.Store(time.Now().Add(-2 * maxSessionIdle).UnixNano())
	if _, ok := s.vault.get(tok); ok {
		t.Fatal("an idled-out session still validated")
	}
}

// Lever 2. An expired session used to call a bare vault.lock(), which zeroed
// the identity and nothing else: the onion stayed published, the session loops
// and publish watchdog kept running against an empty vault, and no lock-grace
// was armed so the next unlock paid a full republish. The 10/19 log shows the
// consequence — a service still serving 41 hours after its session ended, which
// also means StopService's keystore wipe ("so the onion key does not outlive
// the session") had never run. An expiry must end a session the same way the
// user ending it does.
func TestAnExpiredSessionTakesTheWholeLockPath(t *testing.T) {
	s := newServerOnOnion(t, newServingOnion(keyWithPublic(1).Public, "already.onion"))
	tok := unlockOn(t, s)
	s.sessMu.Lock()
	live := s.sessID != nil
	s.sessMu.Unlock()
	if !live {
		t.Fatal("no session state after unlock — the test cannot show it being cleared")
	}

	expireSession(t, s, tok)

	// The teardown runs in the background: vault.get holds a read lock and the
	// lock path needs the write lock.
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.sessMu.Lock()
		cleared := s.sessID == nil
		s.sessMu.Unlock()
		if cleared {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("session state survived the expiry: only the identity was zeroed, so the loops and the publish watchdog kept running against an empty vault")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The other half of lever 2: the expiry arms the lock-grace, so the onion it
// leaves published is bounded rather than left up for as long as the process
// lives.
func TestAnExpiredSessionBoundsThePublishedOnion(t *testing.T) {
	old := graceWindow
	graceWindow = 20 * time.Millisecond
	t.Cleanup(func() { graceWindow = old })

	o := newServingOnion(keyWithPublic(1).Public, "already.onion")
	s := newServerOnOnion(t, o)
	tok := unlockOn(t, s)
	if !o.alive.Load() {
		t.Fatal("no live service after unlock — the test cannot show it coming down")
	}

	expireSession(t, s, tok)

	deadline := time.Now().Add(2 * time.Second)
	for !time.Now().After(deadline) {
		if !o.alive.Load() {
			return // the grace fired and the service came down
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Error("the onion stayed published indefinitely after the session expired; the keystore wipe that bounds the onion key's lifetime never runs")
}
