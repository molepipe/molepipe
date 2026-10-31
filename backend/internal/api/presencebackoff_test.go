package api

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/tor"
)

// countingOnion is readyOnion with a dial counter. The count is the whole point
// of these tests: the backoff's only observable effect is that a sweep stops
// spending dials on a contact, and a dial is exactly what fixedDialer's target
// callback marks. Asserting on presence state instead would prove nothing —
// a skipped contact keeps the state it already had.
type countingOnion struct {
	dials atomic.Int64
	ready atomic.Bool
}

func (o *countingOnion) Start(context.Context, tor.OnionKey, string) (string, error) {
	return "test.onion", nil
}
func (o *countingOnion) Ready() bool                       { return o.ready.Load() }
func (o *countingOnion) Dialable() bool                    { return true }
func (o *countingOnion) StartClient(context.Context) error { return nil }
func (o *countingOnion) Sweep() error                      { return nil }
func (o *countingOnion) Stop() error                       { return nil }
func (o *countingOnion) BootstrapFrac() float32            { return 1.0 }
func (o *countingOnion) LogLines() []string                { return nil }
func (o *countingOnion) Dialer() tor.Dialer {
	// Nothing listens on port 1, so every probe fails fast — the offline contact
	// this whole mechanism exists for.
	return fixedDialer{func() string { o.dials.Add(1); return "127.0.0.1:1" }}
}

// backoffTestServer returns an unlocked server with one accepted, unreachable
// contact, plus the live identity the sweep needs.
func backoffTestServer(t *testing.T, published bool) (*Server, *countingOnion, *identity.Identity, string) {
	t.Helper()
	onion := &countingOnion{}
	onion.ready.Store(published)
	s := newServerOnOnion(t, onion)
	tok := unlockOn(t, s)
	id, ok := s.vault.get(tok)
	if !ok {
		t.Fatal("session did not validate")
	}
	peer, _ := identity.New()
	acct := peer.AccountNumber()
	s.sessMu.Lock()
	s.contacts[acct] = chatstore.Contact{Account: acct, Status: chatstore.StatusAccepted}
	s.sessMu.Unlock()
	return s, onion, id, acct
}

func dueNow(s *Server, acct string) bool {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	return s.probeDueLocked(acct)
}

// The headline property: a contact who stays unreachable stops costing a dial
// on every sweep. The first probeBackoffGrace failures are still probed at full
// cadence (a lone failure is usually our circuit, not their absence), so the
// dot still reaches offline as fast as it ever did — it is the sweeps after
// that which get skipped.
func TestSweepStopsDialingAnOfflineContact(t *testing.T) {
	s, onion, id, acct := backoffTestServer(t, true)

	for i := 0; i < probeBackoffGrace+3; i++ {
		s.probeAllContacts(context.Background(), id)
	}
	// grace+1 probes land: the failures within grace, plus the one that trips the
	// backoff. Every sweep after that is skipped, because even the first backoff
	// window (2x presenceInterval) outlasts this loop.
	if got, want := onion.dials.Load(), int64(probeBackoffGrace+1); got != want {
		t.Errorf("dials across %d sweeps = %d, want %d (backoff not engaging)",
			probeBackoffGrace+3, got, want)
	}

	// ...and the skip is a WINDOW, not a latch. Nothing above distinguishes
	// "backed off until nextAt" from "never probed again", because the sweeps run
	// microseconds apart and any non-zero window swallows them all. Rewinding
	// nextAt is the only way to assert the contact comes back round without
	// sleeping out a real interval. (The window's LENGTH is pinned separately, by
	// TestBackoffScheduleDoublesAndCaps.)
	before := onion.dials.Load()
	s.sessMu.Lock()
	b := s.probeBackoff[acct]
	b.nextAt = time.Now().Add(-time.Second)
	s.probeBackoff[acct] = b
	s.sessMu.Unlock()

	s.probeAllContacts(context.Background(), id)
	if got := onion.dials.Load(); got != before+1 {
		t.Errorf("dials after the window elapsed = %d, want %d — the backoff is a latch, not a window", got, before+1)
	}
}

// The grace window must actually probe. A backoff that kicked in on the first
// failure would turn a one-off circuit error into a minutes-long stale dot.
func TestGraceSweepsAreNotSkipped(t *testing.T) {
	s, onion, id, _ := backoffTestServer(t, true)

	for i := 0; i < probeBackoffGrace; i++ {
		s.probeAllContacts(context.Background(), id)
		if got, want := onion.dials.Load(), int64(i+1); got != want {
			t.Fatalf("after %d sweeps dials = %d, want %d — a grace sweep was skipped", i+1, got, want)
		}
	}
}

// While our own descriptor is unpublished the probe is carrying our presence
// hello, which is the only way a contact learns we are up before we reach the
// HSDir ring. The backoff must not throttle that: an unpublished device probes
// everyone every sweep, however long they have been unreachable.
// TestOnionFlapDoesNotReopenTheBackoff pins the field regression that made the
// backoff worth about 2x instead of 10x.
//
// The announcing gate above is a deliberate hole in the backoff: while we are
// unpublished every sweep must dial, because the hello it carries is the only
// way a contact learns we exist. But "unpublished" was read live off Ready(),
// and Ready() dips to false on every intro-point re-establishment — 24 times in
// 12 minutes on the phone on 2026-10-20. Each dip reopened the hole, so a device
// published for minutes kept sweeping at full cadence and five contacts hit the
// backoff cap in 4m34s on a schedule that needs 8 minutes.
//
// The dip must therefore cost nothing. A descriptor already on the HSDirs does
// not come off them because the service rebuilt a circuit.
func TestOnionFlapDoesNotReopenTheBackoff(t *testing.T) {
	s, onion, id, _ := backoffTestServer(t, true)

	for i := 0; i < probeBackoffGrace+3; i++ {
		s.probeAllContacts(context.Background(), id)
	}
	backedOff := onion.dials.Load()
	if backedOff != int64(probeBackoffGrace+1) {
		t.Fatalf("harness precondition: dials = %d, want %d (backoff never engaged)", backedOff, probeBackoffGrace+1)
	}

	// The flap: Ready() goes false on a service that never stopped serving.
	onion.ready.Store(false)
	if s.announcing() {
		t.Fatal("a Ready() dip re-armed announcing — the publish latch is being re-tested, not latched")
	}
	for i := 0; i < 3; i++ {
		s.probeAllContacts(context.Background(), id)
	}
	if got := onion.dials.Load(); got != backedOff {
		t.Errorf("dials across 3 sweeps during a Ready() dip = %d, want %d (the flap is cancelling the backoff)", got, backedOff)
	}

	// A real teardown is different in kind: the descriptor is gone and has to be
	// re-published, so the hole reopens and the sweep announces again.
	s.forgetReachEvidence()
	if !s.announcing() {
		t.Fatal("a republish did not re-arm announcing — the latch is never cleared")
	}
	s.probeAllContacts(context.Background(), id)
	if got := onion.dials.Load(); got != backedOff+1 {
		t.Errorf("dials after a republish = %d, want %d (a new publication must announce)", got, backedOff+1)
	}
}

func TestAnnouncingSweepIgnoresTheBackoff(t *testing.T) {
	s, onion, id, _ := backoffTestServer(t, false) // unpublished => announcing
	if !s.announcing() {
		t.Fatal("harness precondition: expected the server to be announcing")
	}

	sweeps := probeBackoffGrace + 3
	for i := 0; i < sweeps; i++ {
		s.probeAllContacts(context.Background(), id)
	}
	if got := onion.dials.Load(); got != int64(sweeps) {
		t.Errorf("dials while announcing = %d, want %d (one per sweep — the backoff must not gate hellos)", got, sweeps)
	}
}

// Authenticated inbound traffic or a successful direct send is proof the peer is
// up, so it voids the backoff outright: the next sweep dials them at full
// cadence instead of waiting out a window accrued while they were gone. This
// reset is what makes the backoff affordable — a peer who interacts with us is
// never subject to it.
func TestInboundTrafficClearsTheBackoff(t *testing.T) {
	s, onion, id, acct := backoffTestServer(t, true)

	for i := 0; i < probeBackoffGrace+2; i++ {
		s.probeAllContacts(context.Background(), id)
	}
	if dueNow(s, acct) {
		t.Fatal("precondition: contact should be backed off by now")
	}
	before := onion.dials.Load()

	s.sessMu.Lock()
	s.touchPeerPresenceLocked(acct, "direct message")
	s.sessMu.Unlock()

	if !dueNow(s, acct) {
		t.Error("inbound traffic did not clear the probe backoff")
	}
	// And the sweep acts on it. Presence is online off the back of the touch, so
	// this also covers the online guard: an online contact is always probed.
	s.probeAllContacts(context.Background(), id)
	if got := onion.dials.Load(); got != before+1 {
		t.Errorf("dials after a touch = %d, want %d", got, before+1)
	}
}

// A contact held online by a fresh hello is failing our probes while reaching us
// fine — asymmetric reachability resolving. That is the one contact we most want
// to keep re-testing, so it never accrues a backoff, and the state cannot sit
// green past helloStickiness with nothing left to demote it.
func TestHelloHeldContactKeepsFullProbeCadence(t *testing.T) {
	s, onion, id, acct := backoffTestServer(t, true)
	s.sessMu.Lock()
	s.helloAt = map[string]time.Time{acct: time.Now()}
	s.sessMu.Unlock()

	sweeps := probeBackoffGrace + 3
	for i := 0; i < sweeps; i++ {
		s.probeAllContacts(context.Background(), id)
	}
	if got := presenceOf(s, acct); got != presenceOnline {
		t.Fatalf("precondition: hello should hold presence online, got %q", got)
	}
	if got := onion.dials.Load(); got != int64(sweeps) {
		t.Errorf("dials for a hello-held contact = %d, want %d (one per sweep)", got, sweeps)
	}
}

// ...and once the hello goes stale the backoff accrues normally, so the hold is
// a window and not a way to opt out of the backoff forever.
func TestStaleHelloResumesTheBackoff(t *testing.T) {
	s, onion, id, acct := backoffTestServer(t, true)
	s.sessMu.Lock()
	s.helloAt = map[string]time.Time{acct: time.Now().Add(-helloStickiness - time.Second)}
	s.sessMu.Unlock()

	for i := 0; i < probeBackoffGrace+3; i++ {
		s.probeAllContacts(context.Background(), id)
	}
	if got, want := onion.dials.Load(), int64(probeBackoffGrace+1); got != want {
		t.Errorf("dials with a stale hello = %d, want %d (backoff should apply)", got, want)
	}
}

// The schedule itself: doubling from presenceInterval, capped, and the cap holds
// however long the streak runs — a session-long outage must not let the delay
// grow without bound (or overflow the doubling).
func TestBackoffScheduleDoublesAndCaps(t *testing.T) {
	s, _, _, acct := backoffTestServer(t, true)

	want := []time.Duration{}
	for d := 2 * presenceInterval; d < probeBackoffMax; d *= 2 {
		want = append(want, d)
	}
	want = append(want, probeBackoffMax, probeBackoffMax, probeBackoffMax)

	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	for i := 0; i < probeBackoffGrace; i++ {
		s.recordProbeOutcomeLocked(acct, presenceOffline)
		if got := s.probeBackoff[acct].nextAt; !got.IsZero() {
			t.Fatalf("failure %d set nextAt = %v, want zero (still within grace)", i+1, got)
		}
	}
	for i, w := range want {
		start := time.Now()
		s.recordProbeOutcomeLocked(acct, presenceOffline)
		got := s.probeBackoff[acct].nextAt.Sub(start)
		// Tolerance absorbs the wall clock between start and the call's time.Now().
		if got < w || got > w+time.Second {
			t.Errorf("failure %d pushed the next probe out %v, want ~%v", probeBackoffGrace+i+1, got, w)
		}
	}
	if !s.probeBackoff[acct].capped {
		t.Error("the cap was reached but never marked, so the field log line never fires")
	}
}

// A contact removed mid-probe takes its backoff entry with it, so re-adding the
// same account later starts clean instead of inheriting a stale skip window.
func TestRemovedContactDropsItsBackoffEntry(t *testing.T) {
	s, _, id, acct := backoffTestServer(t, true)
	for i := 0; i < probeBackoffGrace+1; i++ {
		s.probeAllContacts(context.Background(), id)
	}
	s.sessMu.Lock()
	if _, ok := s.probeBackoff[acct]; !ok {
		s.sessMu.Unlock()
		t.Fatal("precondition: expected a backoff entry")
	}
	delete(s.contacts, acct)
	s.sessMu.Unlock()

	s.probeContact(context.Background(), id, acct)

	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if _, ok := s.probeBackoff[acct]; ok {
		t.Error("backoff entry survived the contact being removed")
	}
}
