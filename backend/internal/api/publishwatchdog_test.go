package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/tor"
)

// stuckOnion is a host whose descriptor never finishes publishing as far as
// Ready() is concerned, while outbound circuits are fine. It counts the service
// restarts the publish watchdog performs.
type stuckOnion struct {
	starts atomic.Int32
	stops  atomic.Int32
	alive  atomic.Bool
	ready  atomic.Bool

	mu     sync.Mutex
	stopAt []time.Time // when each restart landed, for the backoff test
}

// stopTimes returns a copy of the restart timestamps recorded so far.
func (o *stuckOnion) stopTimes() []time.Time {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]time.Time(nil), o.stopAt...)
}

func (o *stuckOnion) Start(context.Context, tor.OnionKey, string) (string, error) {
	o.starts.Add(1)
	o.alive.Store(true)
	return "stuck.onion", nil
}
func (o *stuckOnion) StopService() error {
	o.mu.Lock()
	o.stopAt = append(o.stopAt, time.Now())
	o.mu.Unlock()
	o.stops.Add(1)
	return nil
}

func (o *stuckOnion) IsAlive() bool                     { return o.alive.Load() }
func (o *stuckOnion) Ready() bool                       { return o.ready.Load() }
func (o *stuckOnion) Dialable() bool                    { return true }
func (o *stuckOnion) StartClient(context.Context) error { return nil }
func (o *stuckOnion) Sweep() error                      { return nil }
func (o *stuckOnion) Stop() error                       { o.alive.Store(false); return nil }
func (o *stuckOnion) Dialer() tor.Dialer                { return deadDialer{} }
func (o *stuckOnion) BootstrapFrac() float32            { return 1.0 }
func (o *stuckOnion) LogLines() []string                { return nil }

type deadDialer struct{}

func (deadDialer) DialOnion(context.Context, string) (net.Conn, error) {
	return nil, errors.New("no route in this test")
}

// newServerOnOnion builds a started-but-locked server on the given onion host,
// with the watchdog on millisecond timings so the real loop can be driven in a
// test. Unlock it with unlockWatchdogServer once any traffic generator is
// running — the watchdog starts as part of unlock.
func newServerOnOnion(t *testing.T, o tor.OnionService) *Server {
	t.Helper()
	store, err := identity.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(id, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	s := New(store, o)
	s.watchdogPollInterval = 2 * time.Millisecond
	s.watchdogPublishTimeout = 100 * time.Millisecond
	s.watchdogMaxPublishTimeout = 1 * time.Second
	s.watchdogDialWaitTimeout = 2 * time.Second
	if _, err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(nil) })
	return s
}

// unlockWatchdogServer unlocks and waits for the background Tor bring-up, which
// is what launches the publish watchdog.
func unlockWatchdogServer(t *testing.T, s *Server) {
	t.Helper()
	r := s.do(t, "POST", "/api/unlock", `{"password":"pw"}`, map[string]string{"Origin": s.origin()})
	if r.Code != http.StatusOK {
		t.Fatalf("unlock: %d", r.Code)
	}
	s.ready.Wait()
}

// hitOnionListener makes a request arrive on the onion-facing listener, the way
// a peer's request does once Arti has forwarded it over Tor.
func hitOnionListener(s *Server) error {
	resp, err := http.Get("http://" + s.publicAddr() + "/")
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// The regression: Ready() is one-directional (it mirrors Arti's
// is_fully_reachable, true only for Running/DegradedReachable), so a service
// that is serving perfectly well can report false — and the watchdog's restart
// is destructive, dropping intro points and the descriptor-signing keys. The
// phone showed exactly this: cycle after cycle of "stuck, restart attempt" while
// peers were landing inbound requests between the restarts. Peer traffic is
// proof of publication, so it must veto the restart.
func TestWatchdogLeavesServiceAloneWhilePeersReachUs(t *testing.T) {
	o := &stuckOnion{}
	s := newServerOnOnion(t, o)

	// Peers keep arriving from before the watchdog starts, so no publish window
	// is ever empty.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-time.After(s.watchdogPollInterval):
				_ = hitOnionListener(s) // a failed hit just means no traffic that tick
			}
		}
	}()
	unlockWatchdogServer(t, s)
	base := o.starts.Load()
	time.Sleep(6 * s.watchdogPublishTimeout)
	close(stop)
	<-done

	if got := o.stops.Load(); got != 0 {
		t.Fatalf("watchdog tore down a service that peers were reaching: %d StopService calls", got)
	}
	if got := o.starts.Load(); got != base {
		t.Fatalf("watchdog restarted a service that peers were reaching: %d extra Start calls", got-base)
	}
}

// The watchdog must still do its job when nothing is arriving: that is the
// genuinely stuck case it exists for.
func TestWatchdogRestartsWhenNothingArrives(t *testing.T) {
	o := &stuckOnion{}
	s := newServerOnOnion(t, o)
	unlockWatchdogServer(t, s)
	base := o.starts.Load()
	want := int32(s.watchdogMaxRestarts)

	deadline := time.Now().Add(5 * time.Second)
	for o.stops.Load() < want && time.Now().Before(deadline) {
		time.Sleep(s.watchdogPollInterval)
	}
	if got := o.stops.Load(); got != want {
		t.Fatalf("want %d restarts of a stuck service, got %d", want, got)
	}
	if got := o.starts.Load() - base; got != want {
		t.Fatalf("want %d re-Starts, got %d", want, got)
	}

	// And then it gives up rather than restarting forever.
	time.Sleep(4 * s.watchdogPublishTimeout)
	if got := o.stops.Load(); got != want {
		t.Fatalf("watchdog kept restarting past its limit: %d", got)
	}
}

// The other half of the phone's watchdog trouble, and the reason a fixed budget
// can't work: on a cold start nothing has ever reached us, so the peer-traffic
// veto cannot fire by construction, and a publish merely slower than the budget
// is indistinguishable from a stuck one. The phone restarted twice inside three
// minutes and then abandoned the service. Each attempt must therefore get more
// room than the one before it — a restart drops the intro points and signing
// keys, so attempt n+1 has strictly more to do than attempt n did.
func TestWatchdogBackoffGrowsBetweenRestarts(t *testing.T) {
	o := &stuckOnion{}
	s := newServerOnOnion(t, o)
	unlockWatchdogServer(t, s)

	want := s.watchdogMaxRestarts
	deadline := time.Now().Add(5 * time.Second)
	for len(o.stopTimes()) < want && time.Now().Before(deadline) {
		time.Sleep(s.watchdogPollInterval)
	}
	at := o.stopTimes()
	if len(at) < want {
		t.Fatalf("want %d restarts, got %d", want, len(at))
	}
	// A one-sided assertion: the gap can only stretch under load or -race, never
	// shrink, so this can't flake on a slow machine. The second attempt waited
	// publishBudget(1) == 2x the base timeout before giving up on it.
	gap := at[1].Sub(at[0])
	if min := s.watchdogPublishTimeout * 3 / 2; gap < min {
		t.Fatalf("second attempt got no more time than the first: gap %v, want >= %v", gap, min)
	}
}

func TestPublishBudgetDoublesUpToItsCap(t *testing.T) {
	s := &Server{watchdogPublishTimeout: 100 * time.Millisecond, watchdogMaxPublishTimeout: 500 * time.Millisecond}
	want := []time.Duration{100, 200, 400, 500, 500, 500}
	for attempt, ms := range want {
		if got := s.publishBudget(attempt); got != ms*time.Millisecond {
			t.Errorf("publishBudget(%d) = %v, want %v", attempt, got, ms*time.Millisecond)
		}
	}
	// Nothing here should be able to overflow or run away.
	if got := s.publishBudget(1 << 20); got != 500*time.Millisecond {
		t.Errorf("publishBudget(huge) = %v, want the cap", got)
	}
}

// 90s was the shipped first-publish budget, and real hardware showed it landing
// inside the window a normal cold publish needs: one run on the phone took 69s
// to reach its first inbound peer request with Ready() still false at 90s, and
// another spent that budget twice over and gave up. Guard the floor so it can't
// drift back down there.
func TestDefaultPublishBudgetClearsWhatRealHardwareNeeds(t *testing.T) {
	store, err := identity.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(store, nil)
	if got := s.watchdogPublishTimeout; got < 2*time.Minute {
		t.Errorf("first publish budget is %v, too tight for a cold mobile publish", got)
	}
	if s.watchdogMaxPublishTimeout < s.watchdogPublishTimeout {
		t.Errorf("cap %v is below the base budget %v", s.watchdogMaxPublishTimeout, s.watchdogPublishTimeout)
	}
	// The state veto only gets to act in the room between a budget expiring and
	// the ceiling. Let the ceiling drift down to the budget and the veto becomes
	// unreachable — the fix silently reverts to restarting mid-publish, with
	// every test still green, since the watchdog tests set their own timings and
	// leave this one at its default.
	if s.watchdogMaxPublishWait <= s.watchdogMaxPublishTimeout {
		t.Errorf("publish ceiling %v leaves no room above the per-attempt budget cap %v; the in-progress veto can never fire", s.watchdogMaxPublishWait, s.watchdogMaxPublishTimeout)
	}
}

// statefulOnion is a stuckOnion that can also answer the question the state
// veto asks — the way the Arti library binding does, and the desktop sidecar
// does not.
type statefulOnion struct {
	stuckOnion
	state atomic.Int32
}

func newStatefulOnion(st tor.ServiceState) *statefulOnion {
	o := &statefulOnion{}
	o.state.Store(int32(st))
	return o
}

func (o *statefulOnion) ServiceState() tor.ServiceState {
	return tor.ServiceState(o.state.Load())
}

// The bug this fixes, measured on hardware: the watchdog restarted a service
// whose publisher was actively retrying HSDir uploads, discarding 14 in-flight
// attempts and ~4 minutes of work, and the publish then needed another 6m35s
// from scratch. Nothing had ever reached us, so the peer-traffic veto could not
// fire — on a cold start it never can. The service's own state is the signal
// that works there.
func TestWatchdogWaitsWhileServiceReportsPublishInProgress(t *testing.T) {
	for _, st := range []tor.ServiceState{tor.StateBootstrapping, tor.StateDegradedUnreachable, tor.StateRecovering} {
		t.Run(st.String(), func(t *testing.T) {
			o := newStatefulOnion(st)
			s := newServerOnOnion(t, o)
			unlockWatchdogServer(t, s)
			base := o.starts.Load()

			// No peer traffic at all: only the state veto can hold the restart off.
			time.Sleep(6 * s.watchdogPublishTimeout)

			if got := o.stops.Load(); got != 0 {
				t.Fatalf("watchdog restarted a service that was mid-publish: %d StopService calls", got)
			}
			if got := o.starts.Load(); got != base {
				t.Fatalf("watchdog re-Started a service that was mid-publish: %d extra Start calls", got-base)
			}
		})
	}
}

// The other side of it: broken and shutdown are what a restart is for, and the
// veto must not swallow them.
func TestWatchdogRestartsWhenServiceReportsRestartWorthy(t *testing.T) {
	for _, st := range []tor.ServiceState{tor.StateBroken, tor.StateShutdown} {
		t.Run(st.String(), func(t *testing.T) {
			o := newStatefulOnion(st)
			s := newServerOnOnion(t, o)
			unlockWatchdogServer(t, s)
			base := o.starts.Load()
			want := int32(s.watchdogMaxRestarts)

			deadline := time.Now().Add(5 * time.Second)
			for o.stops.Load() < want && time.Now().Before(deadline) {
				time.Sleep(s.watchdogPollInterval)
			}
			if got := o.stops.Load(); got != want {
				t.Fatalf("want %d restarts of a %s service, got %d", want, st, got)
			}
			if got := o.starts.Load() - base; got != want {
				t.Fatalf("want %d re-Starts, got %d", want, got)
			}
		})
	}
}

// The ceiling that keeps the veto from becoming a way to never restart. A
// service reporting progress forever while publishing nothing is stuck
// whatever it says about itself, and the recovery the watchdog exists to
// provide has to survive this change.
func TestWatchdogRestartsOncePublishPassesTheCeiling(t *testing.T) {
	o := newStatefulOnion(tor.StateBootstrapping)
	s := newServerOnOnion(t, o)
	// Above the publish budget, as in production (30m against 4m): the veto
	// fires, resets the publish window, expires again, and only then does the
	// ceiling trip. That repeat is the path the phone will actually take, and a
	// ceiling set below the budget would never enter it.
	s.watchdogMaxPublishWait = 3 * s.watchdogPublishTimeout
	unlockWatchdogServer(t, s)

	// It must hold off while the ceiling has room — one budget's worth of veto
	// at least, which a ceiling that trips on first expiry would skip.
	time.Sleep(2 * s.watchdogPublishTimeout)
	if got := o.stops.Load(); got != 0 {
		t.Fatalf("ceiling tripped before it was reached: %d restarts", got)
	}

	want := int32(s.watchdogMaxRestarts)
	deadline := time.Now().Add(10 * time.Second)
	for o.stops.Load() < want && time.Now().Before(deadline) {
		time.Sleep(s.watchdogPollInterval)
	}
	if got := o.stops.Load(); got != want {
		t.Fatalf("a service past the publish ceiling was never restarted: %d of %d", got, want)
	}
}

// A publish that reports progress and then lands must not be restarted, and the
// watchdog must stop watching rather than sit in the veto forever.
func TestWatchdogStopsOnceAnInProgressPublishLands(t *testing.T) {
	o := newStatefulOnion(tor.StateDegradedUnreachable)
	s := newServerOnOnion(t, o)
	unlockWatchdogServer(t, s)
	base := o.starts.Load()

	// Let the veto hold at least one budget off, then publish.
	time.Sleep(2 * s.watchdogPublishTimeout)
	o.ready.Store(true)
	o.state.Store(int32(tor.StateRunning))
	time.Sleep(4 * s.watchdogPublishTimeout)

	if got := o.stops.Load(); got != 0 {
		t.Fatalf("watchdog restarted a publish that landed: %d StopService calls", got)
	}
	if got := o.starts.Load(); got != base {
		t.Fatalf("watchdog re-Started after the publish landed: %d extra Start calls", got-base)
	}
}

// Two ways the answer can be unusable — an implementation that cannot report
// (desktop's log-scraping sidecar, the nil stub) and a state this build does
// not recognise. Both must read as "no information", so the watchdog falls back
// to the peer-traffic rule rather than treating silence as either answer.
func TestServiceStateIsUnusableWithoutARealAnswer(t *testing.T) {
	s := &Server{onion: &stuckOnion{}}
	if st, known := s.serviceState(); known {
		t.Errorf("a service that cannot report state answered %s", st)
	}
	s.onion = nil
	if _, known := s.serviceState(); known {
		t.Errorf("a nil onion answered")
	}
	// Code 99: a state a future arti might report that this build has no arm for.
	s.onion = newStatefulOnion(tor.ServiceState(0))
	if _, known := s.serviceState(); known {
		t.Errorf("StateUnknown was treated as an answer")
	}
}
