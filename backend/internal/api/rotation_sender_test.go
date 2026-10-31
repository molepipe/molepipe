package api

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/tor"
)

// fakeExtraHost is a tor.OnionService that also implements extraOnionHost, so the
// api-layer upcast (asExtraOnionHost) reaches it. StartExtraService returns the
// account that the given key actually names (as the real host would), so the
// onion a caller derives from an alias index matches what publication reports.
type fakeExtraHost struct {
	mu       sync.Mutex
	nextID   uint64
	starts   []string          // onions started, in order (incl. any it then stops)
	live     map[uint64]string // id -> onion currently up
	stopped  []uint64
	startErr error
}

func (h *fakeExtraHost) StartExtraService(key tor.OnionKey, localAddr, nickname string) (string, uint64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.startErr != nil {
		return "", 0, h.startErr
	}
	onion := identity.AccountNumberForPub(key.Public[:])
	h.nextID++
	if h.live == nil {
		h.live = map[uint64]string{}
	}
	h.live[h.nextID] = onion
	h.starts = append(h.starts, onion)
	return onion, h.nextID, nil
}

func (h *fakeExtraHost) StopExtraService(id uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stopped = append(h.stopped, id)
	delete(h.live, id)
}

func (h *fakeExtraHost) startCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.starts)
}

// tor.OnionService stubs — unused by the rotation orchestration under test.
func (h *fakeExtraHost) Start(context.Context, tor.OnionKey, string) (string, error) {
	return "", nil
}
func (h *fakeExtraHost) StartClient(context.Context) error { return nil }
func (h *fakeExtraHost) Ready() bool                       { return true }
func (h *fakeExtraHost) Dialable() bool                    { return true }
func (h *fakeExtraHost) Dialer() tor.Dialer                { return nil }
func (h *fakeExtraHost) Sweep() error                      { return nil }
func (h *fakeExtraHost) Stop() error                       { return nil }
func (h *fakeExtraHost) BootstrapFrac() float32            { return 1 }
func (h *fakeExtraHost) LogLines() []string                { return nil }

func rotationTestServer(host tor.OnionService) *Server {
	return &Server{
		onion:            host,
		contacts:         map[string]chatstore.Contact{},
		pendingRotations: map[string]chatstore.RotationPending{},
		aliasServiceIDs:  map[string]uint64{},
	}
}

// The first rotation from a nil RotationState is the existing-identity migration:
// it mints alias index 0 as a FRESH alias (never the primary account), publishes
// it, makes it current, and enqueues an ack-driven rotation to accepted contacts
// only.
func TestPerformRotationFromNilMintsFreshIndexZero(t *testing.T) {
	idn, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	host := &fakeExtraHost{}
	s := rotationTestServer(host)
	s.contacts["alice"] = chatstore.Contact{Account: "alice", Status: chatstore.StatusAccepted}
	s.contacts["bob"] = chatstore.Contact{Account: "bob", Status: chatstore.StatusPendingIn}

	s.sessMu.Lock()
	onion, err := s.performRotationLocked(idn)
	s.sessMu.Unlock()
	if err != nil {
		t.Fatalf("performRotationLocked: %v", err)
	}

	want0, _ := idn.AliasAccount(0)
	if onion != want0 {
		t.Fatalf("onion = %s, want alias-0 %s", onion, want0)
	}
	if onion == idn.AccountNumber() {
		t.Fatal("index 0 must be a fresh alias, NEVER the primary account")
	}
	if s.rotation == nil || s.rotation.CurrentIndex != 0 || s.rotation.CurrentAccount != onion {
		t.Fatalf("rotation state = %+v, want index 0 / account %s", s.rotation, onion)
	}
	if len(s.rotation.History) != 0 {
		t.Fatalf("history = %v, want empty on first rotation", s.rotation.History)
	}
	if got := s.rotation.NextRefreshAt.Sub(time.Now()); got < 6*24*time.Hour || got > 8*24*time.Hour {
		t.Fatalf("NextRefreshAt in %v, want ~1 week", got)
	}
	if s.aliasServiceIDs[onion] == 0 {
		t.Fatalf("service id not recorded for %s", onion)
	}
	if len(s.localAliasAccounts) != 1 || s.localAliasAccounts[0] != onion {
		t.Fatalf("localAliasAccounts = %v, want [%s]", s.localAliasAccounts, onion)
	}
	// Ack-driven delivery enqueued for the accepted contact only.
	if pr, ok := s.pendingRotations["alice"]; !ok || pr.NewOnion != onion || pr.AliasIndex != 0 {
		t.Fatalf("pendingRotations[alice] = %+v (ok=%v), want {%s,0}", pr, ok, onion)
	}
	if _, ok := s.pendingRotations["bob"]; ok {
		t.Fatal("pending (non-accepted) contact must not be enqueued")
	}
}

// A second rotation advances the index, retires the previous current alias into
// History with a 7-day grace deadline (kept live), and supersedes the pending ack.
func TestPerformRotationAdvancesAndGraces(t *testing.T) {
	idn, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	host := &fakeExtraHost{}
	s := rotationTestServer(host)
	s.contacts["alice"] = chatstore.Contact{Account: "alice", Status: chatstore.StatusAccepted}

	s.sessMu.Lock()
	onion0, err := s.performRotationLocked(idn)
	if err == nil {
		_, err = s.performRotationLocked(idn)
	}
	s.sessMu.Unlock()
	if err != nil {
		t.Fatalf("performRotationLocked: %v", err)
	}

	onion1, _ := idn.AliasAccount(1)
	if s.rotation.CurrentIndex != 1 || s.rotation.CurrentAccount != onion1 {
		t.Fatalf("rotation = %+v, want index 1 / %s", s.rotation, onion1)
	}
	if len(s.rotation.History) != 1 {
		t.Fatalf("history len = %d, want 1", len(s.rotation.History))
	}
	h := s.rotation.History[0]
	if h.Index != 0 || h.Account != onion0 {
		t.Fatalf("history[0] = %+v, want {0, %s}", h, onion0)
	}
	if got := h.RetireAt.Sub(time.Now()); got < 6*24*time.Hour || got > 8*24*time.Hour {
		t.Fatalf("history RetireAt in %v, want ~7-day grace", got)
	}
	// Both the current and the graced alias stay live for the recipient seam.
	if len(s.localAliasAccounts) != 2 {
		t.Fatalf("localAliasAccounts = %v, want both aliases live", s.localAliasAccounts)
	}
	if s.aliasServiceIDs[onion0] == 0 || s.aliasServiceIDs[onion1] == 0 {
		t.Fatalf("both alias services must stay recorded: %v", s.aliasServiceIDs)
	}
	// The pending ack now targets the newest alias.
	if pr := s.pendingRotations["alice"]; pr.NewOnion != onion1 || pr.AliasIndex != 1 {
		t.Fatalf("pendingRotations[alice] = %+v, want {%s,1}", pr, onion1)
	}
}

// Without a host that supports concurrent services, rotation is unavailable and
// leaves all state untouched.
func TestPerformRotationUnsupportedHost(t *testing.T) {
	idn, _ := identity.New()
	s := rotationTestServer(nil) // nil onion → no extra-service support
	s.sessMu.Lock()
	_, err := s.performRotationLocked(idn)
	s.sessMu.Unlock()
	if err == nil {
		t.Fatal("expected rotation-unavailable error with no extra-service host")
	}
	if s.rotation != nil || len(s.pendingRotations) != 0 {
		t.Fatal("failed rotation must not mutate state")
	}
}

// A publish error surfaces and leaves state untouched (no half-applied rotation).
func TestPerformRotationPublishError(t *testing.T) {
	idn, _ := identity.New()
	host := &fakeExtraHost{startErr: errors.New("descriptor upload failed")}
	s := rotationTestServer(host)
	s.contacts["alice"] = chatstore.Contact{Account: "alice", Status: chatstore.StatusAccepted}
	s.sessMu.Lock()
	_, err := s.performRotationLocked(idn)
	s.sessMu.Unlock()
	if err == nil {
		t.Fatal("expected publish error")
	}
	if s.rotation != nil || len(s.pendingRotations) != 0 || len(s.localAliasAccounts) != 0 {
		t.Fatal("failed publish must not mutate rotation state")
	}
}

// After a restart (empty aliasServiceIDs), prepare+publish re-derives and restarts
// the whole live set — current + non-expired history — and skips expired history.
func TestRepublishLiveAliasSet(t *testing.T) {
	idn, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	host := &fakeExtraHost{}
	s := rotationTestServer(host)

	onion0, _ := idn.AliasAccount(0)
	onion1, _ := idn.AliasAccount(1)
	expired, _ := idn.AliasAccount(99)
	now := time.Now()
	s.rotation = &chatstore.RotationState{
		CurrentIndex:   1,
		CurrentAccount: onion1,
		History: []chatstore.AliasRecord{
			{Index: 0, Account: onion0, RetireAt: now.Add(3 * 24 * time.Hour)}, // live
			{Index: 99, Account: expired, RetireAt: now.Add(-time.Hour)},       // expired
		},
	}

	s.sessMu.Lock()
	prepared, err := s.prepareLiveAliasesLocked(idn)
	s.sessMu.Unlock()
	if err != nil {
		t.Fatalf("prepareLiveAliasesLocked: %v", err)
	}
	if len(prepared) != 2 {
		t.Fatalf("prepared %d aliases, want 2 (current + live history, not expired)", len(prepared))
	}

	s.publishPreparedAliases(prepared)

	if s.aliasServiceIDs[onion1] == 0 || s.aliasServiceIDs[onion0] == 0 {
		t.Fatalf("current + live history must be published: %v", s.aliasServiceIDs)
	}
	if _, ok := s.aliasServiceIDs[expired]; ok {
		t.Fatal("expired history alias must not be republished")
	}
	if len(s.localAliasAccounts) != 2 {
		t.Fatalf("localAliasAccounts = %v, want current + live history", s.localAliasAccounts)
	}
	if host.startCount() != 2 {
		t.Fatalf("host started %d services, want 2", host.startCount())
	}

	// Idempotent: a second publish of the same set starts nothing new.
	s.publishPreparedAliases2ndRound(t, idn)
}

// publishPreparedAliases2ndRound re-derives and re-publishes; because the ids are
// already recorded, no new StartExtraService should fire.
func (s *Server) publishPreparedAliases2ndRound(t *testing.T, idn *identity.Identity) {
	t.Helper()
	host := s.onion.(*fakeExtraHost)
	before := host.startCount()
	s.sessMu.Lock()
	prepared, err := s.prepareLiveAliasesLocked(idn)
	s.sessMu.Unlock()
	if err != nil {
		t.Fatalf("prepare (2nd): %v", err)
	}
	s.publishPreparedAliases(prepared)
	if host.startCount() != before {
		t.Fatalf("2nd publish started %d new services, want 0", host.startCount()-before)
	}
}

// prepareLiveAliasesLocked is a no-op before any rotation has happened.
func TestPrepareLiveAliasesNilRotation(t *testing.T) {
	idn, _ := identity.New()
	s := rotationTestServer(&fakeExtraHost{})
	s.sessMu.Lock()
	prepared, err := s.prepareLiveAliasesLocked(idn)
	s.sessMu.Unlock()
	if err != nil || prepared != nil {
		t.Fatalf("prepare with nil rotation = (%v, %v), want (nil, nil)", prepared, err)
	}
}
