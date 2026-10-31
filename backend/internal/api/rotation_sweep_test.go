package api

import (
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/crypto"
)

// sweepTestServer builds a server whose rotation state has a current alias plus
// the given history, with the runtime alias maps (service ids + signing keys)
// populated to mirror a live fleet — so a sweep has real state to tear down.
func sweepTestServer(host *fakeExtraHost, current string, history []chatstore.AliasRecord) *Server {
	s := rotationTestServer(host)
	s.aliasSigningKeys = map[string]crypto.SigningKeyPair{}
	s.rotation = &chatstore.RotationState{CurrentIndex: 100, CurrentAccount: current, History: history}
	// Current alias is always resident.
	s.aliasServiceIDs[current] = 900
	s.aliasSigningKeys[current] = crypto.SigningKeyPair{}
	for _, h := range history {
		s.aliasServiceIDs[h.Account] = uint64(h.Index)
		s.aliasSigningKeys[h.Account] = crypto.SigningKeyPair{}
	}
	s.refreshLiveAliasesLocked()
	return s
}

func hasID(ids []uint64, want uint64) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// A history alias past its RetireAt is torn down (StopExtraService by id), evicted
// from both runtime maps, and dropped from History; a still-in-grace alias and the
// current alias are left completely untouched.
func TestSweepRetiresExpiredAliasesAndKeepsLive(t *testing.T) {
	now := time.Now()
	host := &fakeExtraHost{}
	s := sweepTestServer(host, "current", []chatstore.AliasRecord{
		{Index: 10, Account: "expired", RetireAt: now.Add(-time.Hour)},
		{Index: 11, Account: "live", RetireAt: now.Add(3 * 24 * time.Hour)},
	})

	s.sweepExpiredAliases()

	if !hasID(host.stopped, 10) {
		t.Fatalf("expired alias service (id 10) not stopped; stopped=%v", host.stopped)
	}
	if hasID(host.stopped, 11) || hasID(host.stopped, 900) {
		t.Fatalf("live/current service must not be stopped; stopped=%v", host.stopped)
	}
	if _, ok := s.aliasServiceIDs["expired"]; ok {
		t.Fatal("expired alias must be dropped from aliasServiceIDs")
	}
	if _, ok := s.aliasSigningKeys["expired"]; ok {
		t.Fatal("expired alias signing key must be evicted")
	}
	if _, ok := s.aliasServiceIDs["live"]; !ok {
		t.Fatal("in-grace alias must stay in aliasServiceIDs")
	}
	if _, ok := s.aliasSigningKeys["live"]; !ok {
		t.Fatal("in-grace alias signing key must stay resident")
	}
	if _, ok := s.aliasServiceIDs["current"]; !ok {
		t.Fatal("current alias must stay in aliasServiceIDs")
	}
	if len(s.rotation.History) != 1 || s.rotation.History[0].Account != "live" {
		t.Fatalf("history = %+v, want just the in-grace alias", s.rotation.History)
	}
}

// The sweep gives up exactly the pending rotations it orphaned: a contact who
// knows us by the just-retired alias (undeliverable once its key is evicted) is
// dropped; a contact on the current alias, a contact on the primary (empty
// MyAccountKnown, always deliverable), and a pending rotation whose contact is
// gone are handled correctly.
func TestSweepGivesUpOnlyOrphanedPendingRotations(t *testing.T) {
	now := time.Now()
	host := &fakeExtraHost{}
	s := sweepTestServer(host, "current", []chatstore.AliasRecord{
		{Index: 10, Account: "retired", RetireAt: now.Add(-time.Hour)},
	})
	s.contacts["alice"] = chatstore.Contact{Account: "alice", MyAccountKnown: "retired"}
	s.contacts["bob"] = chatstore.Contact{Account: "bob", MyAccountKnown: "current"}
	s.contacts["carol"] = chatstore.Contact{Account: "carol", MyAccountKnown: ""}
	for _, c := range []string{"alice", "bob", "carol", "ghost"} {
		s.pendingRotations[c] = chatstore.RotationPending{NewOnion: "current"}
	}

	s.sweepExpiredAliases()

	if _, ok := s.pendingRotations["alice"]; ok {
		t.Fatal("contact who knew us by the retired alias must be given up (undeliverable)")
	}
	if _, ok := s.pendingRotations["bob"]; !ok {
		t.Fatal("contact on the current alias must be kept")
	}
	if _, ok := s.pendingRotations["carol"]; !ok {
		t.Fatal("contact on the primary (empty MyAccountKnown) is always deliverable — keep")
	}
	if _, ok := s.pendingRotations["ghost"]; ok {
		t.Fatal("pending rotation for a vanished contact must be given up")
	}
}

// The give-up must gate on the SET WE ACTUALLY RETIRED, never on aliasSigningKeys
// membership: an in-grace alias whose republish failed is absent from that map yet
// still perfectly reachable. A contact on such an alias must survive a sweep that
// only retired some OTHER (expired) alias. Regression guard for the conflation of
// "swept" with "never cached".
func TestSweepDoesNotGiveUpUncachedLiveAlias(t *testing.T) {
	now := time.Now()
	host := &fakeExtraHost{}
	s := sweepTestServer(host, "current", []chatstore.AliasRecord{
		{Index: 10, Account: "expired", RetireAt: now.Add(-time.Hour)},
		{Index: 11, Account: "live-uncached", RetireAt: now.Add(3 * 24 * time.Hour)},
	})
	// Simulate a failed republish of the in-grace alias: live in History but its
	// signing key never made it into the resident map.
	delete(s.aliasSigningKeys, "live-uncached")
	s.contacts["dave"] = chatstore.Contact{Account: "dave", MyAccountKnown: "live-uncached"}
	s.pendingRotations["dave"] = chatstore.RotationPending{NewOnion: "current"}

	s.sweepExpiredAliases()

	if _, ok := s.pendingRotations["dave"]; !ok {
		t.Fatal("contact on an in-grace (merely uncached) alias must NOT be given up")
	}
}

// A sweep with nothing past its deadline changes nothing: no teardown, no history
// edit, no pending-rotation give-up.
func TestSweepNoExpiryIsNoOp(t *testing.T) {
	now := time.Now()
	host := &fakeExtraHost{}
	s := sweepTestServer(host, "current", []chatstore.AliasRecord{
		{Index: 11, Account: "live", RetireAt: now.Add(3 * 24 * time.Hour)},
	})
	s.contacts["alice"] = chatstore.Contact{Account: "alice", MyAccountKnown: "live"}
	s.pendingRotations["alice"] = chatstore.RotationPending{NewOnion: "current"}

	s.sweepExpiredAliases()

	if len(host.stopped) != 0 {
		t.Fatalf("nothing expired, nothing should stop; stopped=%v", host.stopped)
	}
	if len(s.rotation.History) != 1 {
		t.Fatalf("history should be untouched, got %+v", s.rotation.History)
	}
	if _, ok := s.pendingRotations["alice"]; !ok {
		t.Fatal("no expiry must not give up a pending rotation")
	}
}

// A nil rotation state (before any rotation ever happened) sweeps to a clean no-op.
func TestSweepNilRotationNoOp(t *testing.T) {
	host := &fakeExtraHost{}
	s := rotationTestServer(host)
	s.sweepExpiredAliases()
	if len(host.stopped) != 0 {
		t.Fatalf("nil rotation must not stop anything; stopped=%v", host.stopped)
	}
}
