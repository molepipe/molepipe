package api

import (
	"testing"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
)

// ackServer builds a minimal Server for exercising hookOnAddressRotationAck: our
// own rotation state (so an acked index maps back to the alias account the
// contact now knows us by), one accepted contact, and an empty pending set the
// test fills in. No sessID/onion, so the handler never dials.
func ackServer(contact string, rot *chatstore.RotationState) *Server {
	return &Server{
		contacts:         map[string]chatstore.Contact{contact: {Account: contact, Status: chatstore.StatusAccepted}},
		pendingRotations: map[string]chatstore.RotationPending{},
		rotation:         rot,
	}
}

// A matching-index ack clears the pending rotation and advances the account this
// contact knows us by. Index 0 is a real alias, so MyAccountKnown advances off
// its empty ("primary") sentinel even though the acked index is zero.
func TestRotationAckClearsAndAdvances(t *testing.T) {
	s := ackServer("alice", &chatstore.RotationState{CurrentIndex: 0, CurrentAccount: "aliasZero"})
	s.pendingRotations["alice"] = chatstore.RotationPending{NewOnion: "aliasZero", AliasIndex: 0}

	if err := s.hookOnAddressRotationAck("alice", 0); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if _, ok := s.pendingRotations["alice"]; ok {
		t.Error("pending rotation not cleared after ack")
	}
	c := s.contacts["alice"]
	if c.MyAccountKnown != "aliasZero" || c.MyAliasIndexKnown != 0 {
		t.Errorf("MyAccountKnown=%q idx=%d, want aliasZero/0", c.MyAccountKnown, c.MyAliasIndexKnown)
	}
}

// The clear condition is ack >= pending, NOT ==: an ack for a newer (superseding)
// rotation must also settle an older one still sitting in the pending set, or a
// raced supersede would leave an entry that never clears. MyAccountKnown advances
// to the alias for the acked index (current), not the stale pending index.
func TestRotationAckGeqClearsSuperseded(t *testing.T) {
	s := ackServer("alice", &chatstore.RotationState{
		CurrentIndex: 1, CurrentAccount: "aliasOne",
		History: []chatstore.AliasRecord{{Index: 0, Account: "aliasZero"}},
	})
	s.pendingRotations["alice"] = chatstore.RotationPending{NewOnion: "aliasZero", AliasIndex: 0}

	if err := s.hookOnAddressRotationAck("alice", 1); err != nil { // 1 >= 0
		t.Fatalf("ack: %v", err)
	}
	if _, ok := s.pendingRotations["alice"]; ok {
		t.Error(">= ack did not clear the superseded pending rotation")
	}
	c := s.contacts["alice"]
	if c.MyAccountKnown != "aliasOne" || c.MyAliasIndexKnown != 1 {
		t.Errorf("MyAccountKnown=%q idx=%d, want aliasOne/1", c.MyAccountKnown, c.MyAliasIndexKnown)
	}
}

// An ack for a LOWER index than the one we are currently delivering must not clear
// the pending rotation, and must not walk MyAccountKnown backwards (a late or
// duplicate ack for an alias the contact has already moved past).
func TestRotationAckLowerIndexNoClearNoRegress(t *testing.T) {
	s := ackServer("alice", &chatstore.RotationState{
		CurrentIndex: 1, CurrentAccount: "aliasOne",
		History: []chatstore.AliasRecord{{Index: 0, Account: "aliasZero"}},
	})
	s.pendingRotations["alice"] = chatstore.RotationPending{NewOnion: "aliasOne", AliasIndex: 1}
	c := s.contacts["alice"]
	c.MyAccountKnown, c.MyAliasIndexKnown = "aliasOne", 1 // already acked alias 1
	s.contacts["alice"] = c

	if err := s.hookOnAddressRotationAck("alice", 0); err != nil { // 0 >= 1 is false
		t.Fatalf("ack: %v", err)
	}
	if pr, ok := s.pendingRotations["alice"]; !ok || pr.AliasIndex != 1 {
		t.Errorf("pending = %+v (ok=%v), want it kept at index 1", pr, ok)
	}
	if c := s.contacts["alice"]; c.MyAccountKnown != "aliasOne" || c.MyAliasIndexKnown != 1 {
		t.Errorf("MyAccountKnown regressed to %q/%d, want aliasOne/1", c.MyAccountKnown, c.MyAliasIndexKnown)
	}
}

// An ack whose index we can no longer map (pruned from history past grace) still
// clears the pending on the >= rule, but leaves MyAccountKnown untouched rather
// than pointing it at an unknown/dead alias.
func TestRotationAckUnmappableIndexKeepsKnown(t *testing.T) {
	s := ackServer("alice", &chatstore.RotationState{CurrentIndex: 5, CurrentAccount: "aliasFive"})
	s.pendingRotations["alice"] = chatstore.RotationPending{NewOnion: "aliasThree", AliasIndex: 3}
	c := s.contacts["alice"]
	c.MyAccountKnown, c.MyAliasIndexKnown = "aliasTwo", 2
	s.contacts["alice"] = c

	if err := s.hookOnAddressRotationAck("alice", 3); err != nil { // 3 >= 3 clears
		t.Fatalf("ack: %v", err)
	}
	if _, ok := s.pendingRotations["alice"]; ok {
		t.Error("pending not cleared for a mappable-by-index ack")
	}
	// Index 3 is not in current/history, so MyAccountKnown must stay put.
	if c := s.contacts["alice"]; c.MyAccountKnown != "aliasTwo" || c.MyAliasIndexKnown != 2 {
		t.Errorf("MyAccountKnown = %q/%d, want it unchanged at aliasTwo/2", c.MyAccountKnown, c.MyAliasIndexKnown)
	}
}

// An ack from an account that is not an accepted contact is rejected.
func TestRotationAckRejectsNonContact(t *testing.T) {
	s := ackServer("alice", &chatstore.RotationState{CurrentIndex: 0, CurrentAccount: "aliasZero"})
	if err := s.hookOnAddressRotationAck("stranger", 0); err == nil {
		t.Error("ack from a non-accepted account should be rejected")
	}
}
