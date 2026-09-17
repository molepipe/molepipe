package api

import (
	"testing"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
)

// reactionOn returns the reactions currently on the message with the given id.
func reactionOn(s *Server, id string) []chatstore.MessageReaction {
	for _, m := range s.messages {
		if m.ID == id {
			return m.Reactions
		}
	}
	return nil
}

// TestReactionAuthorization is the whole security of the reaction feature: a
// verified peer request (signature already checked in ReceiveReactionRequest)
// may only touch a message in the 1:1 conversation between the two accounts.
// Nothing else exercises hookOnReaction, so this is what stops a later edit from
// silently widening it — e.g. by inheriting delete's "inbound only" guard.
func TestReactionAuthorization(t *testing.T) {
	s, _ := unlocked(t)
	const alice = "6obmoy6chv7h53forcoiioehxcsd2mpfn7xtlbucc45agi7ltl4iqvqd"

	s.sessMu.Lock()
	s.messages = []chatMessage{
		{ID: "m1", Direction: "in", Peer: alice},          // alice → us
		{ID: "m2", Direction: "out", Peer: alice},         // us → alice
		{ID: "m3", Direction: "in", Peer: "someone-else"}, // a different conversation
		{ID: "m4", Direction: "in", GroupID: "g1"},        // a group message
	}
	s.sessMu.Unlock()

	// Alice may react to a message she sent us...
	if err := s.hookOnReaction(alice, "m1", "👍", false); err != nil {
		t.Fatalf("m1: %v", err)
	}
	if !chatstore.HasReaction(reactionOn(s, "m1"), "👍", alice) {
		t.Error("m1 should carry alice's reaction")
	}

	// ...and to a message WE sent her — the deliberate divergence from delete,
	// where reacting to something we said is normal.
	if err := s.hookOnReaction(alice, "m2", "❤️", false); err != nil {
		t.Fatalf("m2: %v", err)
	}
	if !chatstore.HasReaction(reactionOn(s, "m2"), "❤️", alice) {
		t.Error("m2 (our own outbound) should accept alice's reaction")
	}

	// She may NOT reach into a different conversation, even naming a real id.
	if err := s.hookOnReaction(alice, "m3", "👍", false); err != nil {
		t.Fatalf("m3 should be a silent no-op, got %v", err)
	}
	if len(reactionOn(s, "m3")) != 0 {
		t.Error("m3 belongs to another conversation and must be untouched")
	}

	// Group messages are deferred; a 1:1 peer request must never land on one.
	if err := s.hookOnReaction(alice, "m4", "👍", false); err != nil {
		t.Fatalf("m4 should be a silent no-op, got %v", err)
	}
	if len(reactionOn(s, "m4")) != 0 {
		t.Error("m4 is a group message and must be untouched")
	}

	// Removal clears her reaction on m1.
	if err := s.hookOnReaction(alice, "m1", "👍", true); err != nil {
		t.Fatalf("m1 remove: %v", err)
	}
	if chatstore.HasReaction(reactionOn(s, "m1"), "👍", alice) {
		t.Error("m1 reaction should be gone after remove")
	}
}
