package api

import (
	"testing"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// recipientCandidates feeds the init-handler's signature retry: our primary
// account first, then any live alias we're currently publishing. Default is
// primary-only (behaviour unchanged until we rotate); declaring aliases appends
// them and clearing restores primary-only.
func TestRecipientCandidatesTracksLiveAliases(t *testing.T) {
	idn, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{}

	got := s.recipientCandidates(idn)
	if len(got) != 1 || got[0] != idn.AccountNumber() {
		t.Fatalf("default candidates = %v, want [primary]", got)
	}

	// setLiveAliasAccountsLocked must tolerate a nil peer (server locked) and record
	// the set; a real peer receives the push without panicking.
	s.sessMu.Lock()
	s.setLiveAliasAccountsLocked([]string{"aliasA", "aliasB"})
	s.sessMu.Unlock()

	got = s.recipientCandidates(idn)
	if len(got) != 3 || got[0] != idn.AccountNumber() || got[1] != "aliasA" || got[2] != "aliasB" {
		t.Fatalf("candidates with aliases = %v, want [primary, aliasA, aliasB]", got)
	}

	// A real peer must be pushed the set too (no panic; the protocol package tests
	// that the peer then matches those recipients).
	s.peer = protocol.NewPeer(idn, protocol.Hooks{})
	s.sessMu.Lock()
	s.setLiveAliasAccountsLocked([]string{"aliasA"})
	s.sessMu.Unlock()
	if got = s.recipientCandidates(idn); len(got) != 2 || got[1] != "aliasA" {
		t.Fatalf("candidates after peer push = %v, want [primary, aliasA]", got)
	}

	s.sessMu.Lock()
	s.setLiveAliasAccountsLocked(nil)
	s.sessMu.Unlock()
	if got = s.recipientCandidates(idn); len(got) != 1 {
		t.Fatalf("candidates after clear = %v, want [primary]", got)
	}
}
