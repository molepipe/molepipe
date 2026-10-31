package api

import (
	"testing"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/crypto"
)

// Before any rotation the outbound bootstrap identity is the primary, signed with
// the primary key — identical to the pre-rotation world, so a never-rotated device
// is unaffected. isAlias is false so the caller records no MyAccountKnown.
func TestAdvertisedOutboundIdentityPreRotationIsPrimary(t *testing.T) {
	s := inviteTestServer()
	id := s.sessID
	s.sessMu.Lock()
	acct, priv, idx, isAlias, err := s.advertisedOutboundIdentityLocked(id)
	s.sessMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if acct != id.AccountNumber() {
		t.Fatalf("pre-rotation account = %q, want primary", acct)
	}
	if isAlias || idx != 0 {
		t.Fatalf("pre-rotation must not be an alias (isAlias=%v idx=%d)", isAlias, idx)
	}
	if !priv.Equal(id.Keys.Signing.Private) {
		t.Fatal("pre-rotation must sign with the primary key")
	}
}

// After a rotation the outbound friend request presents the current alias, signed
// with the ALIAS key (never the primary) and carrying the alias's index for the
// MyAccountKnown record. This is the seam that stops a brand-new contact learning
// our real onion.
func TestAdvertisedOutboundIdentityPostRotationIsAlias(t *testing.T) {
	s := inviteTestServer()
	id := s.sessID
	alias, err := id.AliasAccount(0)
	if err != nil {
		t.Fatal(err)
	}
	s.sessMu.Lock()
	s.rotation = &chatstore.RotationState{CurrentIndex: 0, CurrentAccount: alias}
	s.aliasSigningKeys = map[string]crypto.SigningKeyPair{}
	if err := s.cacheAliasSigningKeyLocked(id, 0, alias); err != nil {
		t.Fatal(err)
	}
	acct, priv, idx, isAlias, err := s.advertisedOutboundIdentityLocked(id)
	s.sessMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if acct != alias || !isAlias || idx != 0 {
		t.Fatalf("post-rotation = (%q, isAlias=%v, idx=%d), want (%q, true, 0)", acct, isAlias, idx, alias)
	}
	aliasKP, err := id.AliasSigningKey(0)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Equal(aliasKP.Private) {
		t.Fatal("post-rotation must sign with the alias key")
	}
	if priv.Equal(id.Keys.Signing.Private) {
		t.Fatal("post-rotation must NOT sign with the primary key")
	}
}

// A rotation whose advertised alias key is not resident fails loud rather than
// falling back to the primary — refusing to stamp an unusable/leaking identity onto
// a new contact is safer than silently disclosing the real onion.
func TestAdvertisedOutboundIdentityMissingAliasKeyFailsLoud(t *testing.T) {
	s := inviteTestServer()
	id := s.sessID
	alias, err := id.AliasAccount(0)
	if err != nil {
		t.Fatal(err)
	}
	s.sessMu.Lock()
	s.rotation = &chatstore.RotationState{CurrentIndex: 0, CurrentAccount: alias}
	s.aliasSigningKeys = map[string]crypto.SigningKeyPair{} // alias key NOT resident
	_, _, _, _, err = s.advertisedOutboundIdentityLocked(id)
	s.sessMu.Unlock()
	if err == nil {
		t.Fatal("a non-resident advertised alias must fail, not fall back to the primary")
	}
}

// When a requester dials one of our live aliases (a redeemed rotated code), the
// inbound friend-request hook records that alias as MyAccountKnown so our accept
// answers as the same alias. A primary dial keeps MyAccountKnown empty (the primary
// sentinel), and a dial we cannot resolve to a live alias is left unset rather than
// stamped with an identity outboundIdentity would then fail loud on forever.
func TestFriendRequestRecordsDialedAlias(t *testing.T) {
	s := inviteTestServer()
	s.autoRefresh = false // reusable token so several adds land
	s.inviteToken = "LIVE"
	id := s.sessID
	alias, err := id.AliasAccount(0)
	if err != nil {
		t.Fatal(err)
	}
	s.sessMu.Lock()
	s.rotation = &chatstore.RotationState{CurrentIndex: 0, CurrentAccount: alias}
	s.sessMu.Unlock()

	// Dialed our live alias → recorded.
	if err := s.hookOnFriendRequest("alice", "Alice", "r1", "LIVE", alias); err != nil {
		t.Fatal(err)
	}
	if c := s.contacts["alice"]; c.MyAccountKnown != alias || c.MyAliasIndexKnown != 0 {
		t.Fatalf("MyAccountKnown=%q idx=%d, want %q/0", c.MyAccountKnown, c.MyAliasIndexKnown, alias)
	}

	// Dialed our primary → left empty.
	if err := s.hookOnFriendRequest("bob", "Bob", "r2", "LIVE", id.AccountNumber()); err != nil {
		t.Fatal(err)
	}
	if c := s.contacts["bob"]; c.MyAccountKnown != "" {
		t.Fatalf("primary dial recorded MyAccountKnown=%q, want empty", c.MyAccountKnown)
	}

	// Dialed an account we do not hold as a live alias → left empty (divergence-safe).
	unknown := "aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllllmmmmnnnn"
	if err := s.hookOnFriendRequest("carol", "Carol", "r3", "LIVE", unknown); err != nil {
		t.Fatal(err)
	}
	if c := s.contacts["carol"]; c.MyAccountKnown != "" {
		t.Fatalf("unresolvable dial recorded MyAccountKnown=%q, want empty", c.MyAccountKnown)
	}
}
