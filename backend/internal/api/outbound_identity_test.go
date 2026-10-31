package api

import (
	"bytes"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/crypto"
	"github.com/molepipe/molepipe/backend/internal/identity"
)

// A contact with an empty MyAccountKnown — the default for every pre-rotation
// contact, and the sentinel for "has not acked a rotation of ours" — is addressed
// as our primary account, signed with the primary key. An unknown recipient
// (not in contacts) takes the same default.
func TestOutboundIdentityDefaultsToPrimary(t *testing.T) {
	idn, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		contacts:         map[string]chatstore.Contact{"bob": {Account: "bob", Status: chatstore.StatusAccepted}},
		aliasSigningKeys: map[string]crypto.SigningKeyPair{},
	}
	for _, to := range []string{"bob", "never-heard-of"} {
		acct, signer, err := s.outboundIdentity(idn, to)
		if err != nil {
			t.Fatalf("%s: %v", to, err)
		}
		if acct != idn.AccountNumber() {
			t.Errorf("%s: account = %q, want primary %q", to, acct, idn.AccountNumber())
		}
		if !bytes.Equal(signer, idn.Keys.Signing.Private) {
			t.Errorf("%s: did not return the primary signing key", to)
		}
	}
}

// Once a contact has acked a rotation (non-empty MyAccountKnown), outbound stamps
// that alias account and signs with the RESIDENT alias key — never the primary
// key, because the peer derives our verifying key from the stamped account.
func TestOutboundIdentityUsesAliasWhenAcked(t *testing.T) {
	idn, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	kp, err := idn.AliasSigningKey(0)
	if err != nil {
		t.Fatal(err)
	}
	aliasAcct, err := idn.AliasAccount(0)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		contacts: map[string]chatstore.Contact{
			"bob": {Account: "bob", Status: chatstore.StatusAccepted, MyAccountKnown: aliasAcct, MyAliasIndexKnown: 0},
		},
		aliasSigningKeys: map[string]crypto.SigningKeyPair{aliasAcct: kp},
	}
	acct, signer, err := s.outboundIdentity(idn, "bob")
	if err != nil {
		t.Fatalf("outboundIdentity: %v", err)
	}
	if acct != aliasAcct {
		t.Errorf("account = %q, want alias %q", acct, aliasAcct)
	}
	if !bytes.Equal(signer, kp.Private) {
		t.Error("did not sign with the alias key")
	}
	if bytes.Equal(signer, idn.Keys.Signing.Private) {
		t.Error("leaked the primary signing key for an alias-known contact")
	}
}

// Regression for the unlock seam: startSession clears aliasSigningKeys to empty,
// and the ONLY thing that repopulates it on unlock is prepareLiveAliasesLocked
// (the synchronous call finishUnlock makes before handing back the token). If a
// refactor ever moves cache-population off that path, an unlock with rotation
// already active would leave every alias-known contact hitting the fail-loud
// branch — a healthy alias mistaken for a dead one. This exercises the real
// wiring (prepareLiveAliasesLocked, not a hand-built map) end to end: rotation
// state loaded from disk, empty cache, then outbound must resolve to the alias.
func TestOutboundIdentityCachePopulatedOnUnlock(t *testing.T) {
	idn, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	aliasAcct, err := idn.AliasAccount(0)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		// As on disk after a rotation: current alias is index 0.
		rotation: &chatstore.RotationState{CurrentIndex: 0, CurrentAccount: aliasAcct},
		contacts: map[string]chatstore.Contact{
			"bob": {Account: "bob", Status: chatstore.StatusAccepted, MyAccountKnown: aliasAcct, MyAliasIndexKnown: 0},
		},
		// As startSession leaves it: cleared, awaiting the unlock derive.
		aliasSigningKeys: map[string]crypto.SigningKeyPair{},
	}

	// The exact call finishUnlock makes under sessMu at unlock.
	s.sessMu.Lock()
	prepared, err := s.prepareLiveAliasesLocked(idn)
	s.sessMu.Unlock()
	if err != nil {
		t.Fatalf("prepareLiveAliasesLocked: %v", err)
	}
	defer zeroPreparedAliases(prepared)

	acct, signer, err := s.outboundIdentity(idn, "bob")
	if err != nil {
		t.Fatalf("outboundIdentity after unlock derive: %v — the cache was not populated", err)
	}
	if acct != aliasAcct {
		t.Errorf("account = %q, want alias %q", acct, aliasAcct)
	}
	kp, err := idn.AliasSigningKey(0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signer, kp.Private) {
		t.Error("did not sign with the alias key derived by the unlock path")
	}
	if bytes.Equal(signer, idn.Keys.Signing.Private) {
		t.Error("leaked the primary signing key for an alias-known contact after unlock")
	}
}

// The non-negotiable primary-leak guard: a contact whose MyAccountKnown names an
// alias whose key is no longer resident (aged past grace and swept) must FAIL the
// send — never silently fall back to the primary, which would disclose the
// permanent address the rotation exists to hide. This is the documented orphan
// trade-off, failing loudly.
func TestOutboundIdentityDeadAliasFailsLoud(t *testing.T) {
	idn, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		contacts: map[string]chatstore.Contact{
			"bob": {Account: "bob", Status: chatstore.StatusAccepted, MyAccountKnown: "deadalias", MyAliasIndexKnown: 2},
		},
		aliasSigningKeys: map[string]crypto.SigningKeyPair{}, // the alias key is gone
	}
	acct, signer, err := s.outboundIdentity(idn, "bob")
	if err == nil {
		t.Fatal("a non-empty MyAccountKnown with no resident key must fail, not fall back")
	}
	if acct == idn.AccountNumber() || signer != nil {
		t.Error("must not disclose the primary account/key when the alias is dead")
	}
}
