package protocol

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

// During a rotation grace window a contact who hasn't applied our rotation still
// dials us at an alias-of-us and signs + AAD-binds their message to that alias, not
// our primary account. The receive path must recognise the alias as a valid
// recipient (via SetLocalAliasAccounts) and open the box with the matching AAD.
// The mock session uses real AEAD, so a decrypt succeeds ONLY if recipient-matching
// selected the alias for both the signature and the AAD.
func TestReceiveRatchetMatchesAliasRecipient(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	bobAlias, _ := identity.New() // stands in for an alias-of-bob bob is still publishing

	send := func(recipient string) RatchetEnvelope {
		s := &mockSession{established: true, ratchetKey: [32]byte{1, 2, 3}, chainKey: [32]byte{4, 5, 6}}
		box, header, err := s.Encrypt(EncodePayload("m1", "hi"), aad(alice.AccountNumber(), recipient))
		if err != nil {
			t.Fatal(err)
		}
		sig := ed25519.Sign(alice.Keys.Signing.Private,
			RatchetMsgSigningBlob(alice.AccountNumber(), recipient, header.HeaderBytes()))
		return RatchetEnvelope{Sender: alice.AccountNumber(), Ratchet: header, Sig: sig, Box: box}
	}
	newPeer := func() (*Peer, chan [2]string, *mockSessionManager) {
		delivered := make(chan [2]string, 1)
		p := NewPeer(bob, msgHooks(func(a string) bool { return a == alice.AccountNumber() }, delivered))
		sm := &mockSessionManager{sessions: map[string]*mockSession{
			alice.AccountNumber(): {established: true, ratchetKey: [32]byte{1, 2, 3}, chainKey: [32]byte{4, 5, 6}},
		}}
		return p, delivered, sm
	}
	wantDelivered := func(t *testing.T, delivered chan [2]string) {
		t.Helper()
		select {
		case <-delivered:
		case <-time.After(3 * time.Second):
			t.Fatal("message not delivered")
		}
	}

	// A message addressed to the alias is REJECTED while only the primary is live —
	// the signature does not verify against the primary account.
	p, _, sm := newPeer()
	if err := p.ReceiveRatchet(send(bobAlias.AccountNumber()), sm); err == nil {
		t.Fatal("message to an unknown alias-of-us should be rejected")
	}

	// Once the alias is declared live, the same message is accepted and opened with
	// the alias AAD.
	p, delivered, sm := newPeer()
	p.SetLocalAliasAccounts([]string{bobAlias.AccountNumber()})
	if err := p.ReceiveRatchet(send(bobAlias.AccountNumber()), sm); err != nil {
		t.Fatalf("message to a live alias should be accepted: %v", err)
	}
	wantDelivered(t, delivered)

	// The primary account still works with aliases declared (primary-first matching).
	p, delivered, sm = newPeer()
	p.SetLocalAliasAccounts([]string{bobAlias.AccountNumber()})
	if err := p.ReceiveRatchet(send(bob.AccountNumber()), sm); err != nil {
		t.Fatalf("message to the primary should still be accepted: %v", err)
	}
	wantDelivered(t, delivered)

	// Clearing the alias set restores primary-only matching.
	p, _, sm = newPeer()
	p.SetLocalAliasAccounts([]string{bobAlias.AccountNumber()})
	p.SetLocalAliasAccounts(nil)
	if err := p.ReceiveRatchet(send(bobAlias.AccountNumber()), sm); err == nil {
		t.Fatal("cleared alias should no longer be an accepted recipient")
	}
}
