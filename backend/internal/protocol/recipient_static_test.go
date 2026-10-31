package protocol

import (
	"crypto/ed25519"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/crypto"
	"github.com/molepipe/molepipe/backend/internal/identity"
)

// The static (non-ratchet) bootstrap verbs must tolerate a request an un-updated
// contact addressed to an alias-of-us during a rotation grace window, exactly as
// the ratchet path does — the sender signs (and, for v1 messages, AAD-binds) to
// whichever account they dialed. Each verb is rejected when the alias is not
// declared live and accepted once SetLocalAliasAccounts declares it, proving the
// recipient-candidate loop threads the matched account through verification (and,
// for the v1 message, through key/AAD derivation via real AEAD).
func TestStaticVerbsMatchAliasRecipient(t *testing.T) {
	bob, _ := identity.New()      // us
	alice, _ := identity.New()    // an accepted contact who dials our alias
	bobAlias, _ := identity.New() // stands in for an alias-of-us still published

	alias := bobAlias.AccountNumber()

	t.Run("friend-request", func(t *testing.T) {
		called := 0
		p := NewPeer(bob, Hooks{OnFriendRequest: func(string, string, string, string, string) error { called++; return nil }})
		req := func() FriendRequest {
			ch := p.Challenge()
			sig := ed25519.Sign(alice.Keys.Signing.Private, signBlob(sigContextFor(protoVerCurrent),
				[]byte("friend-request"), ch.Nonce, []byte(alias), []byte("Alice"), []byte("r1")))
			return FriendRequest{From: alice.AccountNumber(), FromName: "Alice", ReqID: "r1", Nonce: ch.Nonce, Sig: sig}
		}
		if err := p.ReceiveFriendRequest(req()); err == nil {
			t.Fatal("request to an undeclared alias must be rejected")
		}
		p.SetLocalAliasAccounts([]string{alias})
		if err := p.ReceiveFriendRequest(req()); err != nil {
			t.Fatalf("request to a live alias must be accepted: %v", err)
		}
		if called != 1 {
			t.Fatalf("OnFriendRequest called %d times, want 1", called)
		}
	})

	t.Run("friend-accept", func(t *testing.T) {
		called := 0
		p := NewPeer(bob, Hooks{OnFriendAccept: func(string, string, string) error { called++; return nil }})
		acc := func() FriendAccept {
			ch := p.Challenge()
			sig := ed25519.Sign(alice.Keys.Signing.Private, signBlob(sigContextFor(protoVerCurrent),
				[]byte("friend-accept"), ch.Nonce, []byte(alias), []byte("Alice"), []byte("r1")))
			return FriendAccept{From: alice.AccountNumber(), FromName: "Alice", ReqID: "r1", Nonce: ch.Nonce, Sig: sig}
		}
		if err := p.ReceiveFriendAccept(acc()); err == nil {
			t.Fatal("accept to an undeclared alias must be rejected")
		}
		p.SetLocalAliasAccounts([]string{alias})
		if err := p.ReceiveFriendAccept(acc()); err != nil {
			t.Fatalf("accept to a live alias must be accepted: %v", err)
		}
		if called != 1 {
			t.Fatalf("OnFriendAccept called %d times, want 1", called)
		}
	})

	t.Run("contact-profile", func(t *testing.T) {
		mailbox := "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"
		p := NewPeer(bob, Hooks{ContactMailbox: func(s string) string {
			if s == alice.AccountNumber() {
				return mailbox
			}
			return ""
		}})
		req := func() ContactProfileRequest {
			ch := p.Challenge()
			sig := ed25519.Sign(alice.Keys.Signing.Private, signBlob(sigContextFor(protoVerCurrent),
				[]byte("contact-profile"), ch.Nonce, []byte(alias)))
			return ContactProfileRequest{From: alice.AccountNumber(), Nonce: ch.Nonce, Sig: sig}
		}
		if _, err := p.ServeContactProfile(req()); err == nil {
			t.Fatal("contact-profile to an undeclared alias must be rejected")
		}
		p.SetLocalAliasAccounts([]string{alias})
		cp, err := p.ServeContactProfile(req())
		if err != nil {
			t.Fatalf("contact-profile to a live alias must be accepted: %v", err)
		}
		if cp.MailboxURL != mailbox {
			t.Fatalf("mailbox = %q, want %q", cp.MailboxURL, mailbox)
		}
	})

	t.Run("prekey-bundle", func(t *testing.T) {
		built := 0
		p := NewPeer(bob, Hooks{})
		isAccepted := func(s string) bool { return s == alice.AccountNumber() }
		build := func() (crypto.PrekeyBundle, error) { built++; return crypto.PrekeyBundle{}, nil }
		req := func() PrekeyBundleRequest {
			ch := p.Challenge()
			sig := ed25519.Sign(alice.Keys.Signing.Private, PrekeyBundleSigningBlob(ch.Nonce, alias))
			return PrekeyBundleRequest{From: alice.AccountNumber(), Nonce: ch.Nonce, Sig: sig}
		}
		if _, err := p.ServePrekeyBundle(req(), isAccepted, build); err == nil {
			t.Fatal("prekey request to an undeclared alias must be rejected")
		}
		p.SetLocalAliasAccounts([]string{alias})
		if _, err := p.ServePrekeyBundle(req(), isAccepted, build); err != nil {
			t.Fatalf("prekey request to a live alias must be accepted: %v", err)
		}
		if built != 1 {
			t.Fatalf("build called %d times, want 1 (only after the gate)", built)
		}
	})

	t.Run("respond-challenge-as-alias", func(t *testing.T) {
		p := NewPeer(bob, Hooks{})
		aliasEd, err := identity.AccountNumberFromString(alias)
		if err != nil {
			t.Fatal(err)
		}
		ch := p.ChallengeAs(alias, bobAlias.Keys.Signing.Private)
		// The client derives our verifying key from the alias it dialed, so the
		// challenge must verify under the alias key over the alias account...
		if !ed25519.Verify(aliasEd, signBlob(sigContextFor(protoVerCurrent),
			[]byte("challenge"), []byte(alias), ch.DHPub), ch.Sig) {
			t.Fatal("challenge must verify as the dialed alias account")
		}
		// ...and NOT under our primary key (proving it is really alias-signed, so
		// the primary account never appears in a response to an alias dialer).
		primaryEd, _ := identity.AccountNumberFromString(bob.AccountNumber())
		if ed25519.Verify(primaryEd, signBlob(sigContextFor(protoVerCurrent),
			[]byte("challenge"), []byte(bob.AccountNumber()), ch.DHPub), ch.Sig) {
			t.Fatal("challenge signed as the alias must NOT verify as the primary account")
		}
		// The DHPub is the stable identity anchor: same key regardless of alias.
		wantDH := bob.Keys.DH.Public
		if string(ch.DHPub) != string(wantDH[:]) {
			t.Fatal("respond-as-alias must still carry the stable m/0'/1' DHPub")
		}
	})

	t.Run("respond-profile-as-alias", func(t *testing.T) {
		p := NewPeer(bob, Hooks{DisplayName: func() string { return "Bob" }})
		aliasEd, err := identity.AccountNumberFromString(alias)
		if err != nil {
			t.Fatal(err)
		}
		card := p.ProfileCardAs(alias, bobAlias.Keys.Signing.Private)
		if card.Account != alias {
			t.Fatalf("card account = %s, want the dialed alias %s", card.Account, alias)
		}
		if !verifyProfileSig(aliasEd, alias, card) {
			t.Fatal("profile card must verify as the dialed alias account")
		}
		primaryEd, _ := identity.AccountNumberFromString(bob.AccountNumber())
		if verifyProfileSig(primaryEd, bob.AccountNumber(), card) {
			t.Fatal("alias-signed card must NOT verify as the primary account")
		}
		wantDH := bob.Keys.DH.Public
		if string(card.DHPub) != string(wantDH[:]) {
			t.Fatal("respond-as-alias card must still carry the stable m/0'/1' DHPub")
		}
	})

	t.Run("v1-message", func(t *testing.T) {
		delivered := make(chan [2]string, 1)
		p := NewPeer(bob, msgHooks(func(a string) bool { return a == alice.AccountNumber() }, delivered))
		// Build a v1 envelope whose signature AND AAD/key derivation bind the alias.
		env := func() Envelope {
			ch := p.Challenge()
			var theirDH [32]byte
			copy(theirDH[:], ch.DHPub)
			shared, _ := crypto.SharedSecret(alice.Keys.DH.Private, theirDH)
			key := crypto.DeriveDirectionalKey(shared, msgKeyInfo(alice.AccountNumber(), alias))
			box, _ := crypto.SealMessage(key, EncodePayload("m1", "hi"), aad(alice.AccountNumber(), alias))
			dh := alice.Keys.DH.Public
			sig := ed25519.Sign(alice.Keys.Signing.Private, signBlob(sigContextFor(protoVerCurrent),
				[]byte("message"), ch.Nonce, []byte(alias), dh[:]))
			return Envelope{Sender: alice.AccountNumber(), SenderDHPub: dh[:], Nonce: ch.Nonce, Sig: sig, Box: box}
		}
		if err := p.Receive(env()); err == nil {
			t.Fatal("v1 message to an undeclared alias must be rejected")
		}
		p.SetLocalAliasAccounts([]string{alias})
		if err := p.Receive(env()); err != nil {
			t.Fatalf("v1 message to a live alias must be accepted and decrypt: %v", err)
		}
		select {
		case <-delivered:
		default:
			t.Fatal("v1 message to a live alias was not delivered")
		}
	})
}
