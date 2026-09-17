package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

func sealFor(t *testing.T, from, to *identity.Identity, text string) protocol.MailEnvelope {
	t.Helper()
	env, err := protocol.SealMailEnvelope(from, to.AccountNumber(), to.Keys.DH.Public, "mid-1", text, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// TestRelayDropOffAndDeliver walks the full push relay: Alice drops a sealed
// message for Carol at Bob (her approved relay), and Bob's push to Carol is
// accepted and stored.
func TestRelayDropOffAndDeliver(t *testing.T) {
	bob, _ := syncPrimary(t)
	carol, carolID := syncPrimary(t)
	alice, _ := identity.New()

	toBob := syncFakeDialer{addr: bob.pubLn.Addr().String()}
	toCarol := syncFakeDialer{addr: carol.pubLn.Addr().String()}

	// Bob approves Alice as a relay sender; Carol has Alice as an accepted contact.
	bob.sessMu.Lock()
	bob.contacts[alice.AccountNumber()] = chatstore.Contact{Account: alice.AccountNumber(), Status: chatstore.StatusAccepted, RelayGrant: true}
	bob.sessMu.Unlock()
	carol.sessMu.Lock()
	carol.contacts[alice.AccountNumber()] = chatstore.Contact{Account: alice.AccountNumber(), Status: chatstore.StatusAccepted}
	carol.sessMu.Unlock()

	env := sealFor(t, alice, carolID, "relayed hello")

	// Alice drops off at Bob; Bob holds it for Carol.
	if err := protocol.RelayDropOff(context.Background(), toBob, env, "ignored.onion"); err != nil {
		t.Fatalf("relay drop-off: %v", err)
	}
	items, _ := bob.relay.Pickup(carolID.AccountNumber())
	if len(items) != 1 {
		t.Fatalf("relay held %d blobs, want 1", len(items))
	}

	// Bob pushes to Carol; Carol accepts and stores it.
	if err := protocol.RelayDeliver(context.Background(), toCarol, env, "ignored.onion"); err != nil {
		t.Fatalf("relay deliver: %v", err)
	}
	carol.sessMu.Lock()
	got := ""
	for _, m := range carol.messages {
		if m.Peer == alice.AccountNumber() {
			got = m.Text
		}
	}
	carol.sessMu.Unlock()
	if got != "relayed hello" {
		t.Fatalf("carol received %q, want %q", got, "relayed hello")
	}
}

func TestRelayDropOffRejectsUnapprovedSender(t *testing.T) {
	bob, _ := syncPrimary(t)
	_, carolID := syncPrimary(t)
	alice, _ := identity.New()
	toBob := syncFakeDialer{addr: bob.pubLn.Addr().String()}

	// Alice is a contact but NOT relay-granted.
	bob.sessMu.Lock()
	bob.contacts[alice.AccountNumber()] = chatstore.Contact{Account: alice.AccountNumber(), Status: chatstore.StatusAccepted}
	bob.sessMu.Unlock()

	env := sealFor(t, alice, carolID, "nope")
	if err := protocol.RelayDropOff(context.Background(), toBob, env, "x.onion"); err == nil {
		t.Fatal("relay accepted a drop-off from an unapproved sender")
	}
	if items, _ := bob.relay.Pickup(carolID.AccountNumber()); len(items) != 0 {
		t.Fatal("unapproved drop-off was stored")
	}
}

// TestRelayHolderSelection covers relayHolderLocked, which backs the "pick a
// relay" choice in the offline-send popup: an empty selector falls back to the
// first available holder, a named holder is honoured, and — the security point —
// an account that is not an approved relay-holder is refused, so a caller can
// never steer a drop-off to an arbitrary contact.
func TestRelayHolderSelection(t *testing.T) {
	srv, _ := syncPrimary(t)
	holder, _ := identity.New()
	plain, _ := identity.New()

	srv.sessMu.Lock()
	defer srv.sessMu.Unlock()
	srv.contacts[holder.AccountNumber()] = chatstore.Contact{Account: holder.AccountNumber(), Status: chatstore.StatusAccepted, RelayHolder: true}
	srv.contacts[plain.AccountNumber()] = chatstore.Contact{Account: plain.AccountNumber(), Status: chatstore.StatusAccepted}

	if c, ok := srv.relayHolderLocked(""); !ok || c.Account != holder.AccountNumber() {
		t.Fatalf("empty selector: got %q ok=%v, want the relay-holder", c.Account, ok)
	}
	if c, ok := srv.relayHolderLocked(holder.AccountNumber()); !ok || c.Account != holder.AccountNumber() {
		t.Fatalf("named holder: got %q ok=%v", c.Account, ok)
	}
	if c, ok := srv.relayHolderLocked(plain.AccountNumber()); ok {
		t.Fatalf("a non-holder contact was accepted as a relay: %q", c.Account)
	}
	if _, ok := srv.relayHolderLocked("not-a-real-account"); ok {
		t.Fatal("an unknown account was accepted as a relay")
	}
}

// TestContactsReportRelayAvailable pins the JSON contract the offline-send popup
// triggers on: /api/contacts must report relay_available=true only when BOTH an
// approved relay-holder exists AND we hold the contact's encryption key. The
// server-side relayHolderLocked test can't see this boundary; the frontend does.
func TestContactsReportRelayAvailable(t *testing.T) {
	s, tok := unlocked(t)
	auth := map[string]string{"Authorization": "Bearer " + tok, "Origin": s.origin()}

	holder, _ := identity.New()
	withKey, _ := identity.New()
	noKey, _ := identity.New()

	s.sessMu.Lock()
	s.contacts[holder.AccountNumber()] = chatstore.Contact{Account: holder.AccountNumber(), Status: chatstore.StatusAccepted, RelayHolder: true}
	s.contacts[withKey.AccountNumber()] = chatstore.Contact{Account: withKey.AccountNumber(), Status: chatstore.StatusAccepted, DHPub: make([]byte, 32)}
	s.contacts[noKey.AccountNumber()] = chatstore.Contact{Account: noKey.AccountNumber(), Status: chatstore.StatusAccepted}
	s.sessMu.Unlock()

	relayAvail := func() map[string]bool {
		body := decode(t, s.do(t, "GET", "/api/contacts", "", auth).Body)
		out := map[string]bool{}
		for _, raw := range body["contacts"].([]any) {
			c := raw.(map[string]any)
			acct, _ := c["account"].(string)
			av, _ := c["relay_available"].(bool)
			out[acct] = av
		}
		return out
	}

	got := relayAvail()
	if !got[withKey.AccountNumber()] {
		t.Error("a keyed contact with an approved relay-holder should be relay_available")
	}
	if got[noKey.AccountNumber()] {
		t.Error("a contact with no encryption key must not be relay_available")
	}

	// With no relay-holder left, even the keyed contact can't be relayed to.
	s.sessMu.Lock()
	delete(s.contacts, holder.AccountNumber())
	s.sessMu.Unlock()
	if relayAvail()[withKey.AccountNumber()] {
		t.Error("with no relay-holder, relay_available must be false")
	}
}

// TestRelayDeliverIsNotAnOracle: a message from a non-contact and a message with
// a bad signature must be rejected with the SAME status, so /relay/deliver can't
// be used to probe whether an account is one of Carol's contacts.
func TestRelayDeliverIsNotAnOracle(t *testing.T) {
	carol, carolID := syncPrimary(t)
	stranger, _ := identity.New()
	toCarol := syncFakeDialer{addr: carol.pubLn.Addr().String()}

	// Stranger is validly signed but not a contact.
	notContact := sealFor(t, stranger, carolID, "hi")
	errNotContact := protocol.RelayDeliver(context.Background(), toCarol, notContact, "x")

	// A tampered (bad-signature) envelope from the same stranger.
	bad := sealFor(t, stranger, carolID, "hi")
	bad.Box[0] ^= 0xff
	errBadSig := protocol.RelayDeliver(context.Background(), toCarol, bad, "x")

	if errNotContact == nil || errBadSig == nil {
		t.Fatal("relay deliver accepted a non-contact or bad-signature message")
	}
	// Both errors carry the HTTP status; they must be identical (both 403).
	if !strings.Contains(errNotContact.Error(), "403") || !strings.Contains(errBadSig.Error(), "403") {
		t.Fatalf("relay-deliver rejections not uniform: notContact=%v badSig=%v", errNotContact, errBadSig)
	}
}

// TestRelayRequestHandshake: Alice asks Bob to relay for her; the request marks
// Bob's contact pending, and Bob's accept marks Alice's contact as a relay-holder.
func TestRelayRequestHandshake(t *testing.T) {
	bob, bobID := syncPrimary(t)
	alice, aliceID := syncPrimary(t)
	toBob := syncFakeDialer{addr: bob.pubLn.Addr().String()}
	toAlice := syncFakeDialer{addr: alice.pubLn.Addr().String()}

	// They're mutual accepted contacts (relay requests only run between contacts).
	bob.sessMu.Lock()
	bob.contacts[aliceID.AccountNumber()] = chatstore.Contact{Account: aliceID.AccountNumber(), Status: chatstore.StatusAccepted}
	bob.sessMu.Unlock()
	alice.sessMu.Lock()
	alice.contacts[bobID.AccountNumber()] = chatstore.Contact{Account: bobID.AccountNumber(), Status: chatstore.StatusAccepted, RelayReqID: "rq1"}
	alice.sessMu.Unlock()

	// Alice → Bob request.
	if err := protocol.SendRelayRequest(context.Background(), toBob, aliceID, "rq1", bobID.AccountNumber()); err != nil {
		t.Fatalf("send relay request: %v", err)
	}
	bob.sessMu.Lock()
	bc := bob.contacts[aliceID.AccountNumber()]
	bob.sessMu.Unlock()
	if !bc.RelayPending || bc.RelayReqID != "rq1" {
		t.Fatalf("bob did not record pending relay request: %+v", bc)
	}

	// Bob → Alice accept.
	if err := protocol.SendRelayAccept(context.Background(), toAlice, bobID, "rq1", aliceID.AccountNumber()); err != nil {
		t.Fatalf("send relay accept: %v", err)
	}
	alice.sessMu.Lock()
	ac := alice.contacts[bobID.AccountNumber()]
	alice.sessMu.Unlock()
	if !ac.RelayHolder || ac.RelayReqID != "" {
		t.Fatalf("alice did not record relay-holder: %+v", ac)
	}
}

func TestRelayRequestFromNonContactRejected(t *testing.T) {
	bob, _ := syncPrimary(t)
	stranger, _ := identity.New()
	toBob := syncFakeDialer{addr: bob.pubLn.Addr().String()}

	// Stranger is not a contact of Bob.
	if err := protocol.SendRelayRequest(context.Background(), toBob, stranger, "rq", bob.myAccount); err == nil {
		t.Fatal("bob accepted a relay request from a non-contact")
	}
}
