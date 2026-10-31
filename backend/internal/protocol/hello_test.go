package protocol

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

// helloPeer builds a peer whose OnPeerOnline hook records who it was told about.
// The returned pointer is read after each call, so a hook that fires when it
// should not is caught as loudly as one that fails to fire.
func helloPeer(t *testing.T, id *identity.Identity) (*Peer, *[]string) {
	t.Helper()
	var seen []string
	p := NewPeer(id, Hooks{
		DisplayName:  func() string { return "" },
		OnPeerOnline: func(sender string) { seen = append(seen, sender) },
	})
	return p, &seen
}

// stampFor builds the hello a caller would send: signed over the timestamp bound
// to the recipient account, exactly as FetchProfileAs does.
func stampFor(from *identity.Identity, recipient string, ts int64) []byte {
	return ed25519.Sign(from.Keys.Signing.Private, HelloSigningBlob(ts, recipient))
}

// The happy path: a contact's signed hello riding the public profile GET tells us
// they are reachable right now, without our ever having dialed them.
func TestProfileHelloMarksSenderOnline(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	peer, seen := helloPeer(t, bob)

	ts := time.Now().Unix()
	if !peer.ServeProfileHello(alice.AccountNumber(), ts, stampFor(alice, bob.AccountNumber(), ts)) {
		t.Fatal("a fresh, correctly signed hello was rejected")
	}
	if len(*seen) != 1 || (*seen)[0] != alice.AccountNumber() {
		t.Fatalf("hook saw %v, want exactly [alice]", *seen)
	}
}

// Freshness must be bounded in BOTH directions. A future-dated stamp is just as
// replayable as a stale one — it stays valid until the clock catches up to it, so
// a one-sided check would let a caller mint a hello good for as long as it dared.
func TestProfileHelloRejectsStampsOutsideTheWindow(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	skew := int64(helloSkew / time.Second)

	for _, c := range []struct {
		name string
		ts   int64
	}{
		{"stale", time.Now().Unix() - skew - 60},
		{"future", time.Now().Unix() + skew + 60},
	} {
		peer, seen := helloPeer(t, bob)
		if peer.ServeProfileHello(alice.AccountNumber(), c.ts, stampFor(alice, bob.AccountNumber(), c.ts)) {
			t.Errorf("%s stamp accepted", c.name)
		}
		if len(*seen) != 0 {
			t.Errorf("%s stamp reached the hook: %v", c.name, *seen)
		}
	}
}

// Inside the window, a captured stamp must not be reusable — the window bounds
// how long it is valid at all, the jar stops it being replayed within that.
func TestProfileHelloRejectsReplay(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	peer, seen := helloPeer(t, bob)

	ts := time.Now().Unix()
	sig := stampFor(alice, bob.AccountNumber(), ts)
	if !peer.ServeProfileHello(alice.AccountNumber(), ts, sig) {
		t.Fatal("first hello rejected")
	}
	if peer.ServeProfileHello(alice.AccountNumber(), ts, sig) {
		t.Error("replayed hello accepted")
	}
	if len(*seen) != 1 {
		t.Errorf("hook fired %d times, want 1", len(*seen))
	}
}

// The reason the signature binds the recipient. Without that binding, any contact
// of alice's could lift the hello she sent THEM and present it to someone else to
// fake her presence there; carol must reject a hello addressed to bob.
func TestProfileHelloCannotBeReplayedToAnotherContact(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	carol, _ := identity.New()

	ts := time.Now().Unix()
	addressedToBob := stampFor(alice, bob.AccountNumber(), ts)

	carolPeer, seen := helloPeer(t, carol)
	if carolPeer.ServeProfileHello(alice.AccountNumber(), ts, addressedToBob) {
		t.Error("a hello addressed to bob was accepted by carol")
	}
	if len(*seen) != 0 {
		t.Errorf("cross-contact replay reached the hook: %v", *seen)
	}
}

// A hello claiming to be from alice but signed by someone else proves nothing.
// The hook must not run: like every other hook on Peer, it is reached only after
// the signature verifies.
func TestProfileHelloRejectsForgedSender(t *testing.T) {
	alice, _ := identity.New()
	mallory, _ := identity.New()
	bob, _ := identity.New()
	peer, seen := helloPeer(t, bob)

	ts := time.Now().Unix()
	forged := stampFor(mallory, bob.AccountNumber(), ts)
	if peer.ServeProfileHello(alice.AccountNumber(), ts, forged) {
		t.Error("hello signed by mallory accepted as alice")
	}
	if len(*seen) != 0 {
		t.Errorf("forged hello reached the hook: %v", *seen)
	}
}

// Structurally malformed stamps must be rejected before any signature work: the
// endpoint is ungated and reachable by anyone on Tor, so junk has to be cheap to
// refuse. This also covers the absent-stamp case the anonymous FetchProfile takes.
func TestProfileHelloRejectsMalformedStamps(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	ts := time.Now().Unix()
	good := stampFor(alice, bob.AccountNumber(), ts)

	for _, c := range []struct {
		name string
		from string
		sig  []byte
	}{
		{"no stamp at all", "", nil},
		{"empty sender", "", good},
		{"nil signature", alice.AccountNumber(), nil},
		{"truncated signature", alice.AccountNumber(), good[:ed25519.SignatureSize-1]},
		{"unparseable sender", "not-an-account", good},
	} {
		peer, seen := helloPeer(t, bob)
		if peer.ServeProfileHello(c.from, ts, c.sig) {
			t.Errorf("%s: accepted", c.name)
		}
		if len(*seen) != 0 {
			t.Errorf("%s: reached the hook", c.name)
		}
	}
}

// A hello addressed to an alias we are still reachable at must verify, so a
// contact who has not yet learned our new address keeps announcing successfully
// through a rotation grace window — the same tolerance the gated requests get.
func TestProfileHelloAcceptsAnAliasOfUs(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	aliasOfBob, _ := identity.New() // stands in for a live alias account of bob's

	peer, seen := helloPeer(t, bob)
	peer.SetLocalAliasAccounts([]string{aliasOfBob.AccountNumber()})

	ts := time.Now().Unix()
	if !peer.ServeProfileHello(alice.AccountNumber(), ts, stampFor(alice, aliasOfBob.AccountNumber(), ts)) {
		t.Fatal("a hello addressed to a live alias of ours was rejected")
	}
	if len(*seen) != 1 {
		t.Fatalf("hook saw %v, want [alice]", *seen)
	}
}

// Peer with no OnPeerOnline wired must not panic — every other hook is optional
// and this one is too (a build that never tracks presence still serves profiles).
func TestProfileHelloWithNoHookWired(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	peer := NewPeer(bob, Hooks{DisplayName: func() string { return "" }})
	ts := time.Now().Unix()
	if !peer.ServeProfileHello(alice.AccountNumber(), ts, stampFor(alice, bob.AccountNumber(), ts)) {
		t.Fatal("verification should still succeed with no hook wired")
	}
}
