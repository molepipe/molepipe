package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// syncFakeDialer routes the "onion" dial to the primary's real pub listener, so
// protocol.SyncExchange exercises the actual /sync routes with no Tor.
type syncFakeDialer struct{ addr string }

func (d syncFakeDialer) DialOnion(_ context.Context, _ string) (net.Conn, error) {
	return net.Dial("tcp", d.addr)
}

func newDeviceKey(t *testing.T) (ed25519.PublicKey, func([]byte) []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, func(msg []byte) []byte { return ed25519.Sign(priv, msg) }
}

// syncPrimary builds an unlocked primary server (with a live pub listener) and
// returns it plus its identity.
func syncPrimary(t *testing.T) (*Server, *identity.Identity) {
	t.Helper()
	s, pw := newTestServer(t)
	id, err := s.store.Load([]byte(pw))
	if err != nil {
		t.Fatal(err)
	}
	s.startSession(id)
	t.Cleanup(s.clearSession)
	return s, id
}

func TestSyncConverges(t *testing.T) {
	primary, id := syncPrimary(t)
	dialer := syncFakeDialer{addr: primary.pubLn.Addr().String()}

	// Primary already has a message; enroll a secondary device.
	primary.sessMu.Lock()
	primary.messages = append(primary.messages, newChatMessage("in", "contactA", "", "hi from primary", time.Unix(1000, 0)))
	primary.contacts["contactA"] = chatstore.Contact{Account: "contactA", Name: "A", Status: "accepted", UpdatedAt: time.Unix(1000, 0)}
	secPub, secSign := newDeviceKey(t)
	primary.devices = append(primary.devices, chatstore.Device{PubKey: secPub, Name: "secondary", AddedAt: time.Now()})
	primary.persistLocked()
	primary.sessMu.Unlock()

	// Secondary's own state (a different message + contact).
	secState, _ := json.Marshal(chatstore.Data{
		Contacts: []chatstore.Contact{{Account: "contactB", Name: "B", Status: "accepted", UpdatedAt: time.Unix(2000, 0)}},
		Messages: []chatstore.Message{{Direction: "in", Peer: "contactB", Text: "hi from secondary", At: time.Unix(2000, 0), ID: chatstore.MessageID("in", "contactB", "hi from secondary", time.Unix(2000, 0))}},
	})

	mergedJSON, err := protocol.SyncExchange(context.Background(), dialer, id, secPub, secSign, secState)
	if err != nil {
		t.Fatalf("sync exchange: %v", err)
	}
	var merged chatstore.Data
	json.Unmarshal(mergedJSON, &merged)

	// The returned state has both sides' messages and contacts.
	if len(merged.Messages) != 2 {
		t.Fatalf("merged messages = %d, want 2", len(merged.Messages))
	}
	if len(merged.Contacts) != 2 {
		t.Fatalf("merged contacts = %d, want 2", len(merged.Contacts))
	}

	// The primary adopted the secondary's data too.
	primary.sessMu.Lock()
	_, hasB := primary.contacts["contactB"]
	nMsgs := len(primary.messages)
	primary.sessMu.Unlock()
	if !hasB || nMsgs != 2 {
		t.Fatalf("primary did not adopt merged state: hasB=%v msgs=%d", hasB, nMsgs)
	}
}

// TestSyncRejectsUnenrolledDevice is the security-critical check: a caller who
// holds the identity key but whose device is NOT enrolled must be rejected. If
// this passes, the pairing-as-second-factor property is real (a stolen recovery
// phrase alone cannot pull history).
func TestSyncRejectsUnenrolledDevice(t *testing.T) {
	primary, id := syncPrimary(t)
	dialer := syncFakeDialer{addr: primary.pubLn.Addr().String()}

	// A brand-new device, correctly signing with the REAL identity key, but never
	// enrolled.
	strangerPub, strangerSign := newDeviceKey(t)
	state, _ := json.Marshal(chatstore.Data{})
	if _, err := protocol.SyncExchange(context.Background(), dialer, id, strangerPub, strangerSign, state); err == nil {
		t.Fatal("unenrolled device with a valid identity signature was allowed to sync")
	}
}

// TestSyncRejectsWrongIdentity: an enrolled device but the WRONG identity key
// (someone else's) must be rejected.
func TestSyncRejectsWrongIdentity(t *testing.T) {
	primary, _ := syncPrimary(t)
	dialer := syncFakeDialer{addr: primary.pubLn.Addr().String()}

	// Enroll a device, but sign the exchange with a different identity.
	pub, sign := newDeviceKey(t)
	primary.sessMu.Lock()
	primary.devices = append(primary.devices, chatstore.Device{PubKey: pub, AddedAt: time.Now()})
	primary.sessMu.Unlock()

	other, _ := identity.New()
	state, _ := json.Marshal(chatstore.Data{})
	if _, err := protocol.SyncExchange(context.Background(), dialer, other, pub, sign, state); err == nil {
		t.Fatal("wrong identity key was allowed to sync")
	}
}

// TestDeliverInboundDedup proves the property the mailbox pickup loop relies on:
// delivering the same message twice (e.g. re-picked-up before a delete confirms)
// stores exactly one copy.
func TestDeliverInboundDedup(t *testing.T) {
	s, _ := syncPrimary(t)
	at := time.Unix(5000, 0)
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if !s.deliverInboundLocked("peer", "", "hello", at, protocol.Reply{}) {
		t.Fatal("first delivery should be new")
	}
	if s.deliverInboundLocked("peer", "", "hello", at, protocol.Reply{}) {
		t.Fatal("second identical delivery should be de-duped")
	}
	n := 0
	for _, m := range s.messages {
		if m.Peer == "peer" && m.Text == "hello" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("stored %d copies, want 1", n)
	}
}

// TestSyncNonceJarCapped verifies the jar bounds its memory under a challenge
// flood: issuing far past the cap never grows it beyond maxSyncNonces, and a
// nonce issued after the flood is still consumable (eviction drops the oldest,
// not the freshest — so a legitimate peer's current challenge always works).
func TestSyncNonceJarCapped(t *testing.T) {
	j := newSyncNonceJar()
	for i := 0; i < maxSyncNonces*3; i++ {
		j.issue()
	}
	j.mu.Lock()
	got := len(j.nonces)
	j.mu.Unlock()
	if got > maxSyncNonces {
		t.Fatalf("jar holds %d nonces, want <= %d", got, maxSyncNonces)
	}
	// A freshly issued nonce survives the cap and is single-use.
	n := j.issue()
	if !j.consume(n) {
		t.Fatal("freshest nonce should be consumable after a flood")
	}
	if j.consume(n) {
		t.Fatal("nonce should be single-use")
	}
}
