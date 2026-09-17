package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/device"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// TestPairEnrollThenSync exercises the full pairing security property: a new
// device enrolls using a pairing secret (physical access), and ONLY then can it
// sync. Before enrollment, /sync rejects it (proven in TestSyncRejectsUnenrolled).
func TestPairEnrollThenSync(t *testing.T) {
	primary, id := syncPrimary(t)
	dialer := syncFakeDialer{addr: primary.pubLn.Addr().String()}

	// Existing device mints a pairing secret (what /api/pair/start does).
	secret := primary.pairSecrets.issue()

	// New device (same identity, its own device key) enrolls with the secret.
	newPub, newSign := newDeviceKey(t)
	if err := protocol.PairEnroll(context.Background(), dialer, id, newPub, "laptop", secret); err != nil {
		t.Fatalf("pair enroll: %v", err)
	}

	// It is now in the enrolled list...
	if !primary.isEnrolledDevice(newPub) {
		t.Fatal("device not enrolled after pairing")
	}
	// ...and can therefore sync.
	state, _ := json.Marshal(chatstore.Data{})
	if _, err := protocol.SyncExchange(context.Background(), dialer, id, newPub, newSign, state); err != nil {
		t.Fatalf("enrolled device could not sync: %v", err)
	}
}

func TestPairRejectsBadAndReusedSecret(t *testing.T) {
	primary, id := syncPrimary(t)
	dialer := syncFakeDialer{addr: primary.pubLn.Addr().String()}

	newPub, _ := newDeviceKey(t)

	// Wrong secret: rejected, and no enrollment happens.
	if err := protocol.PairEnroll(context.Background(), dialer, id, newPub, "x", []byte("not-the-secret")); err == nil {
		t.Fatal("enrollment accepted a wrong pairing secret")
	}
	if primary.isEnrolledDevice(newPub) {
		t.Fatal("device enrolled despite a wrong secret")
	}

	// Correct secret works once...
	secret := primary.pairSecrets.issue()
	if err := protocol.PairEnroll(context.Background(), dialer, id, newPub, "x", secret); err != nil {
		t.Fatalf("valid enroll failed: %v", err)
	}
	// ...but the single-use secret can't be replayed for another device.
	otherPub, _ := newDeviceKey(t)
	if err := protocol.PairEnroll(context.Background(), dialer, id, otherPub, "y", secret); err == nil {
		t.Fatal("pairing secret was reusable")
	}
	if primary.isEnrolledDevice(otherPub) {
		t.Fatal("second device enrolled by replaying a consumed secret")
	}
}

// A secondary must still bring Tor up. "Don't publish the account onion" was
// implemented as "don't start Tor", which left a secondary with no SOCKS proxy
// and therefore no way to send a message or pull a sync — the whole role was
// inert. The unit fakes hid it because their Dialer works whether or not Start
// was ever called.
func TestSecondaryStartsTorAsAClient(t *testing.T) {
	store, err := identity.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(id, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	fake := &fakeOnion{}
	s := New(store, fake)
	if _, err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(nil) })
	s.device.Role = device.RoleSecondary

	unlockWithPassword(t, s, "pw")

	fake.mu.Lock()
	clientStarts, published := fake.clientStarts, fake.started
	fake.mu.Unlock()
	if clientStarts == 0 {
		t.Error("a secondary must start Tor in client mode, or it has no transport at all")
	}
	if published != 0 {
		t.Error("a secondary must not publish the account onion")
	}
}

// Recovering an account that may still be live elsewhere must not publish a
// second descriptor for the same address: the two collide on the HSDir
// hashring, both devices go intermittently unreachable, and pairing — which
// has to dial that very address — cannot complete either.
func TestRecoveredDeviceDoesNotPublish(t *testing.T) {
	store, err := identity.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeOnion{}
	s := New(store, fake)
	if _, err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(nil) })

	body, _ := json.Marshal(map[string]string{"mnemonic": id.MnemonicString(), "password": "New-password1"})
	r := s.do(t, "POST", "/api/recover", string(body), map[string]string{"Origin": s.origin()})
	if r.Code != http.StatusOK {
		t.Fatalf("recover: %d (%s)", r.Code, r.Body)
	}
	if role := decode(t, r.Body)["role"]; role != string(device.RoleSecondary) {
		t.Errorf("a recovered device should report itself secondary, got %v", role)
	}
	if s.device.IsPrimary() {
		t.Error("recovered device is still primary")
	}

	unlockWithPassword(t, s, "New-password1")
	fake.mu.Lock()
	published, clientStarts := fake.started, fake.clientStarts
	fake.mu.Unlock()
	if published != 0 {
		t.Error("a recovered device published the account onion, colliding with any existing primary")
	}
	if clientStarts == 0 {
		t.Error("a recovered device should still have a Tor client transport")
	}
}
