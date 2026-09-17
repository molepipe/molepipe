package mailbox

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	store, err := New(Config{Dir: t.TempDir(), Defaults: Caps{}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewServer(store).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func nonce(t *testing.T, base string) []byte {
	t.Helper()
	resp, err := http.Get(base + "/mailbox/challenge")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var r struct {
		Nonce []byte `json:"nonce"`
	}
	json.NewDecoder(resp.Body).Decode(&r)
	if len(r.Nonce) == 0 {
		t.Fatal("empty nonce")
	}
	return r.Nonce
}

func post(t *testing.T, url string, req, out any) int {
	t.Helper()
	b, _ := json.Marshal(req)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode == http.StatusOK {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func signedOp(id *identity.Identity, op string, n []byte, extra ...[]byte) []byte {
	return ed25519.Sign(id.Keys.Signing.Private, protocol.MailboxAuthBlob(op, n, id.AccountNumber(), extra...))
}

func TestMailboxLifecycle(t *testing.T) {
	srv := testServer(t)
	base := srv.URL

	bob, _ := identity.New()   // recipient / mailbox owner
	alice, _ := identity.New() // sender

	// Check-in enables the mailbox.
	n := nonce(t, base)
	checkin := map[string]any{"account": bob.AccountNumber(), "nonce": n, "sig": signedOp(bob, protocol.MailboxOpCheckin, n)}
	if code := post(t, base+"/mailbox/checkin", checkin, nil); code != http.StatusOK {
		t.Fatalf("checkin: %d", code)
	}

	// Alice drops off a message for Bob.
	env, err := protocol.SealMailEnvelope(alice, bob.AccountNumber(), bob.Keys.DH.Public, "mid-1", "offline hello", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code := post(t, base+"/mailbox/dropoff", map[string]any{"envelope": env}, nil); code != http.StatusOK {
		t.Fatalf("dropoff: %d", code)
	}

	// Bob picks up and decrypts.
	n = nonce(t, base)
	var picked struct {
		Items []struct {
			ID       string                `json:"id"`
			Envelope protocol.MailEnvelope `json:"envelope"`
		} `json:"items"`
	}
	pickup := map[string]any{"account": bob.AccountNumber(), "nonce": n, "sig": signedOp(bob, protocol.MailboxOpPickup, n)}
	if code := post(t, base+"/mailbox/pickup", pickup, &picked); code != http.StatusOK {
		t.Fatalf("pickup: %d", code)
	}
	if len(picked.Items) != 1 {
		t.Fatalf("picked up %d items, want 1", len(picked.Items))
	}
	sender, _, text, _, err := protocol.OpenMailEnvelope(bob, picked.Items[0].Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if sender != alice.AccountNumber() || text != "offline hello" {
		t.Fatalf("decrypted: sender=%s text=%q", sender, text)
	}

	// Delete after pickup, then confirm the mailbox is empty.
	id := picked.Items[0].ID
	n = nonce(t, base)
	del := map[string]any{"account": bob.AccountNumber(), "nonce": n, "sig": signedOp(bob, protocol.MailboxOpDelete, n, protocol.MailboxDeleteBinding([]string{id})), "ids": []string{id}}
	if code := post(t, base+"/mailbox/delete", del, nil); code != http.StatusOK {
		t.Fatalf("delete: %d", code)
	}
	n = nonce(t, base)
	picked.Items = nil
	post(t, base+"/mailbox/pickup", map[string]any{"account": bob.AccountNumber(), "nonce": n, "sig": signedOp(bob, protocol.MailboxOpPickup, n)}, &picked)
	if len(picked.Items) != 0 {
		t.Fatalf("mailbox not empty after delete: %d", len(picked.Items))
	}
}

func TestDropoffToUncheckedAccountRejected(t *testing.T) {
	srv := testServer(t)
	bob, _ := identity.New() // never checks in
	alice, _ := identity.New()
	env, _ := protocol.SealMailEnvelope(alice, bob.AccountNumber(), bob.Keys.DH.Public, "mid-1", "hi", time.Now())
	if code := post(t, srv.URL+"/mailbox/dropoff", map[string]any{"envelope": env}, nil); code != http.StatusNotFound {
		t.Fatalf("dropoff to unchecked account: got %d, want 404", code)
	}
}

func TestPickupAuthFailures(t *testing.T) {
	srv := testServer(t)
	base := srv.URL
	bob, _ := identity.New()
	mallory, _ := identity.New()

	n := nonce(t, base)
	post(t, base+"/mailbox/checkin", map[string]any{"account": bob.AccountNumber(), "nonce": n, "sig": signedOp(bob, protocol.MailboxOpCheckin, n)}, nil)

	// Wrong key: Mallory signs a pickup for Bob's account.
	n = nonce(t, base)
	forged := ed25519.Sign(mallory.Keys.Signing.Private, protocol.MailboxAuthBlob(protocol.MailboxOpPickup, n, bob.AccountNumber()))
	if code := post(t, base+"/mailbox/pickup", map[string]any{"account": bob.AccountNumber(), "nonce": n, "sig": forged}, nil); code != http.StatusUnauthorized {
		t.Fatalf("forged pickup: got %d, want 401", code)
	}

	// Replay: a consumed nonce must not work again.
	n = nonce(t, base)
	good := map[string]any{"account": bob.AccountNumber(), "nonce": n, "sig": signedOp(bob, protocol.MailboxOpPickup, n)}
	if code := post(t, base+"/mailbox/pickup", good, nil); code != http.StatusOK {
		t.Fatalf("first pickup: %d", code)
	}
	if code := post(t, base+"/mailbox/pickup", good, nil); code != http.StatusUnauthorized {
		t.Fatalf("nonce replay: got %d, want 401", code)
	}
}

// TestNonceJarCapped verifies the challenge jar bounds its memory under a flood:
// GET /mailbox/challenge is unauthenticated, so an attacker could otherwise grow
// it without limit for the nonce TTL. Issuing far past the cap must never exceed
// maxNonces, and a nonce issued after the flood must still be consumable (we
// evict the oldest, not the freshest).
func TestNonceJarCapped(t *testing.T) {
	j := newNonceJar(nonceTTL)
	for i := 0; i < maxNonces*3; i++ {
		j.Issue()
	}
	j.mu.Lock()
	got := len(j.nonces)
	j.mu.Unlock()
	if got > maxNonces {
		t.Fatalf("jar holds %d nonces, want <= %d", got, maxNonces)
	}
	n := j.Issue()
	if !j.Consume(n) {
		t.Fatal("freshest nonce should be consumable after a flood")
	}
	if j.Consume(n) {
		t.Fatal("nonce should be single-use")
	}
}
