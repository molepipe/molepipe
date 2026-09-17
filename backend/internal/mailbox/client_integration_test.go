package mailbox

import (
	"context"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// fakeDialer ignores the onion target and connects to the local httptest server,
// so the real protocol mailbox client talks to the real mailbox server with no
// Tor involved.
type fakeDialer struct{ addr string }

func (d fakeDialer) DialOnion(_ context.Context, _ string) (net.Conn, error) {
	return net.Dial("tcp", d.addr)
}

// TestMailboxClientServerEndToEnd exercises the protocol client funcs against the
// real server: check-in, seal+drop-off, pickup+decrypt, replay de-dup, delete.
func TestMailboxClientServerEndToEnd(t *testing.T) {
	store, err := New(Config{Dir: t.TempDir(), Defaults: Caps{}})
	if err != nil {
		t.Fatal(err)
	}
	httptestSrv := httptest.NewServer(NewServer(store).Handler())
	defer httptestSrv.Close()
	dialer := fakeDialer{addr: httptestSrv.Listener.Addr().String()}
	const box = "mailbox.onion"
	ctx := context.Background()

	bob, _ := identity.New()   // mailbox owner
	alice, _ := identity.New() // sender

	// Bob checks in.
	if _, err := protocol.MailboxCheckIn(ctx, dialer, bob, box); err != nil {
		t.Fatalf("check-in: %v", err)
	}

	// Alice seals and drops off, using Bob's cached DH key.
	env, err := protocol.SealMailEnvelope(alice, bob.AccountNumber(), bob.Keys.DH.Public, "mid-1", "offline hi", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.MailboxDropOff(ctx, dialer, env, box); err != nil {
		t.Fatalf("drop-off: %v", err)
	}
	// A replayed drop-off (identical bytes) must collapse by ID.
	if err := protocol.MailboxDropOff(ctx, dialer, env, box); err != nil {
		t.Fatalf("replay drop-off: %v", err)
	}

	// Bob picks up and decrypts.
	items, err := protocol.MailboxPickup(ctx, dialer, bob, box)
	if err != nil {
		t.Fatalf("pickup: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("pickup returned %d items, want 1 (replay not de-duped)", len(items))
	}
	sender, _, text, _, err := protocol.OpenMailEnvelope(bob, items[0])
	if err != nil {
		t.Fatal(err)
	}
	if sender != alice.AccountNumber() || text != "offline hi" {
		t.Fatalf("decrypted: sender=%s text=%q", sender, text)
	}

	// Delete after pickup, then confirm empty.
	if err := protocol.MailboxDelete(ctx, dialer, bob, box, []string{items[0].ID()}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	items, err = protocol.MailboxPickup(ctx, dialer, bob, box)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("mailbox not empty after delete: %d", len(items))
	}
}
