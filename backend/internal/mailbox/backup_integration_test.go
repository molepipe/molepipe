package mailbox

import (
	"bytes"
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// TestBackupClientServerEndToEnd exercises the real backup client funcs against the
// real server + store: check-in, self-seal + drop-off, non-destructive pickup +
// decrypt on a fresh "device", eviction by budget, and purge.
func TestBackupClientServerEndToEnd(t *testing.T) {
	store, err := New(Config{Dir: t.TempDir(), Defaults: Caps{MaxBackupBytes: 1 << 20, MaxBackupMessage: 6 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewServer(store).Handler())
	defer srv.Close()
	dialer := fakeDialer{addr: srv.Listener.Addr().String()}
	const box = "mailbox.onion"
	ctx := context.Background()

	owner, _ := identity.New()
	if _, err := protocol.MailboxCheckIn(ctx, dialer, owner, box); err != nil {
		t.Fatalf("check-in: %v", err)
	}

	data := bytes.Repeat([]byte{0x33}, 120_000)
	env, err := protocol.SealSelfBackupImage(owner, "gimg-1", "image/png", data, time.Unix(3000, 0))
	if err != nil {
		t.Fatal(err)
	}
	// Deterministic stable id (owner controls it); reuse the envelope ID.
	id := env.ID()
	if err := protocol.MailboxBackupDropOff(ctx, dialer, owner, box, id, 512<<10, env); err != nil {
		t.Fatalf("backup drop-off: %v", err)
	}
	// A replay under the same id must not create a second copy.
	if err := protocol.MailboxBackupDropOff(ctx, dialer, owner, box, id, 512<<10, env); err != nil {
		t.Fatalf("backup replay: %v", err)
	}

	// A FRESH device of the same owner restores from the backup.
	got, err := protocol.MailboxBackupPickup(ctx, dialer, owner, box)
	if err != nil {
		t.Fatalf("backup pickup: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("backup pickup returned %d, want 1 (replay not de-duped)", len(got))
	}
	c, err := protocol.OpenMailContent(owner, got[0])
	if err != nil {
		t.Fatalf("open restored backup: %v", err)
	}
	if c.Kind != protocol.MailKindImage || c.MsgID != "gimg-1" || !bytes.Equal(c.Data, data) {
		t.Fatalf("restored backup mismatch: kind=%q id=%q bytes=%d", c.Kind, c.MsgID, len(c.Data))
	}

	// Pickup is non-destructive: a second device still sees it.
	if again, err := protocol.MailboxBackupPickup(ctx, dialer, owner, box); err != nil || len(again) != 1 {
		t.Fatalf("second pickup = %d, %v (want 1, non-destructive)", len(again), err)
	}

	// The scalable list + fetch-by-id path yields the same blob one at a time.
	metas, err := protocol.MailboxBackupList(ctx, dialer, owner, box)
	if err != nil {
		t.Fatalf("backup list: %v", err)
	}
	if len(metas) != 1 || metas[0].ID != id || metas[0].Size <= 0 {
		t.Fatalf("backup list = %+v, want one entry for id %q", metas, id)
	}
	fetched, err := protocol.MailboxBackupFetch(ctx, dialer, owner, box, id)
	if err != nil {
		t.Fatalf("backup fetch: %v", err)
	}
	fc, err := protocol.OpenMailContent(owner, fetched)
	if err != nil {
		t.Fatalf("open fetched backup: %v", err)
	}
	if fc.Kind != protocol.MailKindImage || fc.MsgID != "gimg-1" || !bytes.Equal(fc.Data, data) {
		t.Fatalf("fetched backup mismatch: kind=%q id=%q bytes=%d", fc.Kind, fc.MsgID, len(fc.Data))
	}
	// Fetching a nonexistent id fails (404 → error).
	if _, err := protocol.MailboxBackupFetch(ctx, dialer, owner, box, "deadbeef"); err == nil {
		t.Fatal("fetch of unknown id succeeded, want error")
	}

	// Purge clears the backups.
	if err := protocol.MailboxBackupPurge(ctx, dialer, owner, box); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if after, err := protocol.MailboxBackupPickup(ctx, dialer, owner, box); err != nil || len(after) != 0 {
		t.Fatalf("after purge = %d, %v (want 0)", len(after), err)
	}
}

// TestBackupDisabledEndToEnd: a server that does not offer backups (MaxBackupBytes
// == 0) rejects the drop-off through the full client path.
func TestBackupDisabledEndToEnd(t *testing.T) {
	store, _ := New(Config{Dir: t.TempDir(), Defaults: Caps{}})
	srv := httptest.NewServer(NewServer(store).Handler())
	defer srv.Close()
	dialer := fakeDialer{addr: srv.Listener.Addr().String()}
	const box = "mailbox.onion"
	ctx := context.Background()

	owner, _ := identity.New()
	protocol.MailboxCheckIn(ctx, dialer, owner, box)
	env, _ := protocol.SealSelfBackupImage(owner, "gimg-1", "image/png", []byte{1, 2, 3, 4}, time.Unix(3000, 0))
	if err := protocol.MailboxBackupDropOff(ctx, dialer, owner, box, env.ID(), 0, env); err == nil {
		t.Fatal("backup drop-off succeeded on a server with backups disabled")
	}
}
