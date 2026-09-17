package mailbox

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

func acct(t *testing.T) string {
	t.Helper()
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	return id.AccountNumber()
}

func newStore(t *testing.T, caps Caps) *Store {
	t.Helper()
	s, err := New(Config{Dir: t.TempDir(), Defaults: caps})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDropOffRequiresCheckIn(t *testing.T) {
	s := newStore(t, Caps{})
	bob := acct(t)

	if err := s.DropOff(bob, "abc123", []byte("blob")); !errors.Is(err, ErrNoMailbox) {
		t.Fatalf("drop-off before check-in: got %v, want ErrNoMailbox", err)
	}
	// Crucially, the refused drop-off must NOT have created a tenancy.
	if _, err := os.Stat(s.tenantDir(bob)); !os.IsNotExist(err) {
		t.Fatal("drop-off created a tenant dir without a check-in")
	}

	if _, err := s.CheckIn(bob); err != nil {
		t.Fatal(err)
	}
	if err := s.DropOff(bob, "abc123", []byte("blob")); err != nil {
		t.Fatalf("drop-off after check-in: %v", err)
	}
	items, err := s.Pickup(bob)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || string(items[0].Blob) != "blob" || items[0].ID != "abc123" {
		t.Fatalf("pickup = %+v", items)
	}
}

func TestDropOffReplayDedup(t *testing.T) {
	s := newStore(t, Caps{})
	bob := acct(t)
	s.CheckIn(bob)

	for i := 0; i < 3; i++ { // same id three times (replay)
		if err := s.DropOff(bob, "deadbeef", []byte("v")); err != nil {
			t.Fatal(err)
		}
	}
	items, _ := s.Pickup(bob)
	if len(items) != 1 {
		t.Fatalf("replayed drop-offs stored %d copies, want 1", len(items))
	}
}

func TestCaps(t *testing.T) {
	bob := acct(t)

	t.Run("count", func(t *testing.T) {
		s := newStore(t, Caps{MaxMessages: 2})
		s.CheckIn(bob)
		s.DropOff(bob, "01", []byte("a"))
		s.DropOff(bob, "02", []byte("b"))
		if err := s.DropOff(bob, "03", []byte("c")); !errors.Is(err, ErrOverCap) {
			t.Fatalf("over count cap: got %v", err)
		}
	})
	t.Run("bytes", func(t *testing.T) {
		s := newStore(t, Caps{MaxBytes: 5})
		s.CheckIn(bob)
		s.DropOff(bob, "01", []byte("abc")) // 3
		if err := s.DropOff(bob, "02", []byte("def")); !errors.Is(err, ErrOverCap) {
			t.Fatalf("over byte cap: got %v", err)
		}
	})
	t.Run("single-message", func(t *testing.T) {
		s := newStore(t, Caps{MaxMessage: 4})
		s.CheckIn(bob)
		if err := s.DropOff(bob, "01", []byte("toolong")); !errors.Is(err, ErrOverCap) {
			t.Fatalf("over single-message cap: got %v", err)
		}
	})
}

func TestDeleteAndForget(t *testing.T) {
	s := newStore(t, Caps{})
	bob := acct(t)
	s.CheckIn(bob)
	s.DropOff(bob, "01", []byte("a"))
	s.DropOff(bob, "02", []byte("b"))

	if err := s.Delete(bob, []string{"01"}); err != nil {
		t.Fatal(err)
	}
	items, _ := s.Pickup(bob)
	if len(items) != 1 || items[0].ID != "02" {
		t.Fatalf("after delete: %+v", items)
	}

	if err := s.Forget(bob); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.tenantDir(bob)); !os.IsNotExist(err) {
		t.Fatal("forget did not purge the tenant dir")
	}
}

func TestSweepExpiry(t *testing.T) {
	s := newStore(t, Caps{BlobTTL: time.Hour, IdleTTL: 24 * time.Hour})
	bob := acct(t)
	s.CheckIn(bob)
	s.DropOff(bob, "01", []byte("a"))

	// Advance the clock past BlobTTL but not IdleTTL: the blob expires, the
	// tenancy survives.
	s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if items, _ := s.Pickup(bob); len(items) != 0 {
		t.Fatal("expired blob still returned by pickup")
	}
	if err := s.Sweep(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.tenantDir(bob)); err != nil {
		t.Fatal("tenancy purged too early")
	}
	if _, err := os.Stat(filepath.Join(s.tenantDir(bob), blobPrefix+"01"+blobSuffix)); !os.IsNotExist(err) {
		t.Fatal("sweep left the expired blob")
	}

	// Advance past IdleTTL: the whole tenancy is purged.
	s.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	if err := s.Sweep(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.tenantDir(bob)); !os.IsNotExist(err) {
		t.Fatal("idle tenancy not purged by sweep")
	}
}

func TestUsageAndOverrides(t *testing.T) {
	bob := acct(t)
	s, err := New(Config{
		Dir:       t.TempDir(),
		Defaults:  Caps{MaxMessages: 10},
		Overrides: map[string]Caps{bob: {MaxMessages: 100}},
	})
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.CheckIn(bob)
	if err != nil {
		t.Fatal(err)
	}
	if u.Caps.MaxMessages != 100 {
		t.Fatalf("override not applied: caps=%+v", u.Caps)
	}
	s.DropOff(bob, "01", []byte("hello")) // 5 bytes
	u, _ = s.Usage(bob)
	if u.Messages != 1 || u.Bytes != 5 {
		t.Fatalf("usage = %+v", u)
	}
}

func TestInvalidInputsRejected(t *testing.T) {
	s := newStore(t, Caps{})
	bob := acct(t)
	s.CheckIn(bob)

	if err := s.DropOff("not-an-account", "01", []byte("x")); err == nil {
		t.Error("invalid recipient accepted")
	}
	if err := s.DropOff(bob, "../escape", []byte("x")); err == nil {
		t.Error("path-traversal blob id accepted")
	}
	if _, err := s.CheckIn("nope"); err == nil {
		t.Error("invalid account checked in")
	}
}

func TestDeleteMissingIsNoOp(t *testing.T) {
	s := newStore(t, Caps{})
	bob := acct(t)
	s.CheckIn(bob)
	// Deleting an id that was never stored (or a second device deleting an already
	// removed blob) must not error.
	if err := s.Delete(bob, []string{"never01", "never02"}); err != nil {
		t.Fatalf("delete of missing ids errored: %v", err)
	}
}

func TestBackupRequiresCheckInAndBudget(t *testing.T) {
	bob := acct(t)

	t.Run("requires check-in", func(t *testing.T) {
		s := newStore(t, Caps{MaxBackupBytes: 100})
		if err := s.DropOffBackup(bob, "01", []byte("x"), 0); !errors.Is(err, ErrNoMailbox) {
			t.Fatalf("backup before check-in: got %v, want ErrNoMailbox", err)
		}
		// and it must not have created a tenancy
		if _, err := os.Stat(s.tenantDir(bob)); !os.IsNotExist(err) {
			t.Fatal("refused backup created a tenant dir")
		}
	})

	t.Run("disabled when budget zero", func(t *testing.T) {
		s := newStore(t, Caps{}) // MaxBackupBytes == 0
		s.CheckIn(bob)
		if err := s.DropOffBackup(bob, "01", []byte("x"), 0); !errors.Is(err, ErrBackupDisabled) {
			t.Fatalf("backup with zero server budget: got %v, want ErrBackupDisabled", err)
		}
	})
}

// Backups must live in a class of their own: routine message pickup/delete must
// not touch them, and the message caps must not count them (nor vice versa).
func TestBackupIsolatedFromMessages(t *testing.T) {
	s := newStore(t, Caps{MaxMessages: 1, MaxBytes: 4, MaxBackupBytes: 1 << 20})
	bob := acct(t)
	s.CheckIn(bob)

	if err := s.DropOffBackup(bob, "b1", []byte("backupdata"), 0); err != nil {
		t.Fatalf("backup drop: %v", err)
	}
	// A backup present must not consume the (tight) message caps.
	if err := s.DropOff(bob, "1a", []byte("msg")); err != nil {
		t.Fatalf("message drop after backup: %v", err)
	}
	// Normal pickup returns only the message, and does not surface the backup.
	items, _ := s.Pickup(bob)
	if len(items) != 1 || items[0].ID != "1a" {
		t.Fatalf("pickup should see only the message: %+v", items)
	}
	// Deleting the message (routine post-pickup cleanup) must leave the backup.
	if err := s.Delete(bob, []string{"1a"}); err != nil {
		t.Fatal(err)
	}
	back, _ := s.PickupBackup(bob)
	if len(back) != 1 || back[0].ID != "b1" || string(back[0].Blob) != "backupdata" {
		t.Fatalf("backup should survive message pickup+delete: %+v", back)
	}
	// PickupBackup is non-destructive: a second call still returns it.
	if again, _ := s.PickupBackup(bob); len(again) != 1 {
		t.Fatalf("PickupBackup must not delete: got %d", len(again))
	}
}

func TestBackupEvictsOldest(t *testing.T) {
	// Budget of 30 bytes; each blob is 10 bytes → holds 3 at a time.
	s := newStore(t, Caps{MaxBackupBytes: 30})
	bob := acct(t)
	s.CheckIn(bob)

	blob := []byte("0123456789") // 10 bytes
	ids := []string{"a1", "b2", "c3", "d4", "e5"}
	for _, id := range ids {
		if err := s.DropOffBackup(bob, id, blob, 0); err != nil {
			t.Fatalf("drop %s: %v", id, err)
		}
		// distinct, increasing mod times so eviction order is well-defined
		fp := filepath.Join(s.tenantDir(bob), backupPrefix+id+blobSuffix)
		mt := time.Now().Add(time.Duration(len(id)) * time.Second)
		if err := os.Chtimes(fp, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	got, bytes := backupIDs(t, s, bob)
	if bytes > 30 {
		t.Fatalf("backup bytes %d exceeds budget 30", bytes)
	}
	// Oldest two (a1,b2) evicted; newest three remain.
	want := map[string]bool{"c3": true, "d4": true, "e5": true}
	if len(got) != 3 {
		t.Fatalf("want 3 backups, got %v", got)
	}
	for _, id := range got {
		if !want[id] {
			t.Fatalf("unexpected surviving backup %q (evicted set wrong): %v", id, got)
		}
	}
}

func TestBackupClientBudgetShrinksServerCap(t *testing.T) {
	// Server allows 100 bytes, but the client asks for only 15 → holds 1 ten-byte blob.
	s := newStore(t, Caps{MaxBackupBytes: 100})
	bob := acct(t)
	s.CheckIn(bob)

	blob := []byte("0123456789") // 10 bytes
	for i, id := range []string{"a1", "b2", "c3"} {
		if err := s.DropOffBackup(bob, id, blob, 15); err != nil {
			t.Fatalf("drop %s: %v", id, err)
		}
		fp := filepath.Join(s.tenantDir(bob), backupPrefix+id+blobSuffix)
		mt := time.Now().Add(time.Duration(i) * time.Second)
		os.Chtimes(fp, mt, mt)
	}
	got, bytes := backupIDs(t, s, bob)
	if bytes > 15 || len(got) != 1 || got[0] != "c3" {
		t.Fatalf("client budget 15 should hold only newest blob: got %v (%d bytes)", got, bytes)
	}
}

func TestBackupPerBlobAndPurge(t *testing.T) {
	s := newStore(t, Caps{MaxMessage: 4, MaxBackupBytes: 100})
	bob := acct(t)
	s.CheckIn(bob)

	// A blob over the per-blob ceiling (MaxMessage) is refused.
	if err := s.DropOffBackup(bob, "b16", []byte("toolong"), 0); !errors.Is(err, ErrOverCap) {
		t.Fatalf("over per-blob ceiling: got %v, want ErrOverCap", err)
	}
	// De-dup: same id twice stores one.
	s.DropOffBackup(bob, "c1", []byte("ab"), 0)
	s.DropOffBackup(bob, "c1", []byte("ab"), 0)
	if got, _ := backupIDs(t, s, bob); len(got) != 1 {
		t.Fatalf("de-dup failed: %v", got)
	}
	// Purge clears backups but leaves the tenancy checked in.
	if err := s.PurgeBackups(bob); err != nil {
		t.Fatal(err)
	}
	if got, _ := backupIDs(t, s, bob); len(got) != 0 {
		t.Fatalf("purge left backups: %v", got)
	}
	if !s.checkedIn(s.tenantDir(bob)) {
		t.Fatal("purge removed the check-in marker")
	}
}

func backupIDs(t *testing.T, s *Store, account string) ([]string, int64) {
	t.Helper()
	items, err := s.PickupBackup(account)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	var bytes int64
	for _, it := range items {
		ids = append(ids, it.ID)
		bytes += int64(len(it.Blob))
	}
	return ids, bytes
}
