package mailbox

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

func newTestAccount(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return identity.AccountNumberForPub(pub)
}

func randBlobID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// GlobalMaxTenants bounds how many tenancies an open-drop-off (relay) store will
// create, so an approved relay sender cannot exhaust the disk by addressing
// endless invented recipients — the per-account caps bound each bucket's size
// but not their number.
func TestGlobalMaxTenantsCapsRelayTenancies(t *testing.T) {
	s, err := New(Config{
		Dir:              t.TempDir(),
		OpenDropOff:      true,
		GlobalMaxTenants: 3,
		Defaults:         Caps{MaxMessages: 100, MaxBytes: 5 << 20, MaxMessage: 32 << 10, BlobTTL: time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The first 3 distinct recipients each create a tenancy and are accepted.
	for i := 0; i < 3; i++ {
		if err := s.DropOff(newTestAccount(t), randBlobID(t), []byte("hi")); err != nil {
			t.Fatalf("recipient %d should be accepted: %v", i, err)
		}
	}
	// A 4th brand-new recipient is refused — the tenancy cap is hit.
	if err := s.DropOff(newTestAccount(t), randBlobID(t), []byte("hi")); !errors.Is(err, ErrOverCap) {
		t.Fatalf("4th new tenancy: want ErrOverCap, got %v", err)
	}
	// An EXISTING tenancy still accepts more blobs: the cap is on tenancy count,
	// not a freeze on established recipients.
	rs, err := s.Recipients()
	if err != nil || len(rs) != 3 {
		t.Fatalf("want 3 tenancies, got %d (%v)", len(rs), err)
	}
	if err := s.DropOff(rs[0], randBlobID(t), []byte("second blob")); err != nil {
		t.Fatalf("existing tenancy should still accept: %v", err)
	}
}

// Zero GlobalMaxTenants means unlimited — the dedicated mailbox server's setting,
// where tenancies are created only by a signed check-in.
func TestGlobalMaxTenantsZeroIsUnlimited(t *testing.T) {
	s, err := New(Config{
		Dir:         t.TempDir(),
		OpenDropOff: true,
		Defaults:    Caps{MaxMessages: 100, MaxBytes: 5 << 20, MaxMessage: 32 << 10, BlobTTL: time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if err := s.DropOff(newTestAccount(t), randBlobID(t), []byte("x")); err != nil {
			t.Fatalf("uncapped store rejected tenancy %d: %v", i, err)
		}
	}
}
