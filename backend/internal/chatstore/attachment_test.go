package chatstore

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func newAttachStore(t *testing.T) *AttachmentStore {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return NewAttachmentStore(t.TempDir(), key)
}

const validID = "0123456789abcdef0123456789abcdef"

// TestAttachmentRoundTrip: bytes written come back identical, Has/Delete work.
func TestAttachmentRoundTrip(t *testing.T) {
	as := newAttachStore(t)
	data := bytes.Repeat([]byte{0x42, 0x00, 0xFE}, 5000)
	if err := as.Put(validID, data); err != nil {
		t.Fatal(err)
	}
	if !as.Has(validID) {
		t.Fatal("Has is false after Put")
	}
	got, err := as.Get(validID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("round-trip bytes differ")
	}
	as.Delete(validID)
	if as.Has(validID) {
		t.Fatal("still present after Delete")
	}
}

// TestAttachmentInvalidID: only the hex randomID() shape is accepted, so a
// crafted id can't traverse out of the attachments directory.
func TestAttachmentInvalidID(t *testing.T) {
	as := newAttachStore(t)
	for _, bad := range []string{"../secret", "SHORT", "0123456789abcdef0123456789abcdeg", "0123456789abcdef0123456789abcde/"} {
		if err := as.Put(bad, []byte("x")); err == nil {
			t.Fatalf("invalid id %q was accepted", bad)
		}
	}
}

// TestAttachmentAADBinding: a blob's ciphertext is bound to its id, so copying
// one attachment's file to another id can't be decrypted (no blob substitution).
func TestAttachmentAADBinding(t *testing.T) {
	as := newAttachStore(t)
	if err := as.Put(validID, []byte("secret image")); err != nil {
		t.Fatal(err)
	}
	otherID := "ffffffffffffffffffffffffffffffff"
	raw, err := os.ReadFile(as.path(validID))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(as.path(otherID), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := as.Get(otherID); err == nil {
		t.Fatal("a blob decrypted under a different id (AAD not binding the id)")
	}
}

// TestAttachmentDirWipeable: the store lives in a single directory a wipe can
// remove wholesale (the account-removal path relies on this).
func TestAttachmentDirWipeable(t *testing.T) {
	as := newAttachStore(t)
	_ = as.Put(validID, []byte("x"))
	if _, err := os.Stat(as.dir); err != nil {
		t.Fatalf("attachments dir missing: %v", err)
	}
	if filepath.Base(as.dir) != attachDirName {
		t.Fatalf("attachments dir name drifted from wipe's expectation: %s", filepath.Base(as.dir))
	}
	_ = os.RemoveAll(as.dir)
	if as.Has(validID) {
		t.Fatal("blob survived dir removal")
	}
}
