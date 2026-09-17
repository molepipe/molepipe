package chatstore

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func avatarKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestAvatarStoreRoundTrip(t *testing.T) {
	st := NewAvatarStore(t.TempDir(), avatarKey(t))
	data := []byte("pretend-image-bytes")
	hash := AvatarHashBytes(data)

	if st.Has(hash) {
		t.Fatal("empty store reports Has")
	}
	if err := st.Put(hash, data); err != nil {
		t.Fatalf("put: %v", err)
	}
	if !st.Has(hash) {
		t.Fatal("Has false after put")
	}
	got, err := st.Get(hash)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("roundtrip mismatch: %q != %q", got, data)
	}
}

// Put must reject bytes whose sha256 is not the claimed hash — the store is
// content-addressed, so a spoofed push (id says one thing, bytes another) can
// never poison the cache. This is what lets FetchAvatar trust a hash from the
// signed card and every reader trust the stored bytes.
func TestAvatarStoreRejectsHashMismatch(t *testing.T) {
	st := NewAvatarStore(t.TempDir(), avatarKey(t))
	realHash := AvatarHashBytes([]byte("A"))
	if err := st.Put(realHash, []byte("B")); err == nil {
		t.Fatal("stored bytes that do not hash to the claimed id")
	}
	if st.Has(realHash) {
		t.Fatal("a rejected put still left a file")
	}
}

func TestAvatarStoreRejectsBadInputs(t *testing.T) {
	st := NewAvatarStore(t.TempDir(), avatarKey(t))
	// Not a 64-hex hash.
	if err := st.Put("nothex", []byte("x")); err == nil {
		t.Error("accepted a non-hex hash")
	}
	// Empty.
	if err := st.Put(AvatarHashBytes(nil), nil); err == nil {
		t.Error("accepted empty data")
	}
	// Oversized (just over the cap).
	big := make([]byte, maxAvatarBytes+1)
	if err := st.Put(AvatarHashBytes(big), big); err == nil {
		t.Error("accepted an oversized avatar")
	}
	// Get on a traversal-shaped id must be refused, never touch the FS by that name.
	if _, err := st.Get("../../etc/passwd"); err == nil {
		t.Error("Get accepted a path-traversal id")
	}
}

// Storing identical bytes twice is a no-op success (content-addressed dedup), so
// a contact and my own device converging on the same avatar don't double-store.
func TestAvatarStoreDedup(t *testing.T) {
	st := NewAvatarStore(t.TempDir(), avatarKey(t))
	data := bytes.Repeat([]byte("z"), 100)
	hash := AvatarHashBytes(data)
	if err := st.Put(hash, data); err != nil {
		t.Fatal(err)
	}
	if err := st.Put(hash, data); err != nil {
		t.Fatalf("second identical put failed: %v", err)
	}
}

func TestAvatarHashShape(t *testing.T) {
	h := AvatarHashBytes([]byte("anything"))
	if len(h) != 64 {
		t.Fatalf("hash len = %d, want 64", len(h))
	}
	if strings.ToLower(h) != h {
		t.Fatal("hash is not lowercase hex")
	}
}
