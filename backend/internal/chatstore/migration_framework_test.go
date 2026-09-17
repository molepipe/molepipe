package chatstore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/crypto"
)

// These tests cover the commit-2 migration framework: the frozen AAD, the
// version branch in Load (newer → ErrNewerVersion, non-destructively), and the
// fail-closed migrate chain. They are behavior-neutral at v1; the point is to pin
// the properties so a later change can't quietly break them.

// writeStoreEnvelope seals d under goldKey and the FROZEN store AAD, then writes an
// envelope stamping an arbitrary version. It seals under aad() (not the version) on
// purpose — that is exactly what the real Save does and what makes an old file
// decryptable after a bump.
func writeStoreEnvelope(t *testing.T, path string, version int, d *Data) {
	t.Helper()
	pt, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	nonce, ct, err := crypto.Seal(goldKey, pt, aad())
	if err != nil {
		t.Fatal(err)
	}
	env := envelope{
		Version:    version,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	raw, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestStoreAADFrozen pins the exact AAD bytes. This is the load-bearing constant
// behind store migratability: if it ever tracked fileVersion, a bump would make
// every existing messages.enc undecryptable by the migrating build. A change here
// is only safe if it is genuinely never shipped.
func TestStoreAADFrozen(t *testing.T) {
	const want = "onion-chat/v1 local-store"
	if got := string(aad()); got != want {
		t.Fatalf("store AAD drifted: got %q want %q (frozen — must never track fileVersion)", got, want)
	}
}

// TestStoreRejectsNewerVersion: a file stamped newer than this build returns
// ErrNewerVersion, decided BEFORE decryption. Proven by using ciphertext this key
// can't open — a decrypt attempt would surface a GCM error instead, so getting
// ErrNewerVersion shows the version gate runs first.
func TestStoreRejectsNewerVersion(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, fileName)
	env := envelope{
		Version:    fileVersion + 1,
		Nonce:      base64.StdEncoding.EncodeToString(make([]byte, 24)),
		Ciphertext: base64.StdEncoding.EncodeToString([]byte("not real ciphertext")),
	}
	raw, _ := json.MarshalIndent(env, "", "  ")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(tmp, goldKey).Load()
	if !errors.Is(err, ErrNewerVersion) {
		t.Fatalf("newer-version file: want ErrNewerVersion, got %v", err)
	}
}

// TestStoreDowngradeDoesNotOverwrite: loading a newer-version file must leave the
// bytes on disk byte-for-byte unchanged. Load never writes, so this is a
// regression guard against a future "recover by resaving" reflex on the read path.
func TestStoreDowngradeDoesNotOverwrite(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, fileName)
	writeStoreEnvelope(t, path, fileVersion+1, goldData())
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(tmp, goldKey).Load(); !errors.Is(err, ErrNewerVersion) {
		t.Fatalf("want ErrNewerVersion, got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("Load overwrote a newer-version file — downgrade must be non-destructive")
	}
}

// TestStoreMigrateFailsClosed is the sharp one for chatstore specifically. Because
// the AAD is frozen, a corrupt-to-lower version DECRYPTS cleanly — so without a
// fail-closed default the plaintext would load as if current. Here a valid, fully
// decryptable payload stamped version 0 must be REJECTED, not silently accepted.
func TestStoreMigrateFailsClosed(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, fileName)
	writeStoreEnvelope(t, path, 0, goldData()) // decryptable (frozen AAD), but version 0
	_, err := New(tmp, goldKey).Load()
	if err == nil {
		t.Fatal("version-0 store loaded — an unknown lower version must fail closed, not load as current")
	}
	if errors.Is(err, ErrNewerVersion) {
		t.Fatalf("version 0 is not newer; want a migration error, got %v", err)
	}
	// The payload decrypts cleanly under the frozen AAD, so a bare "err != nil" would
	// also pass on a decrypt regression. Pin that the MIGRATION default is what fired.
	if !strings.Contains(err.Error(), "no store migration") {
		t.Fatalf("want the fail-closed migration error, got %v", err)
	}
}
