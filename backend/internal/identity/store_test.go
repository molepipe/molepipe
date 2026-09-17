package identity

import (
	"bytes"
	"os"
	"testing"
)

func TestStoreSaveLoadRoundTrip(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pw := []byte("a strong password")

	orig, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(orig, pw); err != nil {
		t.Fatal(err)
	}
	if !store.Exists() {
		t.Fatal("identity file not created")
	}

	loaded, err := store.Load(pw)
	if err != nil {
		t.Fatal(err)
	}
	if orig.AccountNumber() != loaded.AccountNumber() {
		t.Error("account number differs after load")
	}
	if !bytes.Equal(orig.Keys.Signing.Private, loaded.Keys.Signing.Private) {
		t.Error("signing key differs after load")
	}
	if orig.Keys.DH.Private != loaded.Keys.DH.Private {
		t.Error("dh key differs after load")
	}
}

func TestStoreWrongPasswordFails(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	orig, _ := New()
	if err := store.Save(orig, []byte("right password")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load([]byte("wrong password")); err == nil {
		t.Error("load succeeded with wrong password")
	}
}

// The encrypted file must not leak the recovery phrase in cleartext.
func TestStoreFileHasNoPlaintextMnemonic(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	orig, _ := New()
	if err := store.Save(orig, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	firstWord := orig.MnemonicString()[:bytes.IndexByte(orig.Mnemonic, ' ')]
	if bytes.Contains(data, orig.Mnemonic) || bytes.Contains(data, []byte(firstWord)) {
		t.Error("recovery phrase found in cleartext on disk")
	}
}

func TestStoreFilePermissions(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	orig, _ := New()
	if err := store.Save(orig, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("identity file perm = %o, want 600", perm)
	}
}

func TestDefaultDataDirRespectsEnv(t *testing.T) {
	t.Setenv("TORMSG_DATA_DIR", "/tmp/custom-tormsg-dir")
	dir, err := DefaultDataDir()
	if err != nil {
		t.Fatal(err)
	}
	if dir != "/tmp/custom-tormsg-dir" {
		t.Errorf("data dir = %s, want the env override", dir)
	}
}
