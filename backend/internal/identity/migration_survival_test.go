package identity

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/crypto"
)

// Upgrade-survival test for identity.enc / duress.enc (beta blocker #4). Unlike
// chatstore's frozen-bytes fixture, this GENERATES the fixture at test time with
// deliberately weak Argon2 params. Two reasons: (1) real params cost 64 MiB /
// 3 iterations — too heavy to pay every run for a format this simple; (2) baking
// weak params into the envelope and still opening it proves the resilience
// property that makes an identity upgrade safe at all — Load derives the key from
// env.Argon2, NOT from DefaultArgon2Params. If it ever used the current default,
// this test's Load would derive the wrong key and GCM would fail, so a green load
// IS the proof.

// weakParams: cheap KDF, written into the envelope. Legitimate precisely because
// Load reads env.Argon2 and reproduces whatever was stored.
var weakParams = crypto.Argon2Params{TimeCost: 1, MemoryKiB: 8, Threads: 1, SaltLength: 16, KeyLength: 32}

// canonical all-zero BIP39 mnemonic (also used in pin_test); synthetic, not a key.
const fixtureMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// writeIdentityFixture builds and writes an identity.enc-format envelope directly,
// bypassing Save so it can inject weak params. White-box: it uses the package's own
// envelope/sealed/aad, so the bytes are format-identical to what Save produces —
// only the Argon2 cost differs, which is exactly the axis under test.
func writeIdentityFixture(t *testing.T, dir, name, mnemonic, passphrase string, password []byte) {
	t.Helper()
	salt, err := crypto.NewSalt(weakParams)
	if err != nil {
		t.Fatal(err)
	}
	key := crypto.DeriveKeyArgon2id(password, salt, weakParams)
	pt, err := json.Marshal(sealed{Mnemonic: []byte(mnemonic), Passphrase: []byte(passphrase)})
	if err != nil {
		t.Fatal(err)
	}
	nonce, ct, err := crypto.Seal(key, pt, aad(envelopeVersion))
	if err != nil {
		t.Fatal(err)
	}
	env := envelope{
		Version:    envelopeVersion,
		KDF:        "argon2id",
		Argon2:     weakParams,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestIdentityFixtureSurvives: a build opens an identity.enc written earlier (here,
// with weak params), recovering the mnemonic and re-deriving the same keys. This is
// the identity half of the #4 gate: an upgrade must never leave a user unable to
// unlock (the backstop is seed re-entry, but that must remain the exception).
func TestIdentityFixtureSurvives(t *testing.T) {
	dir := t.TempDir()
	password := []byte("survival-test-password")
	writeIdentityFixture(t, dir, identityFile, fixtureMnemonic, "", password)

	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.Load(password)
	if err != nil {
		t.Fatalf("this build failed to LOAD an identity.enc — upgrade would lock the user out: %v", err)
	}
	if string(id.Mnemonic) != fixtureMnemonic {
		t.Errorf("mnemonic did not survive load: got %q", id.MnemonicString())
	}
	// Keys are re-derived from the mnemonic; the account number is the stable proof
	// that derivation reproduced the same key material.
	want, err := FromMnemonic(fixtureMnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	if id.AccountNumber() != want.AccountNumber() {
		t.Errorf("account number drifted after load: got %s want %s", id.AccountNumber(), want.AccountNumber())
	}
	// Sanity: authentication is intact — a wrong password must still fail, so the
	// weak-params fixture hasn't accidentally disabled the check.
	if _, err := st.Load([]byte("wrong-password")); err == nil {
		t.Error("Load accepted a wrong password")
	}
}

// TestDuressFilenameSurvives covers duress.enc, which is byte-identical in format
// (it goes through NewStoreFile — the same envelope code, a different filename). The
// filename is hardcoded rather than imported from internal/duress to avoid an import
// cycle (duress imports identity).
func TestDuressFilenameSurvives(t *testing.T) {
	dir := t.TempDir()
	password := []byte("decoy-password")
	writeIdentityFixture(t, dir, "duress.enc", fixtureMnemonic, "", password)

	st, err := NewStoreFile(dir, "duress.enc")
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.Load(password)
	if err != nil {
		t.Fatalf("this build failed to load a duress.enc: %v", err)
	}
	if string(id.Mnemonic) != fixtureMnemonic {
		t.Errorf("duress mnemonic did not survive load: got %q", id.MnemonicString())
	}
}
