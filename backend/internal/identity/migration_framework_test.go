package identity

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

// Commit-2 migration framework for identity: aad(v) parameterization (byte-identical
// at v1), the ErrNewerVersion branch, openEnvelope binding the AAD to env.Version,
// and the fail-closed migrate chain.

// sealIdentityUnder builds an identity envelope whose ciphertext is sealed under
// aad(aadVersion) and whose Version field is stampVersion — decoupled so a test can
// prove openEnvelope keys the AAD off the field, not a constant.
func sealIdentityUnder(t *testing.T, aadVersion, stampVersion int, password []byte) envelope {
	t.Helper()
	salt, err := crypto.NewSalt(weakParams)
	if err != nil {
		t.Fatal(err)
	}
	key := crypto.DeriveKeyArgon2id(password, salt, weakParams)
	pt, err := json.Marshal(sealed{Mnemonic: []byte(fixtureMnemonic)})
	if err != nil {
		t.Fatal(err)
	}
	nonce, ct, err := crypto.Seal(key, pt, aad(aadVersion))
	if err != nil {
		t.Fatal(err)
	}
	return envelope{
		Version:    stampVersion,
		KDF:        "argon2id",
		Argon2:     weakParams,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
}

// TestIdentityAADByteIdentityAtV1 pins that aad(1) is byte-for-byte the string the
// pre-parameterization hardcoded form produced. If this drifts, every existing
// identity.enc becomes undecryptable. Also confirms the domain genuinely varies by
// version, so the parameter isn't cosmetic.
func TestIdentityAADByteIdentityAtV1(t *testing.T) {
	if got := string(aad(1)); got != "tormsg-identity-v1" {
		t.Fatalf("aad(1) drifted: got %q want %q", got, "tormsg-identity-v1")
	}
	if string(aad(2)) == string(aad(1)) {
		t.Fatal("aad(2) must differ from aad(1) — the AAD has to move with the version")
	}
}

// TestOpenEnvelopeBindsAADToVersion is the guard for the actual bug fix. openEnvelope
// must decrypt under aad(env.Version), NOT aad(envelopeVersion). Bytes sealed under
// aad(1) open when the envelope says version 1; the SAME bytes, restamped version 2,
// must fail — because openEnvelope now tries aad(2). If someone reverted to
// aad(envelopeVersion), the restamped case would wrongly succeed and this fails.
func TestOpenEnvelopeBindsAADToVersion(t *testing.T) {
	password := []byte("aad-binding-pw")
	env := sealIdentityUnder(t, 1, 1, password) // sealed under aad(1), stamped v1
	if _, err := openEnvelope(env, password); err != nil {
		t.Fatalf("v1 envelope sealed under aad(1) should open: %v", err)
	}
	env.Version = 2 // same ciphertext, now claims v2
	if _, err := openEnvelope(env, password); err == nil {
		t.Fatal("restamped-v2 envelope opened under aad(1) — openEnvelope must key AAD off env.Version")
	}
}

// TestIdentityRejectsNewerVersion: a newer-stamped identity file returns
// ErrNewerVersion before any KDF/decryption work.
func TestIdentityRejectsNewerVersion(t *testing.T) {
	dir := t.TempDir()
	password := []byte("newer-version-pw")
	env := sealIdentityUnder(t, envelopeVersion, envelopeVersion+1, password)
	raw, _ := json.MarshalIndent(env, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, identityFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(password); !errors.Is(err, ErrNewerVersion) {
		t.Fatalf("newer-version identity: want ErrNewerVersion, got %v", err)
	}
}

// TestIdentityMigrateFailsClosed: a fully decryptable but version-0 identity must be
// rejected, not loaded. To reach migrateSealed the payload must first decrypt, so it
// is sealed under aad(0) and stamped 0 — openEnvelope opens it, then migrateSealed
// has no step for version 0 and errors.
func TestIdentityMigrateFailsClosed(t *testing.T) {
	dir := t.TempDir()
	password := []byte("fail-closed-pw")
	env := sealIdentityUnder(t, 0, 0, password) // sealed under aad(0), stamped 0
	raw, _ := json.MarshalIndent(env, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, identityFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.Load(password)
	if err == nil {
		t.Fatal("version-0 identity loaded — an unknown lower version must fail closed")
	}
	if errors.Is(err, ErrNewerVersion) {
		t.Fatalf("version 0 is not newer; want a migration error, got %v", err)
	}
	// Assert the MIGRATION default fired, not merely that Load errored. The payload
	// decrypts (sealed under aad(0), stamped 0), so a decrypt failure here would be a
	// regression that this test must not silently accept as "fails closed".
	if !strings.Contains(err.Error(), "no identity migration") {
		t.Fatalf("want the fail-closed migration error, got %v", err)
	}
}
