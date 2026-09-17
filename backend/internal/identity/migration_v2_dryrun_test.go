package identity

import (
	"strings"
	"testing"
)

// Commit-3 dry-run for identity: a durable proof that the reserved v1->v2 identity
// migration is wired and preserves the account, exercised while envelopeVersion
// stays 1 (so production never reaches v2). Mirrors chatstore's dry-run and
// protocol's version_crossver_test — the migrate ceiling is a parameter, so the
// test drives it to 2 through migrateSealed while Load stays capped at
// envelopeVersion.
//
// The identity payload is only the mnemonic + optional passphrase — the irreducible
// root of the account — so a v1->v2 bump is a pure format re-stamp with nothing to
// reshape. The meaningful surface to prove is therefore: the step EXISTS (reaching
// v2 returns nil rather than the fail-closed default), and the secret survives
// untouched so the same keys re-derive.

// TestIdentityMigrateV1ToV2Preserves drives the reserved step and asserts the
// mnemonic and passphrase are byte-identical afterwards, and that the re-derived
// account number is unchanged — the only proof that matters for a payload whose
// whole purpose is to reconstruct keys.
func TestIdentityMigrateV1ToV2Preserves(t *testing.T) {
	orig := sealed{Mnemonic: []byte(fixtureMnemonic), Passphrase: []byte("a passphrase")}
	s := orig
	if err := migrateSealed(1, 2, &s); err != nil {
		t.Fatalf("reserved v1->v2 identity migration must exist and succeed: %v", err)
	}
	if string(s.Mnemonic) != string(orig.Mnemonic) || string(s.Passphrase) != string(orig.Passphrase) {
		t.Fatalf("identity migration corrupted the secret payload: got %+v want %+v", s, orig)
	}
	// Keys re-derive identically — the account number is the stable fingerprint.
	before, err := FromMnemonic(string(orig.Mnemonic), string(orig.Passphrase))
	if err != nil {
		t.Fatal(err)
	}
	after, err := FromMnemonic(string(s.Mnemonic), string(s.Passphrase))
	if err != nil {
		t.Fatal(err)
	}
	if before.AccountNumber() != after.AccountNumber() {
		t.Fatalf("account number drifted across migration: %s -> %s", before.AccountNumber(), after.AccountNumber())
	}
}

// TestIdentityMigrateChainStillFailsClosed guards that raising the ceiling did not
// weaken the fail-closed default: a from-version with no step (0) must still error,
// and the error must be the migration default, not an arity accident.
func TestIdentityMigrateChainStillFailsClosed(t *testing.T) {
	s := sealed{Mnemonic: []byte(fixtureMnemonic)}
	err := migrateSealed(0, 2, &s)
	if err == nil {
		t.Fatal("version-0 payload migrated cleanly — an unknown lower version must fail closed")
	}
	if !strings.Contains(err.Error(), "no identity migration") {
		t.Fatalf("want the fail-closed migration error, got %v", err)
	}
}
