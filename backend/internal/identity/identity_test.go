package identity

import (
	"bytes"
	"strings"
	"testing"
)

func TestRecoveryReproducesIdentity(t *testing.T) {
	orig, err := New()
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := FromMnemonic(orig.MnemonicString(), orig.PassphraseString())
	if err != nil {
		t.Fatal(err)
	}
	if orig.AccountNumber() != recovered.AccountNumber() {
		t.Error("account number changed after recovery")
	}
	if !bytes.Equal(orig.Keys.Signing.Private, recovered.Keys.Signing.Private) {
		t.Error("signing key changed after recovery")
	}
	if orig.Keys.DH.Private != recovered.Keys.DH.Private {
		t.Error("dh key changed after recovery")
	}
}

func TestAccountNumberRoundTrip(t *testing.T) {
	id, err := New()
	if err != nil {
		t.Fatal(err)
	}
	acct := id.AccountNumber()

	// Onion v3 addresses are 56 base32 chars (35 bytes → 56 chars).
	if len(acct) != 56 {
		t.Errorf("account number length = %d, want 56", len(acct))
	}
	if strings.ToLower(acct) != acct {
		t.Error("account number is not lowercase")
	}

	pub, err := AccountNumberFromString(acct)
	if err != nil {
		t.Fatalf("failed to parse own account number: %v", err)
	}
	if !pub.Equal(id.Keys.Signing.Public) {
		t.Error("parsed public key does not match")
	}

	// Also accept the ".onion" form.
	if _, err := AccountNumberFromString(id.OnionAddress()); err != nil {
		t.Errorf("failed to parse onion address form: %v", err)
	}
}

func TestAccountNumberRejectsCorruption(t *testing.T) {
	id, err := New()
	if err != nil {
		t.Fatal(err)
	}
	acct := []byte(id.AccountNumber())
	// Flip a character in the key region.
	if acct[0] == 'a' {
		acct[0] = 'b'
	} else {
		acct[0] = 'a'
	}
	if _, err := AccountNumberFromString(string(acct)); err == nil {
		t.Error("corrupted account number passed checksum")
	}
}

// Conformance to Tor's real v3 onion format, not just self-consistency.
// A genuine published v3 .onion is base32(PUBKEY‖CHECKSUM‖0x03) with a correct
// SHA3-256 checksum. If our parser validates its checksum, our hash choice,
// byte order, and base32 handling all match Tor's spec — a wrong construction
// would fail the 16-bit checksum with ~99.998% probability. This is what backs
// the claim that an account number doubles as a v3 onion address in Phase 3.
func TestConformsToRealV3OnionAddress(t *testing.T) {
	// The Tor Project's official onion service.
	const torProject = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"

	pub, err := AccountNumberFromString(torProject)
	if err != nil {
		t.Fatalf("real v3 onion rejected — our v3 construction does not match Tor: %v", err)
	}

	// Re-encoding the recovered public key must reproduce the exact address,
	// proving the full construction (order, checksum, base32, case) is correct.
	got := accountNumber(pub) + ".onion"
	if got != torProject {
		t.Errorf("re-encode mismatch:\n got  %s\n want %s", got, torProject)
	}
}

func TestDistinctIdentitiesDiffer(t *testing.T) {
	a, _ := New()
	b, _ := New()
	if a.AccountNumber() == b.AccountNumber() {
		t.Error("two fresh identities share an account number")
	}
}
