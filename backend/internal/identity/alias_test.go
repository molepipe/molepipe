package identity

import (
	"strings"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/crypto"
)

// The alias account must be a well-formed onion-style account number, distinct
// from the durable AccountNumber (m/0'/0'), and stable across recovery.
func TestAliasAccountShape(t *testing.T) {
	id, err := New()
	if err != nil {
		t.Fatal(err)
	}
	alias, err := id.AliasAccount(0)
	if err != nil {
		t.Fatal(err)
	}
	// Same 56-char lowercase base32 shape as any account number, and it must
	// round-trip through the validator.
	if len(alias) != 56 {
		t.Errorf("alias account length = %d, want 56", len(alias))
	}
	if strings.ToLower(alias) != alias {
		t.Errorf("alias account not lowercase: %q", alias)
	}
	if _, err := AccountNumberFromString(alias); err != nil {
		t.Errorf("alias account fails validation: %v", err)
	}
	// The alias must NOT equal the durable account — that is the whole point of
	// rotation (friends never learn the real m/0'/0' onion).
	if alias == id.AccountNumber() {
		t.Error("alias 0 equals the durable account number — real onion leaked")
	}
}

// Distinct alias indices give distinct accounts; recovery reproduces each.
func TestAliasAccountDeterministicAndDistinct(t *testing.T) {
	id, err := New()
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := FromMnemonic(id.MnemonicString(), id.PassphraseString())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]uint32{}
	for i := uint32(0); i < 5; i++ {
		a, err := id.AliasAccount(i)
		if err != nil {
			t.Fatal(err)
		}
		b, err := recovered.AliasAccount(i)
		if err != nil {
			t.Fatal(err)
		}
		if a != b {
			t.Errorf("alias %d not reproduced after recovery: %q vs %q", i, a, b)
		}
		if prev, ok := seen[a]; ok {
			t.Errorf("alias %d collides with alias %d", i, prev)
		}
		seen[a] = i
	}
}

// AliasSigningKey's public key must encode to the same string AliasAccount
// returns — the plumbing and the key agree on which onion the alias is.
func TestAliasSigningKeyMatchesAccount(t *testing.T) {
	id, err := New()
	if err != nil {
		t.Fatal(err)
	}
	kp, err := id.AliasSigningKey(2)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.Zero(kp.Private)
	acct, err := id.AliasAccount(2)
	if err != nil {
		t.Fatal(err)
	}
	if AccountNumberForPub(kp.Public) != acct {
		t.Error("AliasSigningKey public key and AliasAccount disagree")
	}
}
