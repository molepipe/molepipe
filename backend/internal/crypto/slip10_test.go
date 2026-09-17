package crypto

import (
	"encoding/hex"
	"testing"
)

// Official SLIP-0010 Ed25519 test vectors (Test vector 1).
// Source: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
// Seed: 000102030405060708090a0b0c0d0e0f. The values below are the "private
// key" (the 32-byte leaf material) that DeriveSLIP10Ed25519 returns directly.
func TestSLIP10Ed25519Vector1(t *testing.T) {
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		path    []uint32
		wantKey string
	}{
		{"m", nil, "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"},
		{"m/0'", []uint32{0}, "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"},
		{"m/0'/1'", []uint32{0, 1}, "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2"},
		{"m/0'/1'/2'", []uint32{0, 1, 2}, "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9"},
		{"m/0'/1'/2'/2'", []uint32{0, 1, 2, 2}, "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662"},
		{"m/0'/1'/2'/2'/1000000000'", []uint32{0, 1, 2, 2, 1000000000}, "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793"},
	}

	for _, c := range cases {
		got, err := DeriveSLIP10Ed25519(seed, c.path...)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if gotHex := hex.EncodeToString(got); gotHex != c.wantKey {
			t.Errorf("%s key = %s, want %s", c.name, gotHex, c.wantKey)
		}
	}
}
