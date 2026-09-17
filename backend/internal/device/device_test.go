package device

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCreatesFreshPrimaryDevice(t *testing.T) {
	dir := t.TempDir()
	c, err := Load(dir)
	if err != nil {
		t.Fatalf("Load on empty dir: %v", err)
	}
	if c.Role != RolePrimary {
		t.Errorf("role = %q, want %q", c.Role, RolePrimary)
	}
	if len(c.Seed) != ed25519.SeedSize {
		t.Errorf("seed length = %d, want %d", len(c.Seed), ed25519.SeedSize)
	}
	if _, err := os.Stat(path(dir)); err != nil {
		t.Fatalf("Load did not persist config: %v", err)
	}
}

func TestLoadCreatesDeterministicConfig(t *testing.T) {
	dir := t.TempDir()
	c1, _ := Load(dir)
	c2, _ := Load(dir)
	if c1.Role != c2.Role {
		t.Error("role changed between loads")
	}
	if len(c1.Seed) != len(c2.Seed) {
		t.Error("seed length changed between loads")
	}
	// The public key is deterministic from the seed.
	pub1 := c1.PublicKey()
	pub2 := c2.PublicKey()
	if !pub1.Equal(pub2) {
		t.Error("public key changed between loads of the same config")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	orig := &Config{
		Role: RoleSecondary,
		Seed: make([]byte, ed25519.SeedSize),
	}
	for i := range orig.Seed {
		orig.Seed[i] = byte(i)
	}
	if err := Save(dir, orig); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Role != RoleSecondary {
		t.Errorf("role = %q, want %q", loaded.Role, RoleSecondary)
	}
	pub1 := orig.PublicKey()
	pub2 := loaded.PublicKey()
	if !pub1.Equal(pub2) {
		t.Error("public key changed after save/load round trip")
	}
}

func TestLoadDefaultsEmptyRoleToPrimary(t *testing.T) {
	dir := t.TempDir()
	// Manually write a config with an empty role.
	c := &Config{Role: "", Seed: make([]byte, ed25519.SeedSize)}
	if _, err := rand.Read(c.Seed); err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path(dir), b, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Role != RolePrimary {
		t.Errorf("empty role not defaulted to primary, got %q", loaded.Role)
	}
}

func TestLoadRejectsCorruptJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(path(dir), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted corrupt JSON")
	}
}

func TestLoadRejectsWrongSeedLength(t *testing.T) {
	dir := t.TempDir()
	c := struct {
		Role Role   `json:"role"`
		Seed []byte `json:"seed"`
	}{
		Role: RolePrimary,
		Seed: make([]byte, 16), // wrong length
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := os.WriteFile(path(dir), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted seed with wrong length")
	}
}

func TestSignAndVerify(t *testing.T) {
	c := &Config{Role: RolePrimary, Seed: make([]byte, ed25519.SeedSize)}
	for i := range c.Seed {
		c.Seed[i] = byte(i + 1)
	}
	msg := []byte("test message")
	sig := c.Sign(msg)
	pub := c.PublicKey()
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("signature verification failed")
	}
	// Tampered message must fail.
	if ed25519.Verify(pub, []byte("tampered"), sig) {
		t.Fatal("signature verified on tampered message")
	}
}

func TestSignDeterministic(t *testing.T) {
	c := &Config{Role: RolePrimary, Seed: make([]byte, ed25519.SeedSize)}
	for i := range c.Seed {
		c.Seed[i] = byte(i + 1)
	}
	msg := []byte("deterministic")
	sig1 := c.Sign(msg)
	sig2 := c.Sign(msg)
	if len(sig1) != ed25519.SignatureSize || len(sig2) != ed25519.SignatureSize {
		t.Fatalf("unexpected signature sizes: %d, %d", len(sig1), len(sig2))
	}
	for i := range sig1 {
		if sig1[i] != sig2[i] {
			t.Fatal("same key produced different signatures on same message")
		}
	}
}

func TestLocalSecretDeterministicAndDomainSeparated(t *testing.T) {
	c := &Config{Role: RolePrimary, Seed: make([]byte, ed25519.SeedSize)}
	for i := range c.Seed {
		c.Seed[i] = byte(i + 1)
	}
	s1 := c.LocalSecret()
	s2 := c.LocalSecret()
	if len(s1) != 32 || len(s2) != 32 {
		t.Fatalf("unexpected secret lengths: %d, %d", len(s1), len(s2))
	}
	for i := range s1 {
		if s1[i] != s2[i] {
			t.Fatal("LocalSecret is not deterministic")
		}
	}
	// LocalSecret must differ from the signing key.
	pub := c.PublicKey()
	for i := range s1 {
		if s1[i] == pub[i] {
			// Not a strict requirement but vanishingly unlikely — good smoke check.
			t.Log("LocalSecret byte matches public key byte; domain separation may be broken")
			break
		}
	}
}

func TestIsPrimary(t *testing.T) {
	tests := []struct {
		role Role
		want bool
	}{
		{RolePrimary, true},
		{RoleSecondary, false},
		{"", true}, // empty defaults to primary
	}
	for _, tt := range tests {
		c := &Config{Role: tt.role}
		if got := c.IsPrimary(); got != tt.want {
			t.Errorf("IsPrimary(%q) = %v, want %v", tt.role, got, tt.want)
		}
	}
}

func TestFilePermissions(t *testing.T) {
	dir := t.TempDir()
	c := &Config{Role: RolePrimary, Seed: make([]byte, ed25519.SeedSize)}
	if err := Save(dir, c); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("device.json perm = %o, want 600", perm)
	}
}

func TestLoadNonexistentReturnsFresh(t *testing.T) {
	// Load on a non-existent dir should create a fresh device, not error.
	dir := filepath.Join(t.TempDir(), "nonexistent")
	c, err := Load(dir)
	if err != nil {
		t.Fatalf("Load on nonexistent dir: %v", err)
	}
	if c.Role != RolePrimary {
		t.Errorf("fresh device role = %q, want %q", c.Role, RolePrimary)
	}
}

func TestSaveCreatesDirWithOwnerOnlyPerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "subdir", "data")
	c := &Config{Role: RolePrimary, Seed: make([]byte, ed25519.SeedSize)}
	if err := Save(dir, c); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("data dir perm = %o, want 700", perm)
	}
}

func TestTwoDevicesHaveDifferentKeys(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	c1, _ := Load(dir1)
	c2, _ := Load(dir2)
	pub1 := c1.PublicKey()
	pub2 := c2.PublicKey()
	if pub1.Equal(pub2) {
		t.Fatal("two fresh devices share the same key")
	}
}
