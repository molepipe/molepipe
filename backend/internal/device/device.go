// Package device holds this installation's LOCAL, per-device state: a random
// device keypair and the device's role. It is deliberately NOT part of the
// synced chatstore — role is device-specific, and the device private key must
// never leave the machine (it's the "this specific enrolled device" factor that,
// combined with the identity key, authorizes multi-device sync).
package device

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/hkdf"
)

const fileName = "device.json"

// Role determines whether this device publishes the account onion service.
type Role string

const (
	// RolePrimary publishes the account onion and receives directly. Exactly one
	// device per identity may be primary (two would collide on the same .onion).
	RolePrimary Role = "primary"
	// RoleSecondary does not publish; it sends outbound and syncs from the primary.
	RoleSecondary Role = "secondary"
)

// Config is the on-disk per-device state.
type Config struct {
	Role Role   `json:"role"`
	Seed []byte `json:"seed"` // Ed25519 device-key seed — a local secret, never synced
}

func (c *Config) private() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(c.Seed) }

// PublicKey is this device's Ed25519 public key (the value that gets enrolled).
func (c *Config) PublicKey() ed25519.PublicKey {
	return c.private().Public().(ed25519.PublicKey)
}

// Sign signs msg with the device key.
func (c *Config) Sign(msg []byte) []byte { return ed25519.Sign(c.private(), msg) }

// LocalSecret derives a 32-byte secret for encrypting device-local data (the
// PIN shortcut). It is domain-separated from the signing use of the same seed
// so the two purposes can never influence each other, and it never leaves this
// machine — anything bound to it is inert if copied elsewhere on its own.
func (c *Config) LocalSecret() []byte {
	out := make([]byte, 32)
	r := hkdf.New(sha256.New, c.Seed, nil, []byte("onion-chat/v1 device local secret"))
	_, _ = io.ReadFull(r, out)
	return out
}

// IsPrimary reports whether this device should publish the onion service.
func (c *Config) IsPrimary() bool { return c.Role != RoleSecondary }

func path(dir string) string { return filepath.Join(dir, fileName) }

// Load reads the device config, creating a fresh primary device (random key) on
// first run so existing single-device installs keep their exact behavior.
func Load(dir string) (*Config, error) {
	b, err := os.ReadFile(path(dir))
	if os.IsNotExist(err) {
		c := &Config{Role: RolePrimary, Seed: make([]byte, ed25519.SeedSize)}
		if _, err := rand.Read(c.Seed); err != nil {
			return nil, err
		}
		if err := Save(dir, c); err != nil {
			return nil, err
		}
		return c, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read device config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse device config: %w", err)
	}
	if len(c.Seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("device config: bad key seed length %d", len(c.Seed))
	}
	if c.Role == "" {
		c.Role = RolePrimary
	}
	return &c, nil
}

// Save writes the device config atomically with owner-only permissions.
func Save(dir string, c *Config) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path(dir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path(dir))
}
