// Package session manages Double Ratchet sessions per peer.
//
// Each (account, device) pair has its own independent session. Sessions are
// persisted in the chatstore and loaded on startup. The manager handles
// session creation via X3DH, message encryption/decryption, and prekey lifecycle.
package session

import (
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/crypto"
)

// --- Prekey lifecycle constants ---

const (
	// DefaultSignedPrekeyRotationInterval is 7 days. Conservative for an
	// asynchronous messenger: long enough to amortize rotation cost, short
	// enough that a compromised prekey limits the damage window.
	DefaultSignedPrekeyRotationInterval = 7 * 24 * time.Hour

	// DefaultSignedPrekeyGracePeriod is 30 days. Covers worst-case async
	// delivery: Tor circuit delays, mailbox storage, offline recipient.
	// After this period, retired private keys are deleted.
	DefaultSignedPrekeyGracePeriod = 30 * 24 * time.Hour

	// DefaultOneTimePrekeyPoolSize is the target number of one-time prekeys
	// to maintain. When the pool falls below this threshold, new prekeys
	// are generated.
	DefaultOneTimePrekeyPoolSize = 100

	// MaxOneTimePrekeyPoolSize caps the pool to prevent DoS-driven generation.
	MaxOneTimePrekeyPoolSize = 200

	// DefaultOneTimePrekeyRefillThreshold triggers refill when unused count
	// drops below this.
	DefaultOneTimePrekeyRefillThreshold = 20
)

// PrekeyConfig holds configurable prekey lifecycle parameters.
type PrekeyConfig struct {
	// SignedPrekeyRotationInterval is how often to rotate the signed prekey.
	SignedPrekeyRotationInterval time.Duration
	// SignedPrekeyGracePeriod is how long to retain retired signed prekeys.
	SignedPrekeyGracePeriod time.Duration
	// OneTimePrekeyPoolSize is the target pool size for one-time prekeys.
	OneTimePrekeyPoolSize int
	// OneTimePrekeyRefillThreshold triggers refill when pool drops below this.
	OneTimePrekeyRefillThreshold int
	// MaxOneTimePrekeyPoolSize caps the pool to prevent DoS.
	MaxOneTimePrekeyPoolSize int
}

// DefaultPrekeyConfig returns the default prekey lifecycle configuration.
func DefaultPrekeyConfig() PrekeyConfig {
	return PrekeyConfig{
		SignedPrekeyRotationInterval:  DefaultSignedPrekeyRotationInterval,
		SignedPrekeyGracePeriod:       DefaultSignedPrekeyGracePeriod,
		OneTimePrekeyPoolSize:         DefaultOneTimePrekeyPoolSize,
		OneTimePrekeyRefillThreshold:  DefaultOneTimePrekeyRefillThreshold,
		MaxOneTimePrekeyPoolSize:      MaxOneTimePrekeyPoolSize,
	}
}

// PrekeyManager handles the lifecycle of signed prekeys and one-time prekeys.
// It generates, rotates, cleans up, and provides prekeys for session establishment.
type PrekeyManager struct {
	mu     sync.Mutex
	config PrekeyConfig

	// Callbacks for persistence — set by the application layer.
	// getSignedPrekeys returns the current and retired signed prekeys.
	getSignedPrekeys func() []chatstore.StoredSignedPrekey
	// getCurrentSignedPrekey returns the active signed prekey.
	getCurrentSignedPrekey func() *chatstore.StoredSignedPrekey
	// addSignedPrekey stores a new signed prekey and retires the old one.
	addSignedPrekey func(sp chatstore.StoredSignedPrekey)
	// deleteExpiredSignedPrekeys removes retired prekeys past their grace period.
	deleteExpiredSignedPrekeys func(gracePeriod time.Duration)
	// getOneTimePrekeys returns the pool of one-time prekeys.
	getOneTimePrekeys func() []chatstore.StoredOneTimePrekey
	// addOneTimePrekeys appends one-time prekeys to the pool.
	addOneTimePrekeys func(prekeys []chatstore.StoredOneTimePrekey)
	// consumeOneTimePrekey marks a prekey as consumed and returns its private key.
	consumeOneTimePrekey func(id uint32) []byte
	// cleanupConsumedOneTimePrekeys removes consumed prekeys from the pool.
	cleanupConsumedOneTimePrekeys func()
	// unusedOneTimePrekeys returns the count of unconsumed one-time prekeys.
	unusedOneTimePrekeys func() int
	// getPrekeyRotationAt returns when the next rotation is due.
	getPrekeyRotationAt func() time.Time
	// setPrekeyRotationAt sets the next rotation time.
	setPrekeyRotationAt func(t time.Time)
	// save persists the current state.
	save func() error
}

// NewPrekeyManager creates a prekey manager with the given configuration and
// persistence callbacks.
func NewPrekeyManager(config PrekeyConfig, callbacks PrekeyCallbacks) *PrekeyManager {
	return &PrekeyManager{
		config:                      config,
		getSignedPrekeys:            callbacks.GetSignedPrekeys,
		getCurrentSignedPrekey:       callbacks.GetCurrentSignedPrekey,
		addSignedPrekey:              callbacks.AddSignedPrekey,
		deleteExpiredSignedPrekeys:   callbacks.DeleteExpiredSignedPrekeys,
		getOneTimePrekeys:            callbacks.GetOneTimePrekeys,
		addOneTimePrekeys:            callbacks.AddOneTimePrekeys,
		consumeOneTimePrekey:         callbacks.ConsumeOneTimePrekey,
		cleanupConsumedOneTimePrekeys: callbacks.CleanupConsumedOneTimePrekeys,
		unusedOneTimePrekeys:         callbacks.UnusedOneTimePrekeys,
		getPrekeyRotationAt:          callbacks.GetPrekeyRotationAt,
		setPrekeyRotationAt:           callbacks.SetPrekeyRotationAt,
		save:                         callbacks.Save,
	}
}

// PrekeyCallbacks groups the persistence callbacks needed by PrekeyManager.
type PrekeyCallbacks struct {
	GetSignedPrekeys            func() []chatstore.StoredSignedPrekey
	GetCurrentSignedPrekey      func() *chatstore.StoredSignedPrekey
	AddSignedPrekey             func(sp chatstore.StoredSignedPrekey)
	DeleteExpiredSignedPrekeys  func(gracePeriod time.Duration)
	GetOneTimePrekeys           func() []chatstore.StoredOneTimePrekey
	AddOneTimePrekeys           func(prekeys []chatstore.StoredOneTimePrekey)
	ConsumeOneTimePrekey        func(id uint32) []byte
	CleanupConsumedOneTimePrekeys func()
	UnusedOneTimePrekeys        func() int
	GetPrekeyRotationAt         func() time.Time
	SetPrekeyRotationAt         func(t time.Time)
	Save                        func() error
}

// GenerateInitialPrekeys generates the initial signed prekey and one-time
// prekey pool for a fresh v2 installation or after account recovery.
// The signing key is the Ed25519 identity key, and identityPub is the
// corresponding public key.
func (pm *PrekeyManager) GenerateInitialPrekeys(
	signingKey ed25519.PrivateKey,
	identityPub ed25519.PublicKey,
) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Generate initial signed prekey
	now := time.Now()
	_, privKey, err := crypto.GenerateSignedPrekey(signingKey, identityPub, 0, now)
	if err != nil {
		return fmt.Errorf("generate signed prekey: %w", err)
	}
	pubKey := x25519PublicKey(privKey)

	ts := now.UnixMilli()
	sigData := signedPrekeySignData(identityPub, 0, pubKey, ts)
	sig := ed25519.Sign(signingKey, sigData)

	storedSP := chatstore.StoredSignedPrekey{
		ID:         0,
		PublicKey:  pubKey[:],
		PrivateKey: privKey,
		Signature:  sig,
		CreatedAt:  now,
		Status:     "current",
	}
	pm.addSignedPrekey(storedSP)

	// Generate initial one-time prekeys
	otps := make([]chatstore.StoredOneTimePrekey, 0, pm.config.OneTimePrekeyPoolSize)
	for i := 0; i < pm.config.OneTimePrekeyPoolSize; i++ {
		otpPriv, err := generateStaticX25519Key()
		if err != nil {
			return fmt.Errorf("generate one-time prekey %d: %w", i, err)
		}
		otpPub := x25519PublicKey(otpPriv)
		otps = append(otps, chatstore.StoredOneTimePrekey{
			PublicKey:  otpPub[:],
			PrivateKey: otpPriv,
			CreatedAt:  now,
		})
	}
	pm.addOneTimePrekeys(otps)

	// Set next rotation time
	pm.setPrekeyRotationAt(now.Add(pm.config.SignedPrekeyRotationInterval))

	return pm.save()
}

// CheckRotation checks if the signed prekey needs rotation and performs it
// if necessary. Should be called periodically (e.g., on app startup or unlock).
func (pm *PrekeyManager) CheckRotation(
	signingKey ed25519.PrivateKey,
	identityPub ed25519.PublicKey,
) (rotated bool, err error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Check if rotation is due
	rotationAt := pm.getPrekeyRotationAt()
	if !rotationAt.IsZero() && time.Now().Before(rotationAt) {
		return false, nil
	}

	// Perform rotation
	return pm.rotateSignedPrekey(signingKey, identityPub)
}

// RotateSignedPrekey forces an immediate rotation. Used for manual rotation
// and emergency key compromise response.
func (pm *PrekeyManager) RotateSignedPrekey(
	signingKey ed25519.PrivateKey,
	identityPub ed25519.PublicKey,
) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	_, err := pm.rotateSignedPrekey(signingKey, identityPub)
	return err
}

// rotateSignedPrekey performs the actual rotation. Caller holds mu.
func (pm *PrekeyManager) rotateSignedPrekey(
	signingKey ed25519.PrivateKey,
	identityPub ed25519.PublicKey,
) (rotated bool, err error) {
	current := pm.getCurrentSignedPrekey()
	var nextID uint32
	if current != nil {
		nextID = current.ID + 1
	}

	now := time.Now()
	privKey, err := generateStaticX25519Key()
	if err != nil {
		return false, fmt.Errorf("generate x25519 key: %w", err)
	}
	pubKey := x25519PublicKey(privKey)

	ts := now.UnixMilli()
	sigData := signedPrekeySignData(identityPub, nextID, pubKey, ts)
	sig := ed25519.Sign(signingKey, sigData)

	storedSP := chatstore.StoredSignedPrekey{
		ID:         nextID,
		PublicKey:  pubKey[:],
		PrivateKey: privKey,
		Signature:  sig,
		CreatedAt:  now,
		Status:     "current",
	}
	pm.addSignedPrekey(storedSP)

	// Set next rotation time
	pm.setPrekeyRotationAt(now.Add(pm.config.SignedPrekeyRotationInterval))

	// Clean up expired retired prekeys
	pm.deleteExpiredSignedPrekeys(pm.config.SignedPrekeyGracePeriod)

	// Save state
	if err := pm.save(); err != nil {
		return false, fmt.Errorf("save after rotation: %w", err)
	}

	return true, nil
}

// RefillOneTimePrekeys generates new one-time prekeys if the pool is below
// the threshold. Should be called periodically.
func (pm *PrekeyManager) RefillOneTimePrekeys() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	unused := pm.unusedOneTimePrekeys()
	if unused >= pm.config.OneTimePrekeyRefillThreshold {
		return nil
	}

	need := pm.config.OneTimePrekeyPoolSize - unused
	if need <= 0 {
		return nil
	}

	// Cap to prevent DoS-driven generation
	available := pm.config.MaxOneTimePrekeyPoolSize - unused
	if need > available {
		need = available
	}
	if need <= 0 {
		return nil
	}

	otps := make([]chatstore.StoredOneTimePrekey, 0, need)
	now := time.Now()
	for i := 0; i < need; i++ {
		privKey, err := generateStaticX25519Key()
		if err != nil {
			return fmt.Errorf("generate one-time prekey: %w", err)
		}
		pubKey := x25519PublicKey(privKey)
		otps = append(otps, chatstore.StoredOneTimePrekey{
			PublicKey:  pubKey[:],
			PrivateKey: privKey,
			CreatedAt:  now,
		})
	}
	pm.addOneTimePrekeys(otps)

	// Clean up consumed prekeys
	pm.cleanupConsumedOneTimePrekeys()

	return pm.save()
}

// ConsumeOneTimePrekey attempts to consume a one-time prekey by ID.
// Returns the private key if found and unconsumed, nil otherwise.
func (pm *PrekeyManager) ConsumeOneTimePrekey(id uint32) []byte {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.consumeOneTimePrekey(id)
}

// CleanupExpiredPrekeys removes retired signed prekeys past their grace period
// and consumed one-time prekeys. Should be called periodically.
func (pm *PrekeyManager) CleanupExpiredPrekeys() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.deleteExpiredSignedPrekeys(pm.config.SignedPrekeyGracePeriod)
	pm.cleanupConsumedOneTimePrekeys()

	return pm.save()
}

// GetPrekeyBundle returns the current signed prekey and an optional one-time
// prekey for inclusion in a prekey bundle response.
func (pm *PrekeyManager) GetPrekeyBundle() (
	signedPrekey *chatstore.StoredSignedPrekey,
	oneTimePrekey *chatstore.StoredOneTimePrekey,
	err error,
) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	sp := pm.getCurrentSignedPrekey()
	if sp == nil {
		return nil, nil, fmt.Errorf("no signed prekey available")
	}

	// Get and consume one-time prekey if available
	otps := pm.getOneTimePrekeys()
	for i := range otps {
		if !otps[i].Consumed {
			pm.consumeOneTimePrekey(otps[i].ID)
			return sp, &otps[i], nil
		}
	}

	return sp, nil, nil
}

// signedPrekeySignData builds the canonical byte sequence for signing a
// prekey. This must match crypto.signedPrekeySignData exactly.
func signedPrekeySignData(identityPub []byte, id uint32, pubKey [32]byte, createdAt int64) []byte {
	return signParts(
		[]byte("Molepipe-Signed-Prekey-v1"),
		identityPub,
		u32Bytes(id),
		pubKey[:],
		i64Bytes(createdAt),
	)
}
