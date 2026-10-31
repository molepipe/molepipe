// Package session manages Double Ratchet sessions per peer.
//
// Each (account, device) pair has its own independent session. Sessions are
// persisted in the chatstore and loaded on startup. The manager handles
// session creation via X3DH, message encryption/decryption, and prekey lifecycle.
package session

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/molepipe/molepipe/backend/internal/crypto"
)

// SessionState is the persisted ratchet state for a single peer session.
// It wraps the crypto.RatchetSession with metadata needed for persistence
// and multi-device operation.
type SessionState struct {
	// PeerAccount is the remote peer's account number.
	PeerAccount string `json:"peer_account"`
	// DeviceID identifies the remote device (empty for single-device peers).
	DeviceID string `json:"device_id,omitempty"`
	// Protocol version used for this session.
	ProtocolVersion uint16 `json:"protocol_version"`

	// Ratchet state
	RootKey          [32]byte `json:"root_key"`
	SendingChain     [32]byte `json:"sending_chain"`
	ReceivingChain   [32]byte `json:"receiving_chain"`
	LocalRatchetPriv [32]byte `json:"local_ratchet_priv"`
	LocalRatchetPub  [32]byte `json:"local_ratchet_pub"`
	RemoteRatchetPub [32]byte `json:"remote_ratchet_pub"`
	SendCounter      uint32   `json:"send_counter"`
	RecvCounter      uint32   `json:"recv_counter"`
	PrevSendCount    uint32   `json:"prev_send_count"`
	// SessionID pins the two sides to one handshake; it rides the wire header and
	// is part of a message key's identity. Dropping it on the persistence round-
	// trip (the 5f bug) silently forked a reloaded session from its live self.
	SessionID []byte `json:"session_id,omitempty"`
	// Established records whether the (responder) session has a sending chain yet,
	// so a reload before the first reply doesn't wrongly think it can encrypt.
	Established bool `json:"established"`

	// Skipped message keys for out-of-order delivery.
	SkippedKeys []SkippedKeyEntry `json:"skipped_keys,omitempty"`

	// Session lifecycle
	CreatedAt   time.Time `json:"created_at"`
	LastUsedAt  time.Time `json:"last_used_at"`
	EstablishedVia string `json:"established_via"` // "x3dh", "prekey-bundle", "v1-fallback"
}

// SkippedKeyEntry is a persisted skipped message key.
type SkippedKeyEntry struct {
	RatchetPub [32]byte `json:"ratchet_pub"`
	MsgNum     uint32   `json:"msg_num"`
	Key        [32]byte `json:"key"`
}

// SessionKey uniquely identifies a session: peer account + device ID.
type SessionKey struct {
	Account  string
	DeviceID string
}

// Manager handles ratchet sessions for all peers. It is thread-safe and
// persists session state through the provided persistence functions.
type Manager struct {
	mu       sync.RWMutex
	sessions map[SessionKey]*crypto.RatchetSession
	states   map[SessionKey]*SessionState

	// Persistence callbacks — set by the application layer.
	saveState func(key SessionKey, state *SessionState) error
	loadState func(key SessionKey) (*SessionState, error)
	deleteState func(key SessionKey) error
}

// NewManager creates a session manager with the given persistence functions.
func NewManager(
	saveFunc func(SessionKey, *SessionState) error,
	loadFunc func(SessionKey) (*SessionState, error),
	deleteFunc func(SessionKey) error,
) *Manager {
	return &Manager{
		sessions:   make(map[SessionKey]*crypto.RatchetSession),
		states:     make(map[SessionKey]*SessionState),
		saveState:  saveFunc,
		loadState:  loadFunc,
		deleteState: deleteFunc,
	}
}

// SessionKeyFor creates a session key from account and device ID.
func SessionKeyFor(account, deviceID string) SessionKey {
	return SessionKey{Account: account, DeviceID: deviceID}
}

// GetOrCreateSession returns an existing session or creates a new one.
// For new sessions, use EstablishSession or EstablishSessionFromBundle instead.
func (m *Manager) GetOrCreateSession(key SessionKey, rootSecret []byte, bobStaticPub, bobStaticPriv [32]byte) (*crypto.RatchetSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.sessions[key]; ok {
		return s, nil
	}

	// Try loading from persistence
	if m.loadState != nil {
		state, err := m.loadState(key)
		if err == nil && state != nil {
			s := stateToSession(state)
			m.sessions[key] = s
			m.states[key] = state
			return s, nil
		}
	}

	// Create new initiator session
	s, err := crypto.NewRatchetSession(rootSecret, generateSessionID(), true, bobStaticPub, bobStaticPriv)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	state := &SessionState{
		PeerAccount:      key.Account,
		DeviceID:         key.DeviceID,
		ProtocolVersion:  2,
		CreatedAt:        time.Now(),
		LastUsedAt:       time.Now(),
		EstablishedVia:   "x3dh",
	}
	copy(state.RootKey[:], rootSecret)
	copy(state.LocalRatchetPriv[:], s.LocalRatchetPriv[:])
	state.LocalRatchetPub = s.LocalRatchetPub

	m.sessions[key] = s
	m.states[key] = state

	return s, nil
}

// GetResponderSession creates a responder session for an incoming X3DH handshake.
func (m *Manager) GetResponderSession(key SessionKey, rootSecret []byte, bobStaticPub, bobStaticPriv [32]byte) (*crypto.RatchetSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.sessions[key]; ok {
		return s, nil
	}

	// Try loading from persistence
	if m.loadState != nil {
		state, err := m.loadState(key)
		if err == nil && state != nil {
			s := stateToSession(state)
			m.sessions[key] = s
			m.states[key] = state
			return s, nil
		}
	}

	// Create new responder session
	s, err := crypto.NewRatchetSession(rootSecret, generateSessionID(), false, bobStaticPub, bobStaticPriv)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	state := &SessionState{
		PeerAccount:      key.Account,
		DeviceID:         key.DeviceID,
		ProtocolVersion:  2,
		CreatedAt:        time.Now(),
		LastUsedAt:       time.Now(),
		EstablishedVia:   "x3dh",
	}
	copy(state.RootKey[:], rootSecret)
	copy(state.LocalRatchetPriv[:], s.LocalRatchetPriv[:])
	state.LocalRatchetPub = s.LocalRatchetPub

	m.sessions[key] = s
	m.states[key] = state

	return s, nil
}

// GetSession returns an in-memory session without creating or loading one.
func (m *Manager) GetSession(key SessionKey) (*crypto.RatchetSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[key]
	return s, ok
}

// GetOrLoadSession returns a live session, loading it from persistence if it is
// not already in memory, but NEVER creating a new one. It is the lookup the
// established-message receive path uses: a v2 message on an already-established
// session must find that session (in memory or on disk after a restart), and if
// there is none the message is undecryptable — the peer should have sent an
// initial (X3DH) envelope instead.
func (m *Manager) GetOrLoadSession(key SessionKey) (*crypto.RatchetSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[key]; ok {
		return s, true
	}
	if m.loadState != nil {
		state, err := m.loadState(key)
		if err == nil && state != nil {
			s := stateToSession(state)
			m.sessions[key] = s
			m.states[key] = state
			return s, true
		}
	}
	return nil, false
}

// SaveSession persists the current session state to storage.
func (m *Manager) SaveSession(key SessionKey) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, ok := m.sessions[key]
	if !ok {
		return fmt.Errorf("session not found for %s", key.Account)
	}
	state, ok := m.states[key]
	if !ok {
		return fmt.Errorf("session state not found for %s", key.Account)
	}

	// Sync state from live session
	sessionToState(s, state)
	state.LastUsedAt = time.Now()

	if m.saveState != nil {
		return m.saveState(key, state)
	}
	return nil
}

// SaveAll persists all active sessions.
func (m *Manager) SaveAll() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for key := range m.sessions {
		s := m.sessions[key]
		state := m.states[key]
		sessionToState(s, state)
		state.LastUsedAt = time.Now()

		if m.saveState != nil {
			if err := m.saveState(key, state); err != nil {
				return fmt.Errorf("save session for %s: %w", key.Account, err)
			}
		}
	}
	return nil
}

// DeleteSession removes a session from memory and storage.
func (m *Manager) DeleteSession(key SessionKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessions, key)
	delete(m.states, key)

	if m.deleteState != nil {
		return m.deleteState(key)
	}
	return nil
}

// sessionToState copies live session state to the persisted state struct.
// Called under the manager's lock — the session is not modified concurrently.
func sessionToState(s *crypto.RatchetSession, state *SessionState) {
	state.RootKey = s.RootKey
	state.SendingChain = s.SendingChain
	state.ReceivingChain = s.ReceivingChain
	state.LocalRatchetPriv = s.LocalRatchetPriv
	state.LocalRatchetPub = s.LocalRatchetPub
	state.RemoteRatchetPub = s.RemoteRatchetPub
	state.SendCounter = s.SendCounter
	state.RecvCounter = s.RecvCounter
	state.PrevSendCount = s.PrevSendCount
	state.SessionID = append([]byte(nil), s.SessionID...)
	state.Established = s.Established

	// Copy skipped keys
	state.SkippedKeys = make([]SkippedKeyEntry, 0, len(s.SkippedKeys))
	for id, key := range s.SkippedKeys {
		state.SkippedKeys = append(state.SkippedKeys, SkippedKeyEntry{
			RatchetPub: id.RatchetPub,
			MsgNum:     id.MsgNum,
			Key:        key,
		})
	}
}

// stateToSession creates a live session from persisted state.
func stateToSession(state *SessionState) *crypto.RatchetSession {
	s := &crypto.RatchetSession{}
	s.RootKey = state.RootKey
	s.SendingChain = state.SendingChain
	s.ReceivingChain = state.ReceivingChain
	s.LocalRatchetPriv = state.LocalRatchetPriv
	s.LocalRatchetPub = state.LocalRatchetPub
	s.RemoteRatchetPub = state.RemoteRatchetPub
	s.SendCounter = state.SendCounter
	s.RecvCounter = state.RecvCounter
	s.PrevSendCount = state.PrevSendCount
	s.SessionID = append([]byte(nil), state.SessionID...)
	s.Established = state.Established
	s.Version = crypto.PrekeyProtocolVersion
	s.SkippedKeys = make(map[crypto.SkippedKeyID][32]byte)

	for _, entry := range state.SkippedKeys {
		id := crypto.SkippedKeyID{
			RatchetPub: entry.RatchetPub,
			MsgNum:     entry.MsgNum,
		}
		s.SkippedKeys[id] = entry.Key
	}

	return s
}

// generateSessionID creates a random 32-byte session identifier.
func generateSessionID() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}

// SerializeStateJSON serializes a session state to JSON for debugging/testing.
func SerializeStateJSON(state *SessionState) ([]byte, error) {
	return json.MarshalIndent(state, "", "  ")
}
