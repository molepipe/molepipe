package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/molepipe/molepipe/backend/internal/crypto"
	"github.com/molepipe/molepipe/backend/internal/identity"
)

// mockSession implements RatchetSession for testing the protocol layer.
// Uses a static chain for both encrypt and decrypt (simplified for testing).
type mockSession struct {
	established bool
	ratchetKey  [32]byte
	chainKey    [32]byte // static key, does not advance
	sendCounter uint32
}

func (m *mockSession) Encrypt(plaintext, aad []byte) ([]byte, RatchetHeader, error) {
	mk := hmacSHA256(m.chainKey[:], []byte{0x01})
	box, _ := crypto.SealMessage(mk, plaintext, aad)
	header := RatchetHeader{
		RatchetPub:   m.ratchetKey[:],
		PrevChainLen: 0,
		MsgNum:       m.sendCounter,
	}
	m.sendCounter++
	return box, header, nil
}

func (m *mockSession) Decrypt(ciphertext []byte, header RatchetHeader, aad []byte) ([]byte, error) {
	mk := hmacSHA256(m.chainKey[:], []byte{0x01})
	return crypto.OpenMessage(mk, ciphertext, aad)
}

func (m *mockSession) IsEstablished() bool {
	return m.established
}

// hmacSHA256 derives a key using HMAC-SHA256.
func hmacSHA256(key, data []byte) []byte {
	r := hkdf.New(sha256.New, nil, key, data)
	out := make([]byte, 32)
	_, _ = io.ReadFull(r, out)
	return out
}

func TestSendMessageV2WithEstablishedSession(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	delivered := make(chan [2]string, 1)

	peer := NewPeer(bob, msgHooks(func(a string) bool { return a == alice.AccountNumber() }, delivered))

	// Create a mock session for Bob (receiver)
	recvSession := &mockSession{
		established: true,
		ratchetKey:  [32]byte{1, 2, 3},
		chainKey:    [32]byte{4, 5, 6},
	}

	sm := &mockSessionManager{
		sessions: map[string]*mockSession{
			alice.AccountNumber(): recvSession,
		},
	}

	// Set session manager on the peer
	peer.SetSessionManager(sm)

	// Build and send a ratchet envelope directly
	aadBytes := aad(alice.AccountNumber(), bob.AccountNumber())
	plaintext := []byte("hello bob via v2")

	box, header, err := recvSession.Encrypt(plaintext, aadBytes)
	if err != nil {
		t.Fatal(err)
	}

	headerBytes := header.HeaderBytes()
	sig := ed25519.Sign(alice.Keys.Signing.Private,
		RatchetMsgSigningBlob(alice.AccountNumber(), bob.AccountNumber(), headerBytes))

	env := RatchetEnvelope{
		Sender:  alice.AccountNumber(),
		Ratchet: header,
		Sig:     sig,
		Box:     box,
	}

	// Receive the ratchet message
	if err := peer.ReceiveRatchet(env, sm); err != nil {
		t.Fatalf("receive ratchet: %v", err)
	}

	select {
	case got := <-delivered:
		if got[0] != alice.AccountNumber() || got[1] != "hello bob via v2" {
			t.Errorf("delivered %v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("not delivered")
	}
}

func TestReceiveRatchetMessage(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	delivered := make(chan [2]string, 1)

	peer := NewPeer(bob, msgHooks(func(a string) bool { return a == alice.AccountNumber() }, delivered))

	// Create a mock session for Bob (receiver) with known chain state
	recvSession := &mockSession{
		established: true,
		ratchetKey:  [32]byte{1, 2, 3},
		chainKey:    [32]byte{4, 5, 6},
	}

	sm := &mockSessionManager{
		sessions: map[string]*mockSession{
			alice.AccountNumber(): recvSession,
		},
	}

	// Build a ratchet envelope using the SAME chain state
	aadBytes := aad(alice.AccountNumber(), bob.AccountNumber())
	plaintext := []byte("hello bob via ratchet")

	// Encrypt using the mock session
	box, header, err := recvSession.Encrypt(plaintext, aadBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Sign the envelope
	headerBytes := header.HeaderBytes()
	sig := ed25519.Sign(alice.Keys.Signing.Private,
		RatchetMsgSigningBlob(alice.AccountNumber(), bob.AccountNumber(), headerBytes))

	env := RatchetEnvelope{
		Sender:  alice.AccountNumber(),
		Ratchet: header,
		Sig:     sig,
		Box:     box,
	}

	// Receive the ratchet message
	if err := peer.ReceiveRatchet(env, sm); err != nil {
		t.Fatalf("receive ratchet: %v", err)
	}

	select {
	case got := <-delivered:
		if got[0] != alice.AccountNumber() || got[1] != "hello bob via ratchet" {
			t.Errorf("delivered %v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("not delivered")
	}
}

func TestReceiveRatchetRejectsForgedSignature(t *testing.T) {
	alice, _ := identity.New()
	mallory, _ := identity.New()
	bob, _ := identity.New()
	delivered := make(chan [2]string, 1)

	peer := NewPeer(bob, msgHooks(func(a string) bool { return a == alice.AccountNumber() }, delivered))

	session := &mockSession{
		established: true,
		ratchetKey:  [32]byte{1, 2, 3},
		chainKey:    [32]byte{4, 5, 6},
	}

	sm := &mockSessionManager{
		sessions: map[string]*mockSession{
			alice.AccountNumber(): session,
		},
	}

	// Mallory signs as alice
	aadBytes := aad(alice.AccountNumber(), bob.AccountNumber())
	box, header, _ := session.Encrypt([]byte("forged"), aadBytes)

	headerBytes := header.HeaderBytes()
	sig := ed25519.Sign(mallory.Keys.Signing.Private,
		RatchetMsgSigningBlob(alice.AccountNumber(), bob.AccountNumber(), headerBytes))

	env := RatchetEnvelope{
		Sender:  alice.AccountNumber(),
		Ratchet: header,
		Sig:     sig,
		Box:     box,
	}

	if err := peer.ReceiveRatchet(env, sm); err == nil {
		t.Fatal("forged ratchet message accepted")
	}
}

// mockSessionManager implements SessionManager for testing.
type mockSessionManager struct {
	sessions map[string]*mockSession
}

func (m *mockSessionManager) GetOrCreateSession(account string) (RatchetSession, error) {
	if s, ok := m.sessions[account]; ok {
		return s, nil
	}
	s := &mockSession{established: true}
	if m.sessions == nil {
		m.sessions = make(map[string]*mockSession)
	}
	m.sessions[account] = s
	return s, nil
}

func (m *mockSessionManager) SaveSession(account string) error {
	return nil
}
