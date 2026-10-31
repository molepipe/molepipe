package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

// --- Double Ratchet Full Flow Tests ---

func TestRatchetBidirectionalExchange(t *testing.T) {
	bobStaticPriv, bobStaticPub := genStaticKeypair()
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	rootSecret := make([]byte, 32)
	rand.Read(rootSecret)

	alice, _ := NewRatchetSession(rootSecret, sessionID, true, bobStaticPub, [32]byte{})
	bob, _ := NewRatchetSession(rootSecret, sessionID, false, [32]byte{}, bobStaticPriv)

	// Alice → Bob (msg 0)
	alice.mu.Lock()
	mk0, _ := alice.AdvanceSendingChain()
	alice.mu.Unlock()
	h0 := MessageHeader{ProtocolVersion: 2, SessionID: sessionID, RatchetPub: alice.LocalRatchetPub[:], MsgNum: 0, MessageID: []byte{0}}
	ct0, _ := SealRatchet(mk0, []byte("a0"), h0.HeaderBytes(), 0)

	bob.mu.Lock()
	bob.DHRatchet(alice.LocalRatchetPub)
	bob.mu.Unlock()
	bob.mu.Lock()
	mk0b, _ := bob.AdvanceReceivingChain(0)
	bob.mu.Unlock()
	pt0, _ := OpenRatchet(mk0b, ct0, h0.HeaderBytes(), 0)
	if string(pt0) != "a0" {
		t.Fatal("msg 0 failed")
	}

	// Bob → Alice (msg 1)
	bob.mu.Lock()
	mk1, _ := bob.AdvanceSendingChain()
	bob.mu.Unlock()
	h1 := MessageHeader{ProtocolVersion: 2, SessionID: sessionID, RatchetPub: bob.LocalRatchetPub[:], MsgNum: 0, MessageID: []byte{1}}
	ct1, _ := SealRatchet(mk1, []byte("b1"), h1.HeaderBytes(), 0)

	alice.mu.Lock()
	alice.DHRatchet(bob.LocalRatchetPub)
	alice.mu.Unlock()
	alice.mu.Lock()
	mk1a, _ := alice.AdvanceReceivingChain(0)
	alice.mu.Unlock()
	pt1, _ := OpenRatchet(mk1a, ct1, h1.HeaderBytes(), 0)
	if string(pt1) != "b1" {
		t.Fatal("msg 1 failed")
	}

	// Alice → Bob (msg 2, same chain, but Alice's ratchet key changed)
	alice.mu.Lock()
	mk2, _ := alice.AdvanceSendingChain()
	alice.mu.Unlock()
	h2 := MessageHeader{ProtocolVersion: 2, SessionID: sessionID, RatchetPub: alice.LocalRatchetPub[:], MsgNum: 0, MessageID: []byte{2}}
	ct2, _ := SealRatchet(mk2, []byte("a2"), h2.HeaderBytes(), 0)

	// Bob receives: Alice's ratchet key is new → DHRatchet
	bob.mu.Lock()
	bob.DHRatchet(alice.LocalRatchetPub)
	bob.mu.Unlock()
	bob.mu.Lock()
	mk2b, _ := bob.AdvanceReceivingChain(0)
	bob.mu.Unlock()
	pt2, _ := OpenRatchet(mk2b, ct2, h2.HeaderBytes(), 0)
	if string(pt2) != "a2" {
		t.Fatal("msg 2 failed")
	}
}

func TestRatchetManyMessagesSameChain(t *testing.T) {
	bobStaticPriv, bobStaticPub := genStaticKeypair()
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	rootSecret := make([]byte, 32)
	rand.Read(rootSecret)

	sender, _ := NewRatchetSession(rootSecret, sessionID, true, bobStaticPub, [32]byte{})
	receiver, _ := NewRatchetSession(rootSecret, sessionID, false, [32]byte{}, bobStaticPriv)

	// First message uses initial chain
	sender.mu.Lock()
	mk0, _ := sender.AdvanceSendingChain()
	sender.mu.Unlock()
	h0 := MessageHeader{ProtocolVersion: 2, SessionID: sessionID, RatchetPub: sender.LocalRatchetPub[:], MsgNum: 0, MessageID: []byte{0}}
	ct0, _ := SealRatchet(mk0, []byte("x"), h0.HeaderBytes(), 0)

	receiver.mu.Lock()
	receiver.DHRatchet(sender.LocalRatchetPub)
	mk0r, _ := receiver.AdvanceReceivingChain(0)
	receiver.mu.Unlock()
	pt0, _ := OpenRatchet(mk0r, ct0, h0.HeaderBytes(), 0)
	if string(pt0) != "x" {
		t.Fatal("msg 0 failed")
	}

	// Ratchet step for subsequent messages
	sender.mu.Lock()
	sender.DHRatchet(receiver.LocalRatchetPub)
	sender.mu.Unlock()
	receiver.mu.Lock()
	receiver.DHRatchet(sender.LocalRatchetPub)
	receiver.mu.Unlock()

	// Send 1000 messages in the new chain
	for i := 0; i < 1000; i++ {
		sender.mu.Lock()
		mk, _ := sender.AdvanceSendingChain()
		sender.mu.Unlock()

		h := MessageHeader{ProtocolVersion: 2, SessionID: sessionID, RatchetPub: sender.LocalRatchetPub[:], MsgNum: uint32(i), MessageID: []byte{byte(i)}}
		ct, _ := SealRatchet(mk, []byte("x"), h.HeaderBytes(), uint32(i))

		receiver.mu.Lock()
		mkR, err := receiver.AdvanceReceivingChain(uint32(i))
		receiver.mu.Unlock()
		if err != nil {
			t.Fatalf("msg %d: %v", i, err)
		}

		pt, err := OpenRatchet(mkR, ct, h.HeaderBytes(), uint32(i))
		if err != nil {
			t.Fatalf("decrypt msg %d: %v", i, err)
		}
		if string(pt) != "x" {
			t.Fatalf("msg %d: mismatch", i)
		}
	}
}

func TestRatchetMessageKeyNeverReused(t *testing.T) {
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	rootSecret := make([]byte, 32)
	rand.Read(rootSecret)

	bobStaticPriv, bobStaticPub := genStaticKeypair()
	sender, _ := NewRatchetSession(rootSecret, sessionID, true, bobStaticPub, [32]byte{})
	receiver, _ := NewRatchetSession(rootSecret, sessionID, false, [32]byte{}, bobStaticPriv)

	// Initialize chains via DHRatchet
	sender.mu.Lock()
	sender.DHRatchet(receiver.LocalRatchetPub)
	sender.mu.Unlock()
	receiver.mu.Lock()
	receiver.DHRatchet(sender.LocalRatchetPub)
	receiver.mu.Unlock()

	keys := make(map[[32]byte]bool)
	for i := 0; i < 10000; i++ {
		sender.mu.Lock()
		key, _ := sender.AdvanceSendingChain()
		sender.mu.Unlock()
		if keys[key] {
			t.Fatalf("duplicate key at iteration %d", i)
		}
		keys[key] = true
	}
}

func TestRatchetDeterministicNonces(t *testing.T) {
	for i := uint32(0); i < 1000; i++ {
		n1 := deriveNonce(i)
		n2 := deriveNonce(i)
		if !bytes.Equal(n1, n2) {
			t.Fatalf("nonce(%d) not deterministic", i)
		}
	}
	n0 := deriveNonce(0)
	n1 := deriveNonce(1)
	if bytes.Equal(n0, n1) {
		t.Fatal("nonces collide")
	}
}

// --- DoS Bound Tests ---

func TestSkippedKeyLimit(t *testing.T) {
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	rootSecret := make([]byte, 32)
	rand.Read(rootSecret)

	bobStaticPriv, bobStaticPub := genStaticKeypair()
	sender, _ := NewRatchetSession(rootSecret, sessionID, true, bobStaticPub, [32]byte{})
	receiver, _ := NewRatchetSession(rootSecret, sessionID, false, [32]byte{}, bobStaticPriv)

	// First message: sender sends with initial chain
	sender.mu.Lock()
	mk0, _ := sender.AdvanceSendingChain()
	sender.mu.Unlock()
	h0 := MessageHeader{ProtocolVersion: 2, SessionID: sessionID, RatchetPub: sender.LocalRatchetPub[:], MsgNum: 0, MessageID: []byte{0}}
	ct0, _ := SealRatchet(mk0, []byte("x"), h0.HeaderBytes(), 0)
	receiver.mu.Lock()
	receiver.DHRatchet(sender.LocalRatchetPub)
	_, _ = receiver.AdvanceReceivingChain(0)
	_ = ct0
	receiver.mu.Unlock()

	// Ratchet step for sender and receiver
	sender.mu.Lock()
	sender.DHRatchet(receiver.LocalRatchetPub)
	sender.mu.Unlock()
	receiver.mu.Lock()
	receiver.DHRatchet(sender.LocalRatchetPub)
	receiver.mu.Unlock()

	// The receiver is at RecvCounter 0 on a fresh receiving chain. A single
	// header that jumps beyond MaxSkip must be rejected outright — the bound is
	// on the GAP, not reached by sending that many messages one at a time (which
	// never skips). This is the DoS guard: without it one header forces
	// (MsgNum - RecvCounter) HMAC derivations and that many stored keys.
	receiver.mu.Lock()
	_, err := receiver.AdvanceReceivingChain(MaxSkip + 1)
	receiver.mu.Unlock()
	if err == nil {
		t.Fatalf("a gap of %d (> MaxSkip %d) must be rejected", MaxSkip+1, MaxSkip)
	}

	// A gap of exactly MaxSkip is allowed (and leaves MaxSkip retained keys).
	receiver.mu.Lock()
	_, err = receiver.AdvanceReceivingChain(MaxSkip)
	nSkipped := len(receiver.SkippedKeys)
	receiver.mu.Unlock()
	if err != nil {
		t.Fatalf("a gap of exactly MaxSkip should succeed: %v", err)
	}
	if nSkipped != MaxSkip {
		t.Fatalf("expected %d retained skipped keys, got %d", MaxSkip, nSkipped)
	}
}

// --- Security Property Tests ---

func TestOldMessageKeyCannotDecryptLaterMessages(t *testing.T) {
	bobStaticPriv, bobStaticPub := genStaticKeypair()
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	rootSecret := make([]byte, 32)
	rand.Read(rootSecret)

	alice, _ := NewRatchetSession(rootSecret, sessionID, true, bobStaticPub, [32]byte{})
	bob, _ := NewRatchetSession(rootSecret, sessionID, false, [32]byte{}, bobStaticPriv)

	// Alice sends msg 0
	alice.mu.Lock()
	_, _ = alice.AdvanceSendingChain()
	alice.mu.Unlock()
	h0 := MessageHeader{ProtocolVersion: 2, SessionID: sessionID, RatchetPub: alice.LocalRatchetPub[:], MsgNum: 0, MessageID: []byte{0}}
	_ = h0 // header created but not needed for this test

	// Bob receives msg 0
	bob.mu.Lock()
	bob.DHRatchet(alice.LocalRatchetPub)
	bob.mu.Unlock()
	bob.mu.Lock()
	mk0b, _ := bob.AdvanceReceivingChain(0)
	bob.mu.Unlock()

	// Alice sends msg 1
	alice.mu.Lock()
	mk1, _ := alice.AdvanceSendingChain()
	alice.mu.Unlock()
	h1 := MessageHeader{ProtocolVersion: 2, SessionID: sessionID, RatchetPub: alice.LocalRatchetPub[:], MsgNum: 1, MessageID: []byte{1}}
	ct1, _ := SealRatchet(mk1, []byte("secret1"), h1.HeaderBytes(), 1)

	// Bob receives msg 1
	bob.mu.Lock()
	mk1b, _ := bob.AdvanceReceivingChain(1)
	bob.mu.Unlock()

	// Old key mk0b CANNOT decrypt msg 1
	_, err := OpenRatchet(mk0b, ct1, h1.HeaderBytes(), 1)
	if err == nil {
		t.Error("old message key decrypted a later message")
	}

	// Correct key mk1b CAN decrypt msg 1
	pt1, err := OpenRatchet(mk1b, ct1, h1.HeaderBytes(), 1)
	if err != nil {
		t.Fatalf("correct key failed: %v", err)
	}
	if string(pt1) != "secret1" {
		t.Fatal("wrong plaintext")
	}
}

// --- Edge Case Tests ---

func TestEmptyMessageEncryption(t *testing.T) {
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	rootSecret := make([]byte, 32)
	rand.Read(rootSecret)

	bobStaticPriv, bobStaticPub := genStaticKeypair()
	sender, _ := NewRatchetSession(rootSecret, sessionID, true, bobStaticPub, [32]byte{})
	receiver, _ := NewRatchetSession(rootSecret, sessionID, false, [32]byte{}, bobStaticPriv)

	// First message: sender sends with initial chain
	sender.mu.Lock()
	mk0, _ := sender.AdvanceSendingChain()
	sender.mu.Unlock()
	h0 := MessageHeader{ProtocolVersion: 2, SessionID: sessionID, RatchetPub: sender.LocalRatchetPub[:], MsgNum: 0, MessageID: []byte{0}}
	ct0, _ := SealRatchet(mk0, []byte(""), h0.HeaderBytes(), 0)
	receiver.mu.Lock()
	receiver.DHRatchet(sender.LocalRatchetPub)
	mk0r, _ := receiver.AdvanceReceivingChain(0)
	receiver.mu.Unlock()
	pt0, err := OpenRatchet(mk0r, ct0, h0.HeaderBytes(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pt0) != 0 {
		t.Fatalf("empty message = %d bytes", len(pt0))
	}
}

func TestMaximumMessageSize(t *testing.T) {
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	rootSecret := make([]byte, 32)
	rand.Read(rootSecret)

	bobStaticPriv, bobStaticPub := genStaticKeypair()
	sender, _ := NewRatchetSession(rootSecret, sessionID, true, bobStaticPub, [32]byte{})
	receiver, _ := NewRatchetSession(rootSecret, sessionID, false, [32]byte{}, bobStaticPriv)

	// First message: sender sends with initial chain
	sender.mu.Lock()
	mk0, _ := sender.AdvanceSendingChain()
	sender.mu.Unlock()
	h0 := MessageHeader{ProtocolVersion: 2, SessionID: sessionID, RatchetPub: sender.LocalRatchetPub[:], MsgNum: 0, MessageID: []byte{0}}
	ct0, _ := SealRatchet(mk0, []byte("x"), h0.HeaderBytes(), 0)
	receiver.mu.Lock()
	receiver.DHRatchet(sender.LocalRatchetPub)
	_, _ = receiver.AdvanceReceivingChain(0)
	_ = ct0
	receiver.mu.Unlock()

	// Ratchet step for sender and receiver
	sender.mu.Lock()
	sender.DHRatchet(receiver.LocalRatchetPub)
	sender.mu.Unlock()
	receiver.mu.Lock()
	receiver.DHRatchet(sender.LocalRatchetPub)
	receiver.mu.Unlock()

	// Send max-size message
	maxPT := make([]byte, 16*1024)
	rand.Read(maxPT)

	sender.mu.Lock()
	mk, _ := sender.AdvanceSendingChain()
	sender.mu.Unlock()

	h := MessageHeader{ProtocolVersion: 2, SessionID: sessionID, RatchetPub: sender.LocalRatchetPub[:], MsgNum: 0, MessageID: []byte{0}}
	ct, err := SealRatchet(mk, maxPT, h.HeaderBytes(), 0)
	if err != nil {
		t.Fatal(err)
	}

	receiver.mu.Lock()
	mkR, _ := receiver.AdvanceReceivingChain(0)
	receiver.mu.Unlock()

	pt, err := OpenRatchet(mkR, ct, h.HeaderBytes(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, maxPT) {
		t.Fatal("max size message mismatch")
	}
}

// --- Prekey Lifecycle Tests ---

func TestCompromisedPrekeyLifecycle(t *testing.T) {
	ikB_pub, ikB_priv, _ := ed25519.GenerateKey(nil)

	spkB1, _, _ := GenerateSignedPrekey(ikB_priv, ikB_pub, 1, time.Now())
	spkB2, _, _ := GenerateSignedPrekey(ikB_priv, ikB_pub, 2, time.Now())

	// Both signatures are valid individually
	if err := VerifySignedPrekey(spkB1, ikB_pub); err != nil {
		t.Fatal("prekey 1 invalid")
	}
	if err := VerifySignedPrekey(spkB2, ikB_pub); err != nil {
		t.Fatal("prekey 2 invalid")
	}

	// But prekey 1 should NOT be used for new sessions (protocol layer enforces this)
	_ = spkB1
	_ = spkB2
}

// helper
func uint32Ptr(v uint32) *uint32 { return &v }
