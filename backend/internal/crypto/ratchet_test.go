package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// genStaticKeypair generates a static X25519 keypair for testing (simulates
// Bob's identity key from the BIP39 seed).
func genStaticKeypair() (priv [32]byte, pub [32]byte) {
	p, _ := generateX25519Key()
	copy(priv[:], p)
	pub = x25519PublicKey(p)
	return
}

func TestRatchetBasicExchange(t *testing.T) {
	bobStaticPriv, bobStaticPub := genStaticKeypair()

	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	rootSecret := make([]byte, 32)
	rand.Read(rootSecret)

	// Alice initializes with Bob's static pubkey
	aliceSession, err := NewRatchetSession(rootSecret, sessionID, true, bobStaticPub, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	// Bob initializes with his static keypair
	bobSession, err := NewRatchetSession(rootSecret, sessionID, false, [32]byte{}, bobStaticPriv)
	if err != nil {
		t.Fatal(err)
	}

	// --- Message 1: Alice → Bob ---
	aliceSession.mu.Lock()
	msgKey1, err := aliceSession.AdvanceSendingChain()
	aliceSession.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	plaintext1 := []byte("hello Bob")
	header1 := MessageHeader{
		ProtocolVersion: 2,
		SessionID:       sessionID,
		RatchetPub:      aliceSession.LocalRatchetPub[:],
		MsgNum:          0,
		MessageID:       []byte("msg-1"),
	}
	aad1 := header1.HeaderBytes()
	ciphertext1, err := SealRatchet(msgKey1, plaintext1, aad1, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Bob receives: new ratchet key → DHRatchet, then decrypt with receiving chain
	bobSession.mu.Lock()
	err = bobSession.DHRatchet(aliceSession.LocalRatchetPub)
	bobSession.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	bobSession.mu.Lock()
	msgKey1b, err := bobSession.AdvanceReceivingChain(0)
	bobSession.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	plaintext1b, err := OpenRatchet(msgKey1b, ciphertext1, aad1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext1, plaintext1b) {
		t.Errorf("decrypted = %q, want %q", plaintext1b, plaintext1)
	}

	// --- Message 2: Bob → Alice ---
	bobSession.mu.Lock()
	msgKey2, err := bobSession.AdvanceSendingChain()
	bobSession.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	plaintext2 := []byte("hello Alice")
	header2 := MessageHeader{
		ProtocolVersion: 2,
		SessionID:       sessionID,
		RatchetPub:      bobSession.LocalRatchetPub[:],
		MsgNum:          0,
		MessageID:       []byte("msg-2"),
	}
	aad2 := header2.HeaderBytes()
	ciphertext2, err := SealRatchet(msgKey2, plaintext2, aad2, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Alice receives: new ratchet key → DHRatchet, then decrypt
	aliceSession.mu.Lock()
	err = aliceSession.DHRatchet(bobSession.LocalRatchetPub)
	aliceSession.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	aliceSession.mu.Lock()
	msgKey2a, err := aliceSession.AdvanceReceivingChain(0)
	aliceSession.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	plaintext2a, err := OpenRatchet(msgKey2a, ciphertext2, aad2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext2, plaintext2a) {
		t.Errorf("decrypted = %q, want %q", plaintext2a, plaintext2)
	}

	// --- Message 3: Alice → Bob ---
	// Alice's ratchet key changed after DHRatchet in message 2,
	// so Bob needs to DHRatchet when receiving this message.
	aliceSession.mu.Lock()
	msgKey3, err := aliceSession.AdvanceSendingChain()
	aliceSession.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	plaintext3 := []byte("hello again")
	header3 := MessageHeader{
		ProtocolVersion: 2,
		SessionID:       sessionID,
		RatchetPub:      aliceSession.LocalRatchetPub[:],
		MsgNum:          0,
		MessageID:       []byte("msg-3"),
	}
	aad3 := header3.HeaderBytes()
	ciphertext3, err := SealRatchet(msgKey3, plaintext3, aad3, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Bob receives: Alice's ratchet key changed → DHRatchet, then decrypt
	bobSession.mu.Lock()
	err = bobSession.DHRatchet(aliceSession.LocalRatchetPub)
	bobSession.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	bobSession.mu.Lock()
	msgKey3b, err := bobSession.AdvanceReceivingChain(0)
	bobSession.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	plaintext3b, err := OpenRatchet(msgKey3b, ciphertext3, aad3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext3, plaintext3b) {
		t.Errorf("decrypted = %q, want %q", plaintext3b, plaintext3)
	}
}

func TestRatchetMultipleMessages(t *testing.T) {
	bobStaticPriv, bobStaticPub := genStaticKeypair()
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	rootSecret := make([]byte, 32)
	rand.Read(rootSecret)

	sender, _ := NewRatchetSession(rootSecret, sessionID, true, bobStaticPub, [32]byte{})
	receiver, _ := NewRatchetSession(rootSecret, sessionID, false, [32]byte{}, bobStaticPriv)

	// First message (initial chain)
	sender.mu.Lock()
	msgKey0, _ := sender.AdvanceSendingChain()
	sender.mu.Unlock()

	header0 := MessageHeader{
		ProtocolVersion: 2, SessionID: sessionID,
		RatchetPub: sender.LocalRatchetPub[:], MsgNum: 0, MessageID: []byte{0},
	}
	ct0, _ := SealRatchet(msgKey0, []byte("msg"), header0.HeaderBytes(), 0)

	receiver.mu.Lock()
	receiver.DHRatchet(sender.LocalRatchetPub)
	receiver.mu.Unlock()

	receiver.mu.Lock()
	mkR0, _ := receiver.AdvanceReceivingChain(0)
	receiver.mu.Unlock()

	d0, err := OpenRatchet(mkR0, ct0, header0.HeaderBytes(), 0)
	if err != nil {
		t.Fatalf("decrypt msg 0: %v", err)
	}
	if string(d0) != "msg" {
		t.Fatal("msg 0 mismatch")
	}

	// Ratchet step (Bob → Alice direction) — sender gets new ratchet key
	sender.mu.Lock()
	sender.DHRatchet(receiver.LocalRatchetPub)
	sender.mu.Unlock()

	// Receiver must DHRatchet on the sender's new ratchet key before receiving
	receiver.mu.Lock()
	receiver.DHRatchet(sender.LocalRatchetPub)
	receiver.mu.Unlock()

	// Send 100 messages in the new chain
	for i := 0; i < 100; i++ {
		sender.mu.Lock()
		msgKey, err := sender.AdvanceSendingChain()
		sender.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}

		header := MessageHeader{
			ProtocolVersion: 2, SessionID: sessionID,
			RatchetPub: sender.LocalRatchetPub[:], MsgNum: uint32(i), MessageID: []byte{byte(i)},
		}
		ciphertext, err := SealRatchet(msgKey, []byte("msg"), header.HeaderBytes(), uint32(i))
		if err != nil {
			t.Fatal(err)
		}

		receiver.mu.Lock()
		msgKeyR, err := receiver.AdvanceReceivingChain(uint32(i))
		receiver.mu.Unlock()
		if err != nil {
			t.Fatalf("receive msg %d: %v", i, err)
		}

		decrypted, err := OpenRatchet(msgKeyR, ciphertext, header.HeaderBytes(), uint32(i))
		if err != nil {
			t.Fatalf("decrypt msg %d: %v", i, err)
		}
		if string(decrypted) != "msg" {
			t.Fatalf("msg %d: mismatch", i)
		}
	}
}

func TestRatchetOutOfOrder(t *testing.T) {
	bobStaticPriv, bobStaticPub := genStaticKeypair()
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	rootSecret := make([]byte, 32)
	rand.Read(rootSecret)

	sender, _ := NewRatchetSession(rootSecret, sessionID, true, bobStaticPub, [32]byte{})
	receiver, _ := NewRatchetSession(rootSecret, sessionID, false, [32]byte{}, bobStaticPriv)

	// First message (initial chain) — just to trigger DHRatchet on receiver
	sender.mu.Lock()
	msgKey0, _ := sender.AdvanceSendingChain()
	sender.mu.Unlock()
	h0 := MessageHeader{
		ProtocolVersion: 2, SessionID: sessionID,
		RatchetPub: sender.LocalRatchetPub[:], MsgNum: 0, MessageID: []byte{0},
	}
	ct0, _ := SealRatchet(msgKey0, []byte("m"), h0.HeaderBytes(), 0)
	receiver.mu.Lock()
	receiver.DHRatchet(sender.LocalRatchetPub)
	mk0, _ := receiver.AdvanceReceivingChain(0)
	receiver.mu.Unlock()
	OpenRatchet(mk0, ct0, h0.HeaderBytes(), 0)

	// Ratchet step — both sides
	sender.mu.Lock()
	sender.DHRatchet(receiver.LocalRatchetPub)
	sender.mu.Unlock()
	receiver.mu.Lock()
	receiver.DHRatchet(sender.LocalRatchetPub)
	receiver.mu.Unlock()

	// Send 5 messages in the new chain
	type msgEntry struct {
		header     MessageHeader
		ciphertext []byte
	}
	messages := make([]msgEntry, 5)
	for i := 0; i < 5; i++ {
		sender.mu.Lock()
		msgKey, _ := sender.AdvanceSendingChain()
		sender.mu.Unlock()

		header := MessageHeader{
			ProtocolVersion: 2, SessionID: sessionID,
			RatchetPub: sender.LocalRatchetPub[:], MsgNum: uint32(i), MessageID: []byte{byte(i)},
		}
		ciphertext, _ := SealRatchet(msgKey, []byte("msg"), header.HeaderBytes(), uint32(i))
		messages[i] = msgEntry{header: header, ciphertext: ciphertext}
	}

	// Receive out of order: 3, 1, 4, 0, 2
	for _, i := range []int{3, 1, 4, 0, 2} {
		receiver.mu.Lock()
		// Try skipped key first (messages skipped when receiving ahead)
		header := messages[i].header
		mk, found := receiver.TrySkippedKey(header)
		var msgKey [32]byte
		if found {
			msgKey = mk
		} else {
			var err error
			msgKey, err = receiver.AdvanceReceivingChain(uint32(i))
			receiver.mu.Unlock()
			if err != nil {
				t.Fatalf("receive msg %d: %v", i, err)
			}
		}
		if !found {
			// Already unlocked above
		} else {
			receiver.mu.Unlock()
		}
		decrypted, err := OpenRatchet(msgKey, messages[i].ciphertext, messages[i].header.HeaderBytes(), uint32(i))
		if err != nil {
			t.Fatalf("decrypt msg %d: %v", i, err)
		}
		if string(decrypted) != "msg" {
			t.Fatalf("msg %d: wrong content", i)
		}
	}
}

func TestRatchetDuplicateRejection(t *testing.T) {
	bobStaticPriv, bobStaticPub := genStaticKeypair()
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	rootSecret := make([]byte, 32)
	rand.Read(rootSecret)

	sender, _ := NewRatchetSession(rootSecret, sessionID, true, bobStaticPub, [32]byte{})
	receiver, _ := NewRatchetSession(rootSecret, sessionID, false, [32]byte{}, bobStaticPriv)

	sender.mu.Lock()
	_, _ = sender.AdvanceSendingChain()
	sender.mu.Unlock()

	receiver.mu.Lock()
	_, err := receiver.AdvanceReceivingChain(0)
	receiver.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	// Duplicate
	receiver.mu.Lock()
	_, err = receiver.AdvanceReceivingChain(0)
	receiver.mu.Unlock()
	if err == nil {
		t.Error("duplicate message number accepted")
	}
}

func TestRatchetForwardSecrecy(t *testing.T) {
	_, bobStaticPub := genStaticKeypair()
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	rootSecret := make([]byte, 32)
	rand.Read(rootSecret)

	sender, _ := NewRatchetSession(rootSecret, sessionID, true, bobStaticPub, [32]byte{})

	var oldRoot [32]byte
	copy(oldRoot[:], sender.RootKey[:])

	_, otherPub, _ := generateRatchetKeypair()
	sender.mu.Lock()
	sender.DHRatchet(otherPub)
	sender.mu.Unlock()

	same := true
	for i := 0; i < 32; i++ {
		if sender.RootKey[i] != oldRoot[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("root key did not change after ratchet step")
	}
	if sender.SendCounter != 0 {
		t.Errorf("send counter = %d, want 0 after ratchet", sender.SendCounter)
	}
}

func TestRatchetMessageKeyUniqueness(t *testing.T) {
	_, bobStaticPub := genStaticKeypair()
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	rootSecret := make([]byte, 32)
	rand.Read(rootSecret)

	sender, _ := NewRatchetSession(rootSecret, sessionID, true, bobStaticPub, [32]byte{})

	keys := make(map[[32]byte]bool)
	for i := 0; i < 1000; i++ {
		sender.mu.Lock()
		key, _ := sender.AdvanceSendingChain()
		sender.mu.Unlock()
		if keys[key] {
			t.Fatalf("duplicate message key at iteration %d", i)
		}
		keys[key] = true
	}
}

func TestRatchetDeterministicNonce(t *testing.T) {
	nonce1 := deriveNonce(42)
	nonce2 := deriveNonce(42)
	if !bytes.Equal(nonce1, nonce2) {
		t.Error("same msgNum produced different nonces")
	}
	nonce3 := deriveNonce(43)
	if bytes.Equal(nonce1, nonce3) {
		t.Error("different msgNum produced same nonce")
	}
}
