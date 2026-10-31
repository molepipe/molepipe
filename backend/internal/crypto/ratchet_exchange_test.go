package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// newPair seeds an initiator (Alice) and responder (Bob) the way X3DH would:
// a shared root secret plus Bob's static (signed-prekey) keypair. This exercises
// the Double Ratchet composition (Encrypt/Decrypt) without the X3DH plumbing.
func newPair(t *testing.T) (alice, bob *RatchetSession) {
	t.Helper()
	bobPriv, err := generateX25519Key()
	if err != nil {
		t.Fatalf("bob key: %v", err)
	}
	var bobStaticPriv, bobStaticPub [32]byte
	copy(bobStaticPriv[:], bobPriv)
	bobStaticPub = x25519PublicKey(bobPriv)

	root := make([]byte, 32)
	sid := make([]byte, 32)
	_, _ = rand.Read(root)
	_, _ = rand.Read(sid)

	alice, err = NewRatchetSession(root, sid, true, bobStaticPub, bobStaticPriv)
	if err != nil {
		t.Fatalf("alice session: %v", err)
	}
	bob, err = NewRatchetSession(root, sid, false, bobStaticPub, bobStaticPriv)
	if err != nil {
		t.Fatalf("bob session: %v", err)
	}
	return alice, bob
}

var (
	aadAB = []byte("alice|bob")
	aadBA = []byte("bob|alice")
)

type wire struct {
	box []byte
	hdr MessageHeader
}

func enc(t *testing.T, s *RatchetSession, msg string, aad []byte) wire {
	t.Helper()
	box, hdr, err := s.Encrypt([]byte(msg), aad)
	if err != nil {
		t.Fatalf("encrypt %q: %v", msg, err)
	}
	return wire{box, hdr}
}

func mustDec(t *testing.T, s *RatchetSession, w wire, aad, want []byte) {
	t.Helper()
	pt, err := s.Decrypt(w.box, w.hdr, aad)
	if err != nil {
		t.Fatalf("decrypt %q: %v", want, err)
	}
	if !bytes.Equal(pt, want) {
		t.Fatalf("decrypt got %q want %q", pt, want)
	}
}

// TestRatchetInOrderBothDirections is the baseline: the responder cannot send
// until his first receive establishes his sending chain, and thereafter both
// directions decrypt in order.
func TestRatchetInOrderBothDirections(t *testing.T) {
	alice, bob := newPair(t)

	if !alice.IsEstablished() {
		t.Fatal("initiator should be established from creation")
	}
	if bob.IsEstablished() {
		t.Fatal("responder should NOT be established before first receive")
	}

	mustDec(t, bob, enc(t, alice, "a0", aadAB), aadAB, []byte("a0"))

	if !bob.IsEstablished() {
		t.Fatal("responder should be established after first receive")
	}

	mustDec(t, bob, enc(t, alice, "a1", aadAB), aadAB, []byte("a1"))
	// Reply direction triggers Alice's DH ratchet on receive.
	mustDec(t, alice, enc(t, bob, "b0", aadBA), aadBA, []byte("b0"))
	mustDec(t, bob, enc(t, alice, "a2", aadAB), aadAB, []byte("a2"))
	mustDec(t, alice, enc(t, bob, "b1", aadBA), aadBA, []byte("b1"))
}

// TestRatchetWithinChainOutOfOrder skips a message inside one sending chain and
// delivers it last, exercising the skipped-key store.
func TestRatchetWithinChainOutOfOrder(t *testing.T) {
	alice, bob := newPair(t)

	w0 := enc(t, alice, "a0", aadAB)
	w1 := enc(t, alice, "a1", aadAB)
	w2 := enc(t, alice, "a2", aadAB)

	mustDec(t, bob, w0, aadAB, []byte("a0"))
	// Skip a1, deliver a2 — bob stores the key for a1.
	mustDec(t, bob, w2, aadAB, []byte("a2"))
	// Late a1 resolves from the skipped-key store.
	mustDec(t, bob, w1, aadAB, []byte("a1"))
}

// TestRatchetHarvestAcrossRatchet is the 5d proof: messages from a previous
// sending chain, still in flight when the peer's next chain arrives, must remain
// decryptable. Without harvestReceivingChain the ratchet step drops those keys.
func TestRatchetHarvestAcrossRatchet(t *testing.T) {
	alice, bob := newPair(t)

	// Alice's chain A: a0,a1,a2. Bob receives only a0; a1,a2 stay in flight.
	a0 := enc(t, alice, "a0", aadAB)
	a1 := enc(t, alice, "a1", aadAB)
	a2 := enc(t, alice, "a2", aadAB)
	mustDec(t, bob, a0, aadAB, []byte("a0"))

	// Bob replies; Alice ratchets on receive and her next send is a new chain.
	mustDec(t, alice, enc(t, bob, "b0", aadBA), aadBA, []byte("b0"))

	// Alice's chain A' (PN=3, since chain A had 3 messages). When Bob receives
	// a'0 he must harvest a1,a2 from the old receiving chain BEFORE ratcheting.
	ap0 := enc(t, alice, "a'0", aadAB)
	mustDec(t, bob, ap0, aadAB, []byte("a'0"))

	// The late messages from chain A now resolve from the harvested skipped keys.
	mustDec(t, bob, a2, aadAB, []byte("a2"))
	mustDec(t, bob, a1, aadAB, []byte("a1"))
}

// TestRatchetDecryptTransactional proves a failed open leaves the session
// usable: a corrupted body must not desynchronize the ratchet.
func TestRatchetDecryptTransactional(t *testing.T) {
	alice, bob := newPair(t)

	// Establish Bob's receiving chain.
	mustDec(t, bob, enc(t, alice, "a0", aadAB), aadAB, []byte("a0"))

	// A valid header (new implicit position) with a corrupted body.
	good := enc(t, alice, "a1", aadAB)
	bad := wire{box: append([]byte(nil), good.box...), hdr: good.hdr}
	bad.box[len(bad.box)-1] ^= 0xff
	if _, err := bob.Decrypt(bad.box, bad.hdr, aadAB); err == nil {
		t.Fatal("corrupted body should fail to decrypt")
	}
	// The session must still decrypt the genuine a1 — no state was consumed.
	mustDec(t, bob, good, aadAB, []byte("a1"))
}

// TestRatchetMaxSkipBound proves a header claiming an enormous gap is rejected
// (the 5a DoS bound) rather than forcing unbounded key derivation.
func TestRatchetMaxSkipBound(t *testing.T) {
	alice, bob := newPair(t)
	mustDec(t, bob, enc(t, alice, "a0", aadAB), aadAB, []byte("a0"))

	w := enc(t, alice, "a1", aadAB)
	// Forge an absurd message number in the same chain.
	forged := wire{box: w.box, hdr: w.hdr}
	forged.hdr.MsgNum = MaxSkip + 5
	if _, err := bob.Decrypt(forged.box, forged.hdr, aadAB); err == nil {
		t.Fatal("gap beyond MaxSkip should be rejected")
	}
	// The rejection left the session intact (transactional): the genuine a1
	// still decrypts at its real position.
	mustDec(t, bob, w, aadAB, []byte("a1"))
}
