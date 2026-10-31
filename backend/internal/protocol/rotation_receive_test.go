package protocol

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

// A rotation payload arriving over an established ratchet session must dispatch to
// OnAddressRotation with the CHANNEL identity (envelope Sender), never fall through
// to Deliver as an empty message.
func TestReceiveRatchetDispatchesRotation(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	newAlias, _ := identity.New() // Alice's freshly-minted alias onion

	delivered := make(chan [2]string, 1)
	type rot struct {
		account string
		onion   string
		index   uint32
	}
	rotated := make(chan rot, 1)

	hooks := msgHooks(func(a string) bool { return a == alice.AccountNumber() }, delivered)
	hooks.OnAddressRotation = func(account, onion string, index uint32) error {
		rotated <- rot{account, onion, index}
		return nil
	}
	peer := NewPeer(bob, hooks)

	recvSession := &mockSession{established: true, ratchetKey: [32]byte{1, 2, 3}, chainKey: [32]byte{4, 5, 6}}
	sm := &mockSessionManager{sessions: map[string]*mockSession{alice.AccountNumber(): recvSession}}

	// Alice announces her new alias over the established session (rides the OLD alias).
	pt := EncodeRotationPayload(AddressRotation{NewOnion: newAlias.AccountNumber(), AliasIndex: 7})
	box, header, err := recvSession.Encrypt(pt, aad(alice.AccountNumber(), bob.AccountNumber()))
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(alice.Keys.Signing.Private,
		RatchetMsgSigningBlob(alice.AccountNumber(), bob.AccountNumber(), header.HeaderBytes()))
	env := RatchetEnvelope{Sender: alice.AccountNumber(), Ratchet: header, Sig: sig, Box: box}

	if err := peer.ReceiveRatchet(env, sm); err != nil {
		t.Fatalf("receive rotation: %v", err)
	}

	select {
	case got := <-rotated:
		if got.account != alice.AccountNumber() {
			t.Errorf("rotation identity = %q, want the channel sender (alice)", got.account)
		}
		if got.onion != newAlias.AccountNumber() || got.index != 7 {
			t.Errorf("rotation payload = %q/%d, want %q/7", got.onion, got.index, newAlias.AccountNumber())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("rotation not dispatched to OnAddressRotation")
	}

	// It must NOT have been delivered as a chat message.
	select {
	case got := <-delivered:
		t.Errorf("rotation leaked into the message thread: %v", got)
	default:
	}
}

// A rotation ACK arriving over an established session must dispatch to
// OnAddressRotationAck with the CHANNEL identity and the acked index, never fall
// through to Deliver as an empty message.
func TestReceiveRatchetDispatchesRotationAck(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()

	delivered := make(chan [2]string, 1)
	type ack struct {
		account string
		index   uint32
	}
	acked := make(chan ack, 1)

	hooks := msgHooks(func(a string) bool { return a == alice.AccountNumber() }, delivered)
	hooks.OnAddressRotationAck = func(account string, index uint32) error {
		acked <- ack{account, index}
		return nil
	}
	peer := NewPeer(bob, hooks)

	recvSession := &mockSession{established: true, ratchetKey: [32]byte{1, 2, 3}, chainKey: [32]byte{4, 5, 6}}
	sm := &mockSessionManager{sessions: map[string]*mockSession{alice.AccountNumber(): recvSession}}

	pt := EncodeRotationAckPayload(7)
	box, header, err := recvSession.Encrypt(pt, aad(alice.AccountNumber(), bob.AccountNumber()))
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(alice.Keys.Signing.Private,
		RatchetMsgSigningBlob(alice.AccountNumber(), bob.AccountNumber(), header.HeaderBytes()))
	env := RatchetEnvelope{Sender: alice.AccountNumber(), Ratchet: header, Sig: sig, Box: box}

	if err := peer.ReceiveRatchet(env, sm); err != nil {
		t.Fatalf("receive ack: %v", err)
	}

	select {
	case got := <-acked:
		if got.account != alice.AccountNumber() || got.index != 7 {
			t.Errorf("ack = %q/%d, want channel sender (alice)/7", got.account, got.index)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ack not dispatched to OnAddressRotationAck")
	}
	select {
	case got := <-delivered:
		t.Errorf("rotation ack leaked into the message thread: %v", got)
	default:
	}
}
