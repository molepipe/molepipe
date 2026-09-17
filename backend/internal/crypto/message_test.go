package crypto

import (
	"bytes"
	"testing"
)

// Alice and Bob must derive the same ECDH shared secret from their DH keys.
func TestSharedSecretAgrees(t *testing.T) {
	alice, _ := DeriveKeys(testSeed(t))
	bob, _ := DeriveKeys(testSeed(t))

	ab, err := SharedSecret(alice.DH.Private, bob.DH.Public)
	if err != nil {
		t.Fatal(err)
	}
	ba, err := SharedSecret(bob.DH.Private, alice.DH.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatal("shared secrets differ")
	}
	var zero [32]byte
	if bytes.Equal(ab, zero[:]) {
		t.Fatal("shared secret is all zero")
	}
}

// The two directions must derive different keys from the same shared secret.
func TestDirectionalKeysDiffer(t *testing.T) {
	shared := []byte("a shared secret for testing 32by")
	ab := DeriveDirectionalKey(shared, "msg v1 alice->bob")
	ba := DeriveDirectionalKey(shared, "msg v1 bob->alice")
	if bytes.Equal(ab, ba) {
		t.Fatal("directional keys are identical — nonce-reuse risk")
	}
	// Determinism.
	if !bytes.Equal(ab, DeriveDirectionalKey(shared, "msg v1 alice->bob")) {
		t.Fatal("key derivation not deterministic")
	}
}

func TestSealOpenMessageRoundTrip(t *testing.T) {
	key := DeriveDirectionalKey([]byte("shared-secret-material-for-tests"), "dir")
	msg := []byte("hello over tor")
	aad := []byte("sender->receiver")

	box, err := SealMessage(key, msg, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(box, msg) {
		t.Error("plaintext leaks in ciphertext")
	}
	got, err := OpenMessage(key, box, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("round trip mismatch")
	}
}

func TestOpenMessageRejectsWrongKeyAadTamper(t *testing.T) {
	key := DeriveDirectionalKey([]byte("shared-secret-material-for-tests"), "dir")
	box, _ := SealMessage(key, []byte("secret"), []byte("aad"))

	other := DeriveDirectionalKey([]byte("different-secret-material-tests!"), "dir")
	if _, err := OpenMessage(other, box, []byte("aad")); err == nil {
		t.Error("opened with wrong key")
	}
	if _, err := OpenMessage(key, box, []byte("different-aad")); err == nil {
		t.Error("opened with wrong aad")
	}
	box[len(box)-1] ^= 0xff
	if _, err := OpenMessage(key, box, []byte("aad")); err == nil {
		t.Error("opened tampered ciphertext")
	}
}

// End-to-end at the primitive level: Alice encrypts to Bob, Bob decrypts.
func TestEndToEndDirectional(t *testing.T) {
	alice, _ := DeriveKeys(testSeed(t))
	bob, _ := DeriveKeys(testSeed(t))
	const info = "onion-chat msg v1 alice->bob"

	sA, _ := SharedSecret(alice.DH.Private, bob.DH.Public)
	kA := DeriveDirectionalKey(sA, info)
	box, err := SealMessage(kA, []byte("ping"), nil)
	if err != nil {
		t.Fatal(err)
	}

	sB, _ := SharedSecret(bob.DH.Private, alice.DH.Public)
	kB := DeriveDirectionalKey(sB, info)
	got, err := OpenMessage(kB, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ping" {
		t.Fatalf("got %q", got)
	}
}
