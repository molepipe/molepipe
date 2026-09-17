package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := []byte("the recovery phrase goes here")
	aad := []byte("tormsg-identity-v1")

	nonce, ct, err := Seal(key, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, plaintext) {
		t.Error("plaintext appears in ciphertext")
	}
	got, err := Open(key, nonce, ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Error("round trip mismatch")
	}
}

func TestOpenWrongKeyFails(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	nonce, ct, _ := Seal(key, []byte("secret"), nil)

	wrong := make([]byte, 32)
	rand.Read(wrong)
	if _, err := Open(wrong, nonce, ct, nil); err == nil {
		t.Error("open succeeded with wrong key")
	}
}

func TestOpenTamperedFails(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	aad := []byte("header")
	nonce, ct, _ := Seal(key, []byte("secret"), aad)

	ct[0] ^= 0xff
	if _, err := Open(key, nonce, ct, aad); err == nil {
		t.Error("open succeeded with tampered ciphertext")
	}

	nonce2, ct2, _ := Seal(key, []byte("secret"), aad)
	if _, err := Open(key, nonce2, ct2, []byte("different header")); err == nil {
		t.Error("open succeeded with wrong aad")
	}
}

func TestDeriveKeyArgon2idDeterministic(t *testing.T) {
	p := DefaultArgon2Params()
	salt := make([]byte, p.SaltLength)
	rand.Read(salt)
	pw := []byte("hunter2")

	k1 := DeriveKeyArgon2id(pw, salt, p)
	k2 := DeriveKeyArgon2id(pw, salt, p)
	if !bytes.Equal(k1, k2) {
		t.Error("argon2 not deterministic for same inputs")
	}
	if len(k1) != int(p.KeyLength) {
		t.Errorf("key length = %d, want %d", len(k1), p.KeyLength)
	}
	k3 := DeriveKeyArgon2id([]byte("hunter3"), salt, p)
	if bytes.Equal(k1, k3) {
		t.Error("different passwords produced same key")
	}
}
