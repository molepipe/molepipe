package crypto

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

func TestSignedPrekeyGenerationAndVerification(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	sp, _, err := GenerateSignedPrekey(priv, pub, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if sp.ID != 1 {
		t.Errorf("ID = %d, want 1", sp.ID)
	}
	if err := VerifySignedPrekey(sp, pub); err != nil {
		t.Errorf("valid signature rejected: %v", err)
	}
}

func TestSignedPrekeyRejectsTampered(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sp, _, _ := GenerateSignedPrekey(priv, pub, 1, time.Now())
	sp.PublicKey[0] ^= 0xff
	if err := VerifySignedPrekey(sp, pub); err == nil {
		t.Error("tampered signed prekey accepted")
	}
}

func TestSignedPrekeyRejectsWrongIdentity(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wrongPub, _, _ := ed25519.GenerateKey(nil)
	sp, _, _ := GenerateSignedPrekey(priv, pub, 1, time.Now())
	if err := VerifySignedPrekey(sp, wrongPub); err == nil {
		t.Error("wrong identity key accepted")
	}
}

func TestSignedPrekeySignatureUniqueness(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sp1, _, _ := GenerateSignedPrekey(priv, pub, 1, time.Now())
	sp2, _, _ := GenerateSignedPrekey(priv, pub, 2, time.Now())
	if string(sp1.Signature) == string(sp2.Signature) {
		t.Error("different prekeys have same signature")
	}
}

func TestOneTimePrekeyGeneration(t *testing.T) {
	otp, privKey, err := GenerateOneTimePrekey(42)
	if err != nil {
		t.Fatal(err)
	}
	if otp.ID != 42 {
		t.Errorf("ID = %d, want 42", otp.ID)
	}
	if len(privKey) != 32 {
		t.Errorf("private key len = %d, want 32", len(privKey))
	}
	pub := x25519PublicKey(privKey)
	if pub != otp.PublicKey {
		t.Error("public key does not match private key")
	}
}

func TestOneTimePrekeyUniqueness(t *testing.T) {
	seen := make(map[[32]byte]bool)
	for i := uint32(0); i < 100; i++ {
		otp, _, _ := GenerateOneTimePrekey(i)
		if seen[otp.PublicKey] {
			t.Fatalf("duplicate public key at ID %d", i)
		}
		seen[otp.PublicKey] = true
	}
}

func TestPrekeyBundleVerification(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	sp, _, _ := GenerateSignedPrekey(priv, pub, 1, now)

	bundle := PrekeyBundle{
		IdentityPub:         pub,
		SignedPrekeyID:      sp.ID,
		SignedPrekeyPub:     sp.PublicKey[:],
		SignedPrekeySig:     sp.Signature,
		SignedPrekeyCreated: now.UnixMilli(),
		Version:             2,
	}

	if err := VerifyBundle(bundle, pub); err != nil {
		t.Errorf("valid bundle rejected: %v", err)
	}
}

// A bundle re-signed for an alias identity verifies under the alias key and NOT
// under the primary key — the property that lets an alias-of-us serve the shared
// signed prekey to a client that dialed the alias without exposing the primary.
// The re-sign must not mutate the input bundle (its stored SP must stay valid).
func TestReSignBundleForIdentity(t *testing.T) {
	primaryPub, primaryPriv, _ := ed25519.GenerateKey(nil)
	aliasPub, aliasPriv, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	sp, _, _ := GenerateSignedPrekey(primaryPriv, primaryPub, 7, now)

	primaryBundle := PrekeyBundle{
		IdentityPub:         primaryPub,
		SignedPrekeyID:      sp.ID,
		SignedPrekeyPub:     sp.PublicKey[:],
		SignedPrekeySig:     sp.Signature,
		SignedPrekeyCreated: now.UnixMilli(),
		Version:             2,
	}

	aliasBundle, err := ReSignBundleForIdentity(primaryBundle, aliasPub, aliasPriv)
	if err != nil {
		t.Fatalf("re-sign: %v", err)
	}
	if err := VerifyBundle(aliasBundle, aliasPub); err != nil {
		t.Errorf("re-signed bundle must verify under the alias key: %v", err)
	}
	if err := VerifyBundle(aliasBundle, primaryPub); err == nil {
		t.Error("re-signed bundle must NOT verify under the primary key")
	}
	if !bytes.Equal(aliasBundle.IdentityPub, aliasPub) {
		t.Error("re-signed bundle must present the alias identity")
	}
	// Input untouched: the primary bundle still verifies under the primary key.
	if err := VerifyBundle(primaryBundle, primaryPub); err != nil {
		t.Errorf("re-sign must not mutate the input bundle: %v", err)
	}
	if bytes.Equal(primaryBundle.SignedPrekeySig, aliasBundle.SignedPrekeySig) {
		t.Error("re-signed bundle must carry a distinct signature")
	}
	// The X25519 material X3DH keys off is unchanged (only the Ed identity moves).
	if !bytes.Equal(aliasBundle.SignedPrekeyPub, primaryBundle.SignedPrekeyPub) {
		t.Error("re-sign must not change the signed-prekey public key")
	}
}

func TestPrekeyBundleRejectsTamperedSig(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	sp, _, _ := GenerateSignedPrekey(priv, pub, 1, now)

	bundle := PrekeyBundle{
		IdentityPub:         pub,
		SignedPrekeyID:      sp.ID,
		SignedPrekeyPub:     sp.PublicKey[:],
		SignedPrekeySig:     sp.Signature,
		SignedPrekeyCreated: now.UnixMilli(),
		Version:             2,
	}
	bundle.SignedPrekeySig[0] ^= 0xff
	if err := VerifyBundle(bundle, pub); err == nil {
		t.Error("tampered bundle accepted")
	}
}

func TestPrekeyBundleRejectsWrongVersion(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	sp, _, _ := GenerateSignedPrekey(priv, pub, 1, now)

	bundle := PrekeyBundle{
		IdentityPub:         pub,
		SignedPrekeyID:      sp.ID,
		SignedPrekeyPub:     sp.PublicKey[:],
		SignedPrekeySig:     sp.Signature,
		SignedPrekeyCreated: now.UnixMilli(),
		Version:             99,
	}
	if err := VerifyBundle(bundle, pub); err == nil {
		t.Error("unsupported version accepted")
	}
}

// genX25519Keypair generates a random X25519 keypair for testing.
func genX25519Keypair() (priv [32]byte, pub [32]byte) {
	p, _ := generateX25519Key()
	copy(priv[:], p)
	pub = x25519PublicKey(p)
	return
}

func TestX3DHBothSidesAgree(t *testing.T) {
	ikA, ikAPub := genX25519Keypair()
	ikB, ikBPub := genX25519Keypair()

	// Bob generates signed prekey (signed by his Ed25519 key)
	edB_pub, edB_priv, _ := ed25519.GenerateKey(nil)
	spkB, spkBPriv, _ := GenerateSignedPrekey(edB_priv, edB_pub, 1, time.Now())
	var spkBPub [32]byte
	copy(spkBPub[:], spkB.PublicKey[:])

	// Bob generates one-time prekey
	_, opkBPriv, _ := GenerateOneTimePrekey(1)
	opkBPub := x25519PublicKey(opkBPriv)

	// Alice initiates X3DH
	_, ephPub, aliceSecret, err := X3DHInitiate(ikA, spkBPub, ikBPub, &opkBPub)
	if err != nil {
		t.Fatal(err)
	}

	// Bob responds
	bobSecret, err := X3DHRespond(ikB, spkBPriv, opkBPriv, ephPub, ikAPub, true)
	if err != nil {
		t.Fatal(err)
	}

	if len(aliceSecret) != 32 || len(bobSecret) != 32 {
		t.Fatalf("secret lengths: alice=%d, bob=%d", len(aliceSecret), len(bobSecret))
	}
	for i := 0; i < 32; i++ {
		if aliceSecret[i] != bobSecret[i] {
			t.Fatalf("secrets differ at byte %d: alice=%02x, bob=%02x", i, aliceSecret[i], bobSecret[i])
		}
	}
}

func TestX3DHWithoutOneTimePrekey(t *testing.T) {
	ikA, ikAPub := genX25519Keypair()
	ikB, ikBPub := genX25519Keypair()

	edB_pub, edB_priv, _ := ed25519.GenerateKey(nil)
	spkB, spkBPriv, _ := GenerateSignedPrekey(edB_priv, edB_pub, 1, time.Now())
	var spkBPub [32]byte
	copy(spkBPub[:], spkB.PublicKey[:])

	_, ephPub, aliceSecret, err := X3DHInitiate(ikA, spkBPub, ikBPub, nil)
	if err != nil {
		t.Fatal(err)
	}

	bobSecret, err := X3DHRespond(ikB, spkBPriv, nil, ephPub, ikAPub, false)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 32; i++ {
		if aliceSecret[i] != bobSecret[i] {
			t.Fatalf("secrets differ at byte %d", i)
		}
	}
}

func TestX3DHDifferentPrekeysProduceDifferentSecrets(t *testing.T) {
	ikA, ikBPub := genX25519Keypair()

	edB_pub, edB_priv, _ := ed25519.GenerateKey(nil)

	spkB1, _, _ := GenerateSignedPrekey(edB_priv, edB_pub, 1, time.Now())
	var spkBPub1 [32]byte
	copy(spkBPub1[:], spkB1.PublicKey[:])
	_, _, secret1, _ := X3DHInitiate(ikA, spkBPub1, ikBPub, nil)

	spkB2, _, _ := GenerateSignedPrekey(edB_priv, edB_pub, 2, time.Now())
	var spkBPub2 [32]byte
	copy(spkBPub2[:], spkB2.PublicKey[:])
	_, _, secret2, _ := X3DHInitiate(ikA, spkBPub2, ikBPub, nil)

	same := true
	for i := 0; i < 32; i++ {
		if secret1[i] != secret2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("different prekeys produced identical shared secrets")
	}
}

func TestX25519RoundTrip(t *testing.T) {
	priv, pub := genX25519Keypair()
	shared, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(shared) != 32 {
		t.Errorf("shared secret len = %d, want 32", len(shared))
	}
}
