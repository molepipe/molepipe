package protocol

import (
	"bytes"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

// TestSelfBackupRoundTrip proves the self-sealed backup envelope decrypts on the
// same owner's device: recipient == sender == owner, and the shared secret is
// SharedSecret(myDH.Private, myDH.Public), which only the owner's key rederives.
func TestSelfBackupRoundTrip(t *testing.T) {
	owner, _ := identity.New()
	data := bytes.Repeat([]byte{0x7E}, 150_000)

	env, err := SealSelfBackupImage(owner, "gimg-1", "image/jpeg", data, time.Unix(2000, 0))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if env.Recipient != owner.AccountNumber() || env.Sender != owner.AccountNumber() {
		t.Fatalf("backup not self-addressed: recipient=%q sender=%q", env.Recipient, env.Sender)
	}
	if !env.VerifySignature() {
		t.Fatal("self-backup envelope failed its own signature check")
	}

	c, err := OpenMailContent(owner, env)
	if err != nil {
		t.Fatalf("open on owner device: %v", err)
	}
	if c.Kind != MailKindImage || c.MsgID != "gimg-1" || c.Mime != "image/jpeg" || !bytes.Equal(c.Data, data) {
		t.Fatalf("self-backup round-trip mismatch: kind=%q id=%q mime=%q bytes=%d", c.Kind, c.MsgID, c.Mime, len(c.Data))
	}
}

// TestSelfBackupOpaqueToOthers proves a self-sealed backup is undecryptable by any
// other identity even though the envelope is (by construction) self-addressed: a
// different device cannot pose as the recipient, and the DH secret is the owner's
// alone.
func TestSelfBackupOpaqueToOthers(t *testing.T) {
	owner, _ := identity.New()
	other, _ := identity.New()

	env, err := SealSelfBackupImage(owner, "gimg-1", "image/png", []byte{1, 2, 3, 4}, time.Unix(2000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenMailContent(other, env); err == nil {
		t.Fatal("a foreign identity opened the owner's self-backup")
	}
}
