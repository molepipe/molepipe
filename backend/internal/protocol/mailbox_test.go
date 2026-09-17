package protocol

import (
	"crypto/ed25519"
	"encoding/binary"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

func TestMailEnvelopeRoundTrip(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	sentAt := time.Unix(1_700_000_000, 0)

	m, err := SealMailEnvelope(alice, bob.AccountNumber(), bob.Keys.DH.Public, "mid-1", "offline hi", sentAt)
	if err != nil {
		t.Fatal(err)
	}
	sender, _, text, gotAt, err := OpenMailEnvelope(bob, m)
	if err != nil {
		t.Fatal(err)
	}
	if sender != alice.AccountNumber() || text != "offline hi" || !gotAt.Equal(sentAt) {
		t.Fatalf("round-trip mismatch: sender=%s text=%q at=%v", sender, text, gotAt)
	}
}

func TestMailEnvelopeTamperRejected(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	base, _ := SealMailEnvelope(alice, bob.AccountNumber(), bob.Keys.DH.Public, "mid-1", "hi", time.Unix(1, 0))

	// Tamper with each authenticated field; every mutation must be rejected.
	mutations := map[string]func(m *MailEnvelope){
		"box":       func(m *MailEnvelope) { m.Box[0] ^= 0xff },
		"sent_at":   func(m *MailEnvelope) { m.SentAt++ },
		"recipient": func(m *MailEnvelope) { c, _ := identity.New(); m.Recipient = c.AccountNumber() },
		"sender_dh": func(m *MailEnvelope) { m.SenderDHPub[0] ^= 0xff },
	}
	for name, mutate := range mutations {
		m := base // copy
		m.Box = append([]byte(nil), base.Box...)
		m.SenderDHPub = append([]byte(nil), base.SenderDHPub...)
		mutate(&m)
		if _, _, _, _, err := OpenMailEnvelope(bob, m); err == nil {
			t.Errorf("mutation %q was accepted", name)
		}
	}
}

// TestMailEnvelopeLabelIsolation is the security-critical one: a signature made
// over the mailbox content but with the DIRECT-message label must not be
// accepted by the mailbox path. If it were, a captured direct message could be
// replayed as a valid drop-off.
func TestMailEnvelopeLabelIsolation(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	m, _ := SealMailEnvelope(alice, bob.AccountNumber(), bob.Keys.DH.Public, "mid-1", "hi", time.Unix(1, 0))

	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(m.SentAt))
	// Same fields, wrong label ("message" instead of "mailbox-message").
	directLabelBlob := signBlob([]byte(sigContext), []byte("message"), []byte(m.Recipient), m.SenderDHPub, ts[:], m.Box)
	m.Sig = ed25519.Sign(alice.Keys.Signing.Private, directLabelBlob)

	if _, _, _, _, err := OpenMailEnvelope(bob, m); err == nil {
		t.Fatal("a direct-labelled signature verified as a mailbox envelope")
	}
}

func TestMailEnvelopeIDStable(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	at := time.Unix(42, 0)

	m1, _ := SealMailEnvelope(alice, bob.AccountNumber(), bob.Keys.DH.Public, "mid-1", "same", at)
	// A replay is byte-identical, so its ID must match (collapses on ingest).
	replay := m1
	if replay.ID() != m1.ID() {
		t.Fatal("replay produced a different ID")
	}
	// Different content ⇒ different ID.
	m2, _ := SealMailEnvelope(alice, bob.AccountNumber(), bob.Keys.DH.Public, "mid-1", "other", at)
	if m2.ID() == m1.ID() {
		t.Fatal("distinct messages collided on ID")
	}
	if m1.ID() == "" {
		t.Fatal("empty ID")
	}
}
