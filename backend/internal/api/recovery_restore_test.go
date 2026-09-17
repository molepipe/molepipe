package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// TestRecoveryThenResyncRestoresFullState pins down what "seed-phrase recovery"
// actually is in this architecture, which is the subtle part: /api/recover
// rebuilds the IDENTITY only. There is no server-side escrow of chats, so the
// feature-set data (contacts, groups, avatar, mailbox config, history) comes
// back only by re-syncing from a surviving device. The recovered device comes
// up as a secondary precisely so it can pull that snapshot without colliding
// with the still-live primary's descriptor.
//
// The test therefore proves two things in sequence:
//  1. Negative: after recover-from-seed alone (no resync), the account is
//     restored but the data is empty — this is by design, not a bug, and a
//     naive "seed restores everything" expectation is wrong.
//  2. Positive: recover -> enroll (physical-access pairing) -> sync from the
//     surviving primary restores the FULL current feature set on the recovered
//     device, exercised through its real adopt path.
func TestRecoveryThenResyncRestoresFullState(t *testing.T) {
	// --- Primary A: unlocked and fully populated with every feature-set kind ---
	primary, id := syncPrimary(t)

	avatarBytes := []byte("\x89PNG\r\n\x1a\n-fake-but-nonempty-avatar-payload")
	avatarHash := chatstore.AvatarHashBytes(avatarBytes)

	primary.sessMu.Lock()
	primary.displayName = "Alice"
	primary.mailboxURL = "alicembx7abcdefghijklmnopqrstuvwxyz234567.onion"
	primary.avatarHash = avatarHash
	primary.avatarBytesOwn = avatarBytes
	// Non-zero so the whole-struct Profile LWW beats the recovered device's zero
	// profileAt; otherwise the merge would keep B's empty profile and the mailbox
	// / avatar assertions would fail in a way that looks like they didn't sync.
	primary.profileAt = time.Unix(5000, 0)
	if err := primary.avatarStore.Put(avatarHash, avatarBytes); err != nil {
		t.Fatalf("seed primary avatar store: %v", err)
	}
	primary.contacts["contactA"] = chatstore.Contact{
		Account: "contactA", Name: "A", Status: "accepted", UpdatedAt: time.Unix(1000, 0),
	}
	primary.groups["grp1"] = chatstore.Group{
		ID: "grp1", Name: "Team", Epoch: 1, Policy: "admin_only",
		Members: []chatstore.GroupMember{{Account: id.AccountNumber(), Role: "admin"}},
	}
	primary.messages = append(primary.messages,
		newChatMessage("in", "contactA", "", "hi from primary", time.Unix(1000, 0)))
	primary.persistLocked()
	primary.sessMu.Unlock()

	// --- Device B: a fresh, empty device that recovers A's identity from seed ---
	bStore, err := identity.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b := New(bStore, nil)
	if _, err := b.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Shutdown(nil) })

	body, _ := json.Marshal(map[string]string{"mnemonic": id.MnemonicString(), "password": "New-password1"})
	if r := b.do(t, "POST", "/api/recover", string(body), map[string]string{"Origin": b.origin()}); r.Code != http.StatusOK {
		t.Fatalf("recover: %d (%s)", r.Code, r.Body.String())
	}
	unlockWithPassword(t, b, "New-password1")

	// --- (1) Negative: seed alone restores the identity but no feature-set data ---
	b.sessMu.Lock()
	if b.myAccount != id.AccountNumber() {
		t.Errorf("recovery did not restore the account identity: got %q want %q", b.myAccount, id.AccountNumber())
	}
	if n := len(b.contacts); n != 0 {
		t.Errorf("seed-only recovery should have no contacts, got %d", n)
	}
	if n := len(b.groups); n != 0 {
		t.Errorf("seed-only recovery should have no groups, got %d", n)
	}
	if n := len(b.messages); n != 0 {
		t.Errorf("seed-only recovery should have no message history, got %d", n)
	}
	if b.mailboxURL != "" || b.avatarHash != "" {
		t.Errorf("seed-only recovery should have no profile data, got mailbox=%q avatar=%q", b.mailboxURL, b.avatarHash)
	}
	b.sessMu.Unlock()

	// --- Resync from the surviving primary ---
	dialer := syncFakeDialer{addr: primary.pubLn.Addr().String()}

	// B enrolls with A using a pairing secret (models physical access to the
	// primary during setup). Enrollment is required before /sync will serve B.
	secret := primary.pairSecrets.issue()
	bPub := b.device.PublicKey()
	if err := protocol.PairEnroll(context.Background(), dialer, id, bPub, "recovered-phone", secret); err != nil {
		t.Fatalf("pair enroll: %v", err)
	}

	// B pulls a snapshot and adopts it through its own real merge path, so the
	// assertions below check restored SESSION STATE, not just wire bytes.
	b.sessMu.Lock()
	bState, _ := json.Marshal(b.snapshotLocked())
	b.sessMu.Unlock()
	mergedJSON, err := protocol.SyncExchange(context.Background(), dialer, id, bPub, b.device.Sign, bState)
	if err != nil {
		t.Fatalf("sync exchange: %v", err)
	}
	var merged chatstore.Data
	if err := json.Unmarshal(mergedJSON, &merged); err != nil {
		t.Fatal(err)
	}
	b.sessMu.Lock()
	b.adoptDataLocked(&merged)
	b.sessMu.Unlock()

	// --- (2) Positive: the full feature set is now on the recovered device ---
	b.sessMu.Lock()
	defer b.sessMu.Unlock()

	if c, ok := b.contacts["contactA"]; !ok {
		t.Error("contact not restored after resync")
	} else if c.Status != "accepted" {
		t.Errorf("restored contact status = %q, want accepted", c.Status)
	}
	if g, ok := b.groups["grp1"]; !ok {
		t.Error("group not restored after resync")
	} else if g.Name != "Team" || len(g.Members) != 1 {
		t.Errorf("restored group = %+v, want Team with 1 member", g)
	}
	if b.mailboxURL != primary.mailboxURL {
		t.Errorf("mailbox config not restored: got %q want %q", b.mailboxURL, primary.mailboxURL)
	}
	if b.avatarHash != avatarHash {
		t.Errorf("avatar hash not restored: got %q want %q", b.avatarHash, avatarHash)
	}
	// The own-avatar BYTES must also land in B's store (mirrored from the synced
	// Profile), or B can advertise a hash it cannot actually serve or render.
	if b.avatarStore == nil || !b.avatarStore.Has(avatarHash) {
		t.Error("avatar bytes not restored into the recovered device's avatar store")
	}
	foundMsg := false
	for _, m := range b.messages {
		if m.Text == "hi from primary" {
			foundMsg = true
			break
		}
	}
	if !foundMsg {
		t.Error("chat history not restored after resync")
	}
}
