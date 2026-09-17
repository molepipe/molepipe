package chatstore

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// This is the disk analog of protocol's golden wire vectors: a FROZEN messages.enc
// produced by a known-good build, checked into testdata, that every future build
// must still open with all fields intact. It is the concrete gate for beta blocker
// #4 (upgrade survives existing accounts) — the richest structured on-disk surface,
// so the one most likely to silently break when a struct field is renamed, retyped,
// or reordered. A change that can no longer load this fixture is NOT a safe upgrade
// and must ship as a migration (a bumped fileVersion + a migrate step), never by
// editing the fixture to match the new code.
//
// messages.enc is AES-GCM only (no Argon2), so a frozen blob is cheap to open —
// unlike identity.enc, whose survival test generates at test time with weak params
// (see internal/identity/migration_survival_test.go).

// goldKey is the fixed 32-byte store key the fixture was sealed under. It is not a
// secret — the fixture holds only synthetic data — it just has to match at regen
// and load time.
var goldKey = func() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = 0x2a
	}
	return k
}()

const fixturePath = "testdata/messages_v1.enc"

func goldTime(sec int64) time.Time { return time.Unix(sec, 0).UTC() }

// goldData is the canonical fully-populated store state. INVARIANTS that keep the
// survival assertion a clean equality (normalize must be a no-op on it, since Load
// runs normalize): every contact has an explicit non-empty Status; every message
// has an explicit non-empty ID; and no Deleted tombstone matches a live message or
// outbox ID (so applyTombstones drops nothing). The tombstones are deliberately
// DANGLING — the realistic persisted case, where the message is already gone but
// the tombstone must survive to stop a sync from resurrecting it (chatstore.go
// documents why dropping one is a data-loss bug, not a cosmetic one).
func goldData() *Data {
	return &Data{
		Profile: Profile{
			DisplayName:           "Gold Tester",
			MailboxURL:            "goldmailboxabcdefghij234567.onion",
			AvatarHash:            "deadbeefcafe",
			AvatarBytes:           []byte{0x01, 0x02, 0x03, 0x04},
			UpdatedAt:             goldTime(1700000000),
			GroupImageBackupBytes: 4096,
		},
		Contacts: []Contact{
			{Account: "acctAAAA", Name: "Alice", Status: StatusAccepted, DHPub: []byte{1, 2, 3, 4}, MailboxURL: "m1.onion", AvatarHash: "a1hash", UpdatedAt: goldTime(1700000100), RelayGrant: true},
			{Account: "acctBBBB", Name: "Bob", Status: StatusPendingOut, ReqID: "req-1", UpdatedAt: goldTime(1700000200)},
			{Account: "acctCCCC", Name: "Carol", Status: StatusBlocked, RelayHolder: true, RelayReqID: "rr-9", RelayPending: true},
		},
		Messages: []Message{
			{Direction: "out", Peer: "acctAAAA", Text: "hello alice", At: goldTime(1700000300), ID: "msg-1"},
			{Direction: "in", Peer: "acctAAAA", Text: "hi back", At: goldTime(1700000360), ID: "msg-2", Reactions: []MessageReaction{{Emoji: "👍", By: "acctAAAA"}}},
			{Direction: "out", GroupID: "G-1", Author: "acctSELF", Text: "group hi", At: goldTime(1700000400), ID: "gmsg-1", AuthorSig: []byte{9, 9, 9}, Reactions: []MessageReaction{{Emoji: "🎉", By: "acctAAAA", At: 1700000450000000000, Sig: []byte{4, 4}}}},
			{Direction: "in", GroupID: "G-1", Author: "acctAAAA", At: goldTime(1700000500), ID: "gimg-1", Kind: KindImage, AttachID: "att-1", Mime: "image/jpeg", Size: 1234, ThumbID: "th-1", ThumbMime: "image/jpeg", FullHash: []byte{7, 7, 7}},
			{Direction: "out", Peer: "acctAAAA", Text: "a reply", At: goldTime(1700000550), ID: "msg-3", Delivery: DeliveryPending, ReplyID: "msg-2", ReplyPreview: "hi back", ReplyAuthor: "Alice"},
		},
		Groups: []Group{
			{ID: "G-1", Name: "Golden Group", Epoch: 5, Policy: InvitePolicyAdmins, Members: []GroupMember{
				{Account: "acctSELF", Role: GroupRoleAdmin, DHPub: []byte{1, 1}, Name: "Me"},
				{Account: "acctAAAA", Role: GroupRoleMember, CanInvite: true, DHPub: []byte{2, 2}, Name: "Alice"},
			}, Signer: "acctSELF", Sig: []byte{5, 5, 5}},
		},
		GroupInvites:     []GroupInvite{{GroupID: "G-2", Name: "Other Group", Inviter: "acctBBBB", ReqID: "gi-1", Accepted: true, At: goldTime(1700000600), Refusals: 2}},
		SentGroupInvites: []SentGroupInvite{{GroupID: "G-1", Account: "acctCCCC", ReqID: "sgi-1", At: goldTime(1700000700)}},
		Reads:            map[string]time.Time{"acctAAAA": goldTime(1700000800), "G-1": goldTime(1700000900)},
		Devices:          []Device{{PubKey: []byte{0xaa, 0xbb}, Name: "Laptop", AddedAt: goldTime(1700001000)}},
		PendingAccepts:   []PendingAccept{{Account: "acctBBBB", ReqID: "req-1", QueuedAt: goldTime(1700001100), Refusals: 1}},
		Outbox:           []OutboxItem{{ID: "out-1", To: "acctAAAA", Text: "queued msg", QueuedAt: goldTime(1700001200), Attempts: 2, ReplyID: "msg-1", ReplyPreview: "hello alice", ReplyAuthor: "Me"}},
		Deleted:          []string{"deleted-msg-gone-1", "deleted-msg-gone-2"},
	}
}

// TestRegenerateMessagesFixture rewrites testdata/messages_v1.enc from goldData().
// Guarded so it never runs in CI: regenerating would defeat the fixture's purpose
// (it must be the OLD build's bytes).
//
// STOP before you run this to "fix" a new field. Regenerating re-seals the fixture
// with TODAY's build, which silently neuters the gate — the survival test goes green
// because it is now reading bytes this same build just wrote, proving nothing about
// upgrade survival. Adding a field to goldData for a NEW format version means writing
// a SECOND fixture (messages_v2.enc) and keeping messages_v1.enc loading unchanged;
// the v1 fixture is a historical artifact and must never be rewritten to match new
// code. The only legitimate regen is a deliberate reset of the v1 baseline before any
// build has shipped it — which is not a situation you are in once this is committed.
//
//	CHATSTORE_REGEN_FIXTURE=1 go test ./internal/chatstore/ -run TestRegenerateMessagesFixture
func TestRegenerateMessagesFixture(t *testing.T) {
	if os.Getenv("CHATSTORE_REGEN_FIXTURE") != "1" {
		t.Skip("set CHATSTORE_REGEN_FIXTURE=1 to regenerate the frozen fixture")
	}
	tmp := t.TempDir()
	if err := New(tmp, goldKey).Save(goldData()); err != nil {
		t.Fatalf("seal fixture: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(tmp, fileName))
	if err != nil {
		t.Fatalf("read sealed fixture: %v", err)
	}
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatalf("mkdir testdata: %v", err)
	}
	if err := os.WriteFile(fixturePath, raw, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Logf("wrote %s (%d bytes) — commit it", fixturePath, len(raw))
}

// TestMessagesFixtureSurvives loads the frozen fixture on THIS build and asserts
// every field of goldData round-trips. This is the upgrade-survival gate: it fails
// the day a struct change can no longer read an older account's messages.enc.
func TestMessagesFixtureSurvives(t *testing.T) {
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture (regenerate with CHATSTORE_REGEN_FIXTURE=1): %v", err)
	}
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, fileName), raw, 0o600); err != nil {
		t.Fatalf("stage fixture: %v", err)
	}
	loaded, err := New(tmp, goldKey).Load()
	if err != nil {
		t.Fatalf("this build failed to LOAD an older messages.enc — upgrade would wipe the account: %v", err)
	}
	want := goldData()

	// Field-by-field so a drift names the exact field rather than dumping the whole
	// struct. Deleted and Outbox are called out because a silent drop there passes a
	// bare "did it load" check but loses data (a dropped tombstone resurrects deleted
	// messages on the next sync).
	check := func(name string, a, b any) {
		if !reflect.DeepEqual(a, b) {
			t.Errorf("field %s did not survive load:\n want %#v\n got  %#v", name, a, b)
		}
	}
	check("Profile", want.Profile, loaded.Profile)
	check("Contacts", want.Contacts, loaded.Contacts)
	check("Messages", want.Messages, loaded.Messages)
	check("Groups", want.Groups, loaded.Groups)
	check("GroupInvites", want.GroupInvites, loaded.GroupInvites)
	check("SentGroupInvites", want.SentGroupInvites, loaded.SentGroupInvites)
	check("Reads", want.Reads, loaded.Reads)
	check("Devices", want.Devices, loaded.Devices)
	check("PendingAccepts", want.PendingAccepts, loaded.PendingAccepts)
	check("Outbox", want.Outbox, loaded.Outbox)
	check("Deleted", want.Deleted, loaded.Deleted)
}
