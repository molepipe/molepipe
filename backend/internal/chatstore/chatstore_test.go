package chatstore

import (
	"bytes"
	"crypto/rand"
	"os"
	"testing"
	"time"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, testKey(t))

	// Missing file loads as empty.
	d0, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(d0.Contacts) != 0 || len(d0.Messages) != 0 {
		t.Fatal("expected empty data for missing file")
	}

	want := &Data{
		Contacts: []Contact{{Account: "abc", Name: "Alice"}},
		Messages: []Message{{Direction: "in", Peer: "abc", Text: "hi", At: time.Now().UTC().Round(time.Second)}},
	}
	if err := s.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Contacts) != 1 || got.Contacts[0].Name != "Alice" {
		t.Errorf("contacts round trip: %+v", got.Contacts)
	}
	if len(got.Messages) != 1 || got.Messages[0].Text != "hi" {
		t.Errorf("messages round trip: %+v", got.Messages)
	}
}

func TestWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	New(dir, testKey(t)).Save(&Data{Messages: []Message{{Text: "secret"}}})
	if _, err := New(dir, testKey(t)).Load(); err == nil {
		t.Fatal("decrypted with a different key")
	}
}

func TestNoPlaintextOnDisk(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, testKey(t))
	if err := s.Save(&Data{
		Contacts: []Contact{{Account: "acct", Name: "SecretName"}},
		Messages: []Message{{Text: "SecretMessageBody"}},
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"SecretName", "SecretMessageBody"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("%q found in cleartext on disk", secret)
		}
	}
}

func TestFilePermissions(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, testKey(t))
	if err := s.Save(&Data{}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 600", perm)
	}
}

func TestMessageIDBackfillDeterministic(t *testing.T) {
	at := time.Date(2026, 8, 4, 12, 0, 0, 123456789, time.UTC)
	// Deterministic: same content -> same ID; different content -> different ID.
	id1 := MessageID("in", "acct", "hello", at)
	if id1 == "" {
		t.Fatal("empty id")
	}
	if id1 != MessageID("in", "acct", "hello", at) {
		t.Fatal("MessageID not deterministic")
	}
	if id1 == MessageID("out", "acct", "hello", at) {
		t.Fatal("direction did not affect id")
	}
	if id1 == MessageID("in", "acct", "hello ", at) {
		t.Fatal("text boundary aliased")
	}

	// normalize backfills empty IDs and leaves existing ones untouched.
	d := &Data{Messages: []Message{
		{Direction: "in", Peer: "acct", Text: "hello", At: at},
		{Direction: "out", Peer: "acct", Text: "hi", At: at, ID: "preset"},
	}}
	d.normalize()
	if d.Messages[0].ID != id1 {
		t.Fatalf("backfill mismatch: got %q want %q", d.Messages[0].ID, id1)
	}
	if d.Messages[1].ID != "preset" {
		t.Fatal("normalize overwrote an existing id")
	}

	// Idempotent: a second device backfilling the same message agrees.
	d2 := &Data{Messages: []Message{{Direction: "in", Peer: "acct", Text: "hello", At: at}}}
	d2.normalize()
	if d2.Messages[0].ID != d.Messages[0].ID {
		t.Fatal("two independent backfills disagreed")
	}
}

func TestMergeMessagesUnionByID(t *testing.T) {
	at := time.Now().UTC()
	a := &Data{Messages: []Message{{Direction: "in", Peer: "p", Text: "one", At: at}}}
	b := &Data{Messages: []Message{
		{Direction: "in", Peer: "p", Text: "one", At: at}, // dup of a's (same content id)
		{Direction: "out", Peer: "p", Text: "two", At: at.Add(time.Second)},
	}}
	m := Merge(a, b)
	if len(m.Messages) != 2 {
		t.Fatalf("union size = %d, want 2", len(m.Messages))
	}
	// Sorted by time: "one" (at) before "two" (at+1s).
	if m.Messages[0].Text != "one" || m.Messages[1].Text != "two" {
		t.Fatalf("merge order wrong: %+v", m.Messages)
	}
	// Idempotent: merging the result with either side adds nothing.
	if again := Merge(m, a); len(again.Messages) != 2 {
		t.Fatalf("merge not idempotent: %d", len(again.Messages))
	}
}

// TestReactionMergeLWW is the load-bearing convergence test for group reactions
// (build 4). The invariants, in the order they'd bite:
//   - a 1:1 legacy reaction (zero At, no tombstone) is NEVER erased by a merge —
//     the case that would silently drop a reaction the old code placed;
//   - a group un-react (tombstone, At = t2) beats a stale add (At = t1 < t2) no
//     matter which side of the merge it is on — the resurrection bug this whole
//     design exists to prevent;
//   - a re-added reaction (At = t3 > t2) beats the tombstone, so re-reacting works.
func TestReactionMergeLWW(t *testing.T) {
	mergeRx := func(a, b []MessageReaction) []MessageReaction { return unionReactions(a, b) }

	// 1:1 legacy add (zero At, no Sig) survives a union with an empty set and with
	// a copy of itself — never dropped, never duplicated.
	legacy := []MessageReaction{{Emoji: "👍", By: "alice"}}
	if got := mergeRx(legacy, nil); len(got) != 1 || got[0].Removed {
		t.Fatalf("legacy 1:1 reaction lost across merge: %+v", got)
	}
	if got := mergeRx(legacy, legacy); len(got) != 1 {
		t.Fatalf("legacy reaction duplicated on self-merge: %+v", got)
	}

	// Group: an un-react at t2 must win over the add at t1 in BOTH merge orders.
	add := []MessageReaction{{Emoji: "❤️", By: "bob", At: 100, Sig: []byte{1}}}
	tomb := []MessageReaction{{Emoji: "❤️", By: "bob", At: 200, Removed: true, Sig: []byte{2}}}
	for _, order := range [][2][]MessageReaction{{add, tomb}, {tomb, add}} {
		got := mergeRx(order[0], order[1])
		if len(got) != 1 || !got[0].Removed || got[0].At != 200 {
			t.Fatalf("stale add resurrected the reaction (order %v): %+v", order, got)
		}
		if len(LiveReactions(got)) != 0 {
			t.Fatalf("tombstone rendered as live: %+v", got)
		}
	}

	// Re-reacting after a remove (t3 > t2) wins the tombstone back to live.
	readd := []MessageReaction{{Emoji: "❤️", By: "bob", At: 300, Sig: []byte{3}}}
	got := mergeRx(tomb, readd)
	if len(got) != 1 || got[0].Removed || got[0].At != 300 {
		t.Fatalf("re-react did not beat the tombstone: %+v", got)
	}
	if len(LiveReactions(got)) != 1 {
		t.Fatalf("re-reacted reaction not live: %+v", got)
	}

	// AddReaction over a tombstoned key must revive it in place, never append a
	// second entry under the same (emoji, by) — a duplicate key would break the
	// single-entry invariant ApplyGroupReaction relies on.
	revived := AddReaction([]MessageReaction{{Emoji: "❤️", By: "bob", At: 200, Removed: true, Sig: []byte{2}}}, "❤️", "bob")
	if len(revived) != 1 || revived[0].Removed {
		t.Fatalf("AddReaction over a tombstone did not revive in place: %+v", revived)
	}
}

func TestMergeReadsMaxPerAccount(t *testing.T) {
	early := time.Unix(1000, 0)
	late := time.Unix(2000, 0)
	a := &Data{Reads: map[string]time.Time{"x": late, "y": early}}
	b := &Data{Reads: map[string]time.Time{"x": early, "z": late}}
	m := Merge(a, b)
	if !m.Reads["x"].Equal(late) { // must keep the LATER read, not overwrite
		t.Errorf("reads[x] = %v, want %v (max)", m.Reads["x"], late)
	}
	if !m.Reads["y"].Equal(early) || !m.Reads["z"].Equal(late) {
		t.Errorf("reads merge lost an account: %+v", m.Reads)
	}
}

func TestMergeContactsLWW(t *testing.T) {
	old := time.Unix(100, 0)
	recent := time.Unix(200, 0)
	a := &Data{Contacts: []Contact{{Account: "c", Name: "Old", Status: "accepted", UpdatedAt: old}}}
	b := &Data{Contacts: []Contact{{Account: "c", Name: "New", Status: "blocked", UpdatedAt: recent}}}
	m := Merge(a, b)
	if len(m.Contacts) != 1 || m.Contacts[0].Name != "New" || m.Contacts[0].Status != "blocked" {
		t.Fatalf("LWW picked wrong contact: %+v", m.Contacts)
	}

	// Zero UpdatedAt is oldest: a device that explicitly touched the record wins.
	z := &Data{Contacts: []Contact{{Account: "c", Name: "Zero", Status: "accepted"}}} // zero time
	nonzero := &Data{Contacts: []Contact{{Account: "c", Name: "Touched", Status: "accepted", UpdatedAt: recent}}}
	if got := Merge(z, nonzero); got.Contacts[0].Name != "Touched" {
		t.Errorf("zero-time did not lose: %+v", got.Contacts)
	}
	if got := Merge(nonzero, z); got.Contacts[0].Name != "Touched" {
		t.Errorf("zero-time won when it was the second arg: %+v", got.Contacts)
	}
}

func TestMergeProfileAndDevices(t *testing.T) {
	a := &Data{
		Profile: Profile{DisplayName: "A", UpdatedAt: time.Unix(1, 0)},
		Devices: []Device{{PubKey: []byte{1}, Name: "phone", AddedAt: time.Unix(1, 0)}},
	}
	b := &Data{
		Profile: Profile{DisplayName: "B", UpdatedAt: time.Unix(2, 0)},
		Devices: []Device{{PubKey: []byte{1}}, {PubKey: []byte{2}, Name: "desktop"}},
	}
	m := Merge(a, b)
	if m.Profile.DisplayName != "B" { // later UpdatedAt wins
		t.Errorf("profile LWW = %q, want B", m.Profile.DisplayName)
	}
	if len(m.Devices) != 2 { // union by pubkey (device {1} not duplicated)
		t.Fatalf("device union = %d, want 2", len(m.Devices))
	}
}

// TestGroupImageMessageIDDistinct guards gossip dedup: an image id never collides
// with a text id, and two different images (different full hashes) get different
// ids even from the same author at the same instant — while the same image is
// stable (idempotent dedup).
func TestGroupImageMessageIDDistinct(t *testing.T) {
	at := time.Unix(1000, 0)
	h1 := make([]byte, 32)
	h2 := make([]byte, 32)
	h2[0] = 1
	img1 := GroupImageMessageID("g", "author", at, h1)
	img1b := GroupImageMessageID("g", "author", at, h1)
	img2 := GroupImageMessageID("g", "author", at, h2)
	txt := GroupMessageID("g", "author", "", at) // empty-text message at the same instant

	if img1 != img1b {
		t.Fatal("same image is not stable")
	}
	if img1 == img2 {
		t.Fatal("different images (different full hash) collide")
	}
	if img1 == txt || img2 == txt {
		t.Fatal("an image id collides with a text id")
	}
}
