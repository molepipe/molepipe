package chatstore

import (
	"testing"
	"time"
)

// TestGroupMessageIDDeterministicAndDistinct: the group id must be identical for
// every member regardless of their local Direction/Peer (so gossip de-dupes),
// and can never collide with a 1:1 MessageID (domain separation).
func TestGroupMessageIDDeterministicAndDistinct(t *testing.T) {
	at := time.Unix(1_700_000_000, 123).UTC()

	// Same content, different local viewpoints → same id.
	authorView := Message{Direction: "out", GroupID: "grp", Author: "alice", Text: "hi", At: at}
	peerView := Message{Direction: "in", Peer: "alice", GroupID: "grp", Author: "alice", Text: "hi", At: at}
	if authorView.syncID() != peerView.syncID() {
		t.Fatalf("group id differs by viewpoint: %s vs %s", authorView.syncID(), peerView.syncID())
	}
	if authorView.syncID() != GroupMessageID("grp", "alice", "hi", at) {
		t.Fatal("syncID did not use GroupMessageID for a group message")
	}

	// A 1:1 message with matching-looking fields must get a DIFFERENT id.
	oneToOne := Message{Direction: "out", Peer: "grp", Text: "hi", At: at}
	if oneToOne.syncID() == authorView.syncID() {
		t.Fatal("group and 1:1 ids collided — domain separation is broken")
	}
	if oneToOne.syncID() != MessageID("out", "grp", "hi", at) {
		t.Fatal("syncID did not use MessageID for a 1:1 message")
	}
}

// TestMergeGroupsAndMessages: groups union by id with the higher epoch winning,
// and a group message that two members hold from different viewpoints collapses
// to one on merge.
func TestMergeGroupsAndMessages(t *testing.T) {
	at := time.Unix(1_700_000_500, 0).UTC()

	a := &Data{
		Groups: []Group{
			{ID: "g1", Name: "old name", Epoch: 1, Policy: InvitePolicyAdmins,
				Members: []GroupMember{{Account: "alice", Role: GroupRoleAdmin}}},
			{ID: "g2", Name: "only in a", Epoch: 3},
		},
		Messages: []Message{{Direction: "out", GroupID: "g1", Author: "alice", Text: "hey all", At: at}},
	}
	b := &Data{
		Groups: []Group{
			{ID: "g1", Name: "new name", Epoch: 2, Policy: InvitePolicyEveryone,
				Members: []GroupMember{{Account: "alice", Role: GroupRoleAdmin}, {Account: "bob", Role: GroupRoleMember}}},
		},
		// Same message, seen as inbound from the other side.
		Messages: []Message{{Direction: "in", Peer: "alice", GroupID: "g1", Author: "alice", Text: "hey all", At: at}},
	}

	out := Merge(a, b)

	// g1: higher epoch (2) wins.
	var g1 *Group
	for i := range out.Groups {
		if out.Groups[i].ID == "g1" {
			g1 = &out.Groups[i]
		}
	}
	if g1 == nil {
		t.Fatal("g1 missing after merge")
	}
	if g1.Epoch != 2 || g1.Name != "new name" || len(g1.Members) != 2 {
		t.Fatalf("g1 did not take the higher-epoch roster: %+v", *g1)
	}
	if len(out.Groups) != 2 {
		t.Fatalf("expected g1+g2 after union, got %d groups", len(out.Groups))
	}

	// The group message collapses to a single copy.
	n := 0
	for _, m := range out.Messages {
		if m.GroupID == "g1" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("group message did not de-dupe across viewpoints: %d copies", n)
	}
}

// TestMergeRosterTiebreak: when two devices hold different rosters for the same
// group, Merge picks the higher epoch, and at an equal epoch a deterministic
// signature-byte comparison — so both devices converge on the same roster
// instead of keeping whichever they saw first.
func TestMergeRosterTiebreak(t *testing.T) {
	hi := Group{ID: "g", Epoch: 5, Sig: []byte{0x01}}
	lo := Group{ID: "g", Epoch: 4, Sig: []byte{0xff}}
	got := Merge(&Data{Groups: []Group{lo}}, &Data{Groups: []Group{hi}})
	if len(got.Groups) != 1 || got.Groups[0].Epoch != 5 {
		t.Fatalf("higher epoch did not win: %+v", got.Groups)
	}

	// Equal epoch: the greater signature bytes win, regardless of merge order.
	a := Group{ID: "g", Epoch: 5, Sig: []byte{0x02}, Name: "A"}
	b := Group{ID: "g", Epoch: 5, Sig: []byte{0x09}, Name: "B"}
	ab := Merge(&Data{Groups: []Group{a}}, &Data{Groups: []Group{b}})
	ba := Merge(&Data{Groups: []Group{b}}, &Data{Groups: []Group{a}})
	if ab.Groups[0].Name != "B" || ba.Groups[0].Name != "B" {
		t.Fatalf("equal-epoch tiebreak not order-independent: ab=%s ba=%s", ab.Groups[0].Name, ba.Groups[0].Name)
	}
}
