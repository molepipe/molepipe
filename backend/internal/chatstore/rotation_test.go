package chatstore

import (
	"testing"
	"time"
)

// A forward-only rotation: the device with the higher CurrentIndex wins as the
// current alias, and the loser's current alias is folded into history so a
// still-live old address is never dropped by a sync.
func TestMergeRotationForwardOnly(t *testing.T) {
	now := time.Now().UTC()
	old := &Data{Rotation: &RotationState{
		CurrentIndex:   2,
		CurrentAccount: "alias2",
		History:        []AliasRecord{{Index: 1, Account: "alias1", RetireAt: now.Add(24 * time.Hour)}},
	}}
	ahead := &Data{Rotation: &RotationState{
		CurrentIndex:   3,
		CurrentAccount: "alias3",
		History:        []AliasRecord{{Index: 2, Account: "alias2", RetireAt: now.Add(48 * time.Hour)}},
	}}

	m := Merge(old, ahead)
	if m.Rotation.CurrentIndex != 3 || m.Rotation.CurrentAccount != "alias3" {
		t.Fatalf("current alias = %d/%q, want 3/alias3", m.Rotation.CurrentIndex, m.Rotation.CurrentAccount)
	}
	// History must retain alias 1 (only the old side had it) and alias 2 (now
	// retired), but never the current alias 3.
	got := map[uint32]string{}
	for _, r := range m.Rotation.History {
		got[r.Index] = r.Account
	}
	if got[1] != "alias1" {
		t.Errorf("history lost alias 1: %+v", m.Rotation.History)
	}
	if got[2] != "alias2" {
		t.Errorf("history lost alias 2: %+v", m.Rotation.History)
	}
	if _, ok := got[3]; ok {
		t.Errorf("current alias 3 wrongly kept in history: %+v", m.Rotation.History)
	}
}

// Merging the same rotation across the two argument orders must converge — the
// winner is decided by index, not position.
func TestMergeRotationOrderIndependent(t *testing.T) {
	a := &Data{Rotation: &RotationState{CurrentIndex: 5, CurrentAccount: "a5"}}
	b := &Data{Rotation: &RotationState{CurrentIndex: 4, CurrentAccount: "a4"}}
	ab := Merge(a, b).Rotation
	ba := Merge(b, a).Rotation
	if ab.CurrentIndex != 5 || ba.CurrentIndex != 5 {
		t.Fatalf("current index not order-independent: ab=%d ba=%d", ab.CurrentIndex, ba.CurrentIndex)
	}
	if ab.CurrentAccount != "a5" || ba.CurrentAccount != "a5" {
		t.Fatalf("current account not order-independent: ab=%q ba=%q", ab.CurrentAccount, ba.CurrentAccount)
	}
}

// A nil rotation on either side must not clobber a set one, and two nils stay nil.
func TestMergeRotationNilHandling(t *testing.T) {
	set := &Data{Rotation: &RotationState{CurrentIndex: 1, CurrentAccount: "a1"}}
	none := &Data{}

	if m := Merge(set, none); m.Rotation == nil || m.Rotation.CurrentIndex != 1 {
		t.Errorf("nil clobbered a set rotation: %+v", m.Rotation)
	}
	if m := Merge(none, set); m.Rotation == nil || m.Rotation.CurrentIndex != 1 {
		t.Errorf("nil clobbered a set rotation (reversed): %+v", m.Rotation)
	}
	if m := Merge(none, none); m.Rotation != nil {
		t.Errorf("two nils produced a non-nil rotation: %+v", m.Rotation)
	}
}

// When both sides carry the same-index record, the later RetireAt survives so a
// grace window is never shortened by a stale sync.
func TestMergeRotationKeepsLaterRetireAt(t *testing.T) {
	now := time.Now().UTC()
	early := &Data{Rotation: &RotationState{
		CurrentIndex:   2,
		CurrentAccount: "a2",
		History:        []AliasRecord{{Index: 1, Account: "a1", RetireAt: now.Add(1 * time.Hour)}},
	}}
	late := &Data{Rotation: &RotationState{
		CurrentIndex:   2,
		CurrentAccount: "a2",
		History:        []AliasRecord{{Index: 1, Account: "a1", RetireAt: now.Add(72 * time.Hour)}},
	}}
	m := Merge(early, late)
	if len(m.Rotation.History) != 1 {
		t.Fatalf("history size = %d, want 1", len(m.Rotation.History))
	}
	if !m.Rotation.History[0].RetireAt.Equal(now.Add(72 * time.Hour)) {
		t.Errorf("kept the earlier RetireAt: %v", m.Rotation.History[0].RetireAt)
	}
}
