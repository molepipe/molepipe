package api

import (
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
)

// fullyPopulatedServer builds a Server with an entry under `old` in EVERY
// account-keyed structure migratePeerAccountLocked must move, plus one unrelated
// contact and one group referencing `old` to prove non-targets are untouched.
func fullyPopulatedServer(old string) *Server {
	return &Server{
		contacts: map[string]chatstore.Contact{
			old:     {Account: old, Status: chatstore.StatusAccepted, DHPub: dh(0x01), AliasIndex: 2},
			"other": {Account: "other", Status: chatstore.StatusAccepted, DHPub: dh(0x02)},
		},
		messages: []chatMessage{
			{ID: "m1", Peer: old, Text: "hi"},
			{ID: "m2", Peer: "other", Text: "unrelated"},
		},
		reads:            map[string]time.Time{old: time.Unix(100, 0), "other": time.Unix(1, 0)},
		pendingAccepts:   map[string]chatstore.PendingAccept{old: {Account: old, ReqID: "r1"}},
		outbox:           map[string]chatstore.OutboxItem{"m1": {ID: "m1", To: old}, "u": {ID: "u", To: "other"}},
		ratchetSessions:  map[string][]byte{old: []byte("sess")},
		pendingInits:     map[string][]byte{old: []byte("init")},
		processedInits:   map[string][]byte{old: []byte("sig")},
		pendingRotations: map[string]chatstore.RotationPending{old: {NewOnion: "n", AliasIndex: 1}},
		presence:         map[string]string{old: "online"},
		mailboxCheckedAt: map[string]time.Time{old: time.Unix(50, 0)},
		// A group whose roster references old — must be LEFT ALONE (groups excluded).
		groups: map[string]chatstore.Group{
			"g1": {ID: "g1", Members: []chatstore.GroupMember{{Account: old}}},
		},
	}
}

func TestMigratePeerAccountExhaustive(t *testing.T) {
	const old, nw = "oldacct", "newacct"
	s := fullyPopulatedServer(old)

	if !s.migratePeerAccountLocked(old, nw) {
		t.Fatal("migrate reported nothing moved")
	}

	// Nothing may still reference old across the account-keyed maps.
	if _, ok := s.contacts[old]; ok {
		t.Error("contacts still has old")
	}
	if _, ok := s.reads[old]; ok {
		t.Error("reads still has old")
	}
	if _, ok := s.pendingAccepts[old]; ok {
		t.Error("pendingAccepts still has old")
	}
	if _, ok := s.ratchetSessions[old]; ok {
		t.Error("ratchetSessions still has old")
	}
	if _, ok := s.pendingInits[old]; ok {
		t.Error("pendingInits still has old")
	}
	if _, ok := s.processedInits[old]; ok {
		t.Error("processedInits still has old")
	}
	if _, ok := s.pendingRotations[old]; ok {
		t.Error("pendingRotations still has old")
	}
	if _, ok := s.presence[old]; ok {
		t.Error("presence still has old")
	}
	if _, ok := s.mailboxCheckedAt[old]; ok {
		t.Error("mailboxCheckedAt still has old")
	}

	// Everything must now be reachable under new (and embedded fields rewritten).
	c, ok := s.contacts[nw]
	if !ok || c.Account != nw {
		t.Errorf("contact not moved to new / Account not rewritten: %+v", c)
	}
	if c.AliasIndex != 2 || len(c.DHPub) != 32 {
		t.Error("migrated contact lost its DHPub/AliasIndex")
	}
	if pa, ok := s.pendingAccepts[nw]; !ok || pa.Account != nw {
		t.Errorf("pendingAccept not moved / Account not rewritten: %+v", pa)
	}
	if s.outbox["m1"].To != nw {
		t.Errorf("outbox item To not rewritten: %q", s.outbox["m1"].To)
	}
	if _, ok := s.reads[nw]; !ok {
		t.Error("reads not moved to new")
	}
	if _, ok := s.presence[nw]; !ok {
		t.Error("presence not moved to new")
	}

	// message.Peer rewritten for the target, untouched for the unrelated peer.
	var got string
	for _, m := range s.messages {
		if m.ID == "m1" {
			got = m.Peer
		}
		if m.ID == "m2" && m.Peer != "other" {
			t.Error("unrelated message Peer was rewritten")
		}
	}
	if got != nw {
		t.Errorf("message m1 Peer = %q, want %q", got, nw)
	}

	// Unrelated contact and outbox item untouched.
	if _, ok := s.contacts["other"]; !ok {
		t.Error("unrelated contact was dropped")
	}
	if s.outbox["u"].To != "other" {
		t.Error("unrelated outbox item was rewritten")
	}

	// Groups are excluded: the roster must still reference old.
	if s.groups["g1"].Members[0].Account != old {
		t.Error("group roster was rewritten — groups must be excluded from rotation")
	}
}

// A second migration with old already gone must be a clean no-op (idempotent).
func TestMigratePeerAccountIdempotent(t *testing.T) {
	const old, nw = "oldacct", "newacct"
	s := fullyPopulatedServer(old)
	s.migratePeerAccountLocked(old, nw)
	if s.migratePeerAccountLocked(old, nw) {
		t.Error("second migration reported a move; should be a no-op")
	}
	if _, ok := s.contacts[nw]; !ok {
		t.Error("new contact vanished after a repeated migration")
	}
}

// A pre-existing entry under new must never be clobbered — and on collision the
// old entry must be PRESERVED, not silently dropped (which would destroy the
// peer's session/reads with no re-establish path).
func TestMigratePeerAccountCollisionSafe(t *testing.T) {
	const old, nw = "oldacct", "newacct"
	s := fullyPopulatedServer(old)
	// Pre-seed new with a distinct ratchet session; migration must not overwrite it.
	s.ratchetSessions[nw] = []byte("preexisting")
	s.contacts[nw] = chatstore.Contact{Account: nw, Status: chatstore.StatusAccepted, DHPub: dh(0x09)}

	s.migratePeerAccountLocked(old, nw)

	if string(s.ratchetSessions[nw]) != "preexisting" {
		t.Error("migration clobbered a pre-existing ratchet session under new")
	}
	if string(s.ratchetSessions[old]) != "sess" {
		t.Error("old ratchet session dropped on collision — state must be preserved, not destroyed")
	}
	if string(s.contacts[nw].DHPub) != string(dh(0x09)) {
		t.Error("migration clobbered a pre-existing contact under new")
	}
	if _, ok := s.contacts[old]; !ok {
		t.Error("old contact dropped on collision — must be preserved")
	}
}

// Guard rails: no-op for empty args or a self-migration.
func TestMigratePeerAccountNoop(t *testing.T) {
	s := fullyPopulatedServer("oldacct")
	if s.migratePeerAccountLocked("oldacct", "oldacct") {
		t.Error("self-migration should be a no-op")
	}
	if s.migratePeerAccountLocked("", "newacct") || s.migratePeerAccountLocked("oldacct", "") {
		t.Error("empty account should be a no-op")
	}
}
