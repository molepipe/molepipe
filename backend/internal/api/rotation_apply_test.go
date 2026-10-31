package api

import (
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
)

// applyServer builds a minimal Server with one accepted contact at `old` and all
// account-keyed maps initialized, ready for hookOnAddressRotation.
func applyServer(old string, aliasIndex uint32) *Server {
	return &Server{
		contacts: map[string]chatstore.Contact{
			old: {Account: old, Status: chatstore.StatusAccepted, DHPub: dh(0x01), AliasIndex: aliasIndex},
		},
		messages:         []chatMessage{{ID: "m1", Peer: old}},
		reads:            map[string]time.Time{old: time.Unix(1, 0)},
		ratchetSessions:  map[string][]byte{old: []byte("s")},
		pendingInits:     map[string][]byte{},
		processedInits:   map[string][]byte{},
		pendingRotations: map[string]chatstore.RotationPending{},
		presence:         map[string]string{old: "online"},
		mailboxCheckedAt: map[string]time.Time{},
		outbox:           map[string]chatstore.OutboxItem{"m1": {ID: "m1", To: old}},
		pendingAccepts:   map[string]chatstore.PendingAccept{},
	}
}

// A newer-index rotation from an accepted contact migrates the contact to the new
// onion, advances the stored index, and moves per-peer state.
func TestOnAddressRotationApplies(t *testing.T) {
	const old, nw = "oldacct", "newacct"
	s := applyServer(old, 3)

	if err := s.hookOnAddressRotation(old, nw, 4); err != nil {
		t.Fatalf("apply: %v", err)
	}
	c, ok := s.contacts[nw]
	if !ok {
		t.Fatal("contact not migrated to new onion")
	}
	if c.AliasIndex != 4 {
		t.Errorf("AliasIndex = %d, want 4", c.AliasIndex)
	}
	if _, gone := s.contacts[old]; gone {
		t.Error("old contact key not removed")
	}
	if s.messages[0].Peer != nw {
		t.Error("message Peer not migrated")
	}
	if s.outbox["m1"].To != nw {
		t.Error("outbox To not migrated")
	}
}

// Delivery is ack-driven resend-until-acked, and a resend arrives addressed from
// the OLD alias (the sender keeps using the old-alias channel until we ack). After
// we've applied and migrated, that resend from `old` must still resolve to the
// migrated contact and succeed as a no-op so the peer gets its ack and stops.
func TestOnAddressRotationIdempotentResend(t *testing.T) {
	const old, nw = "oldacct", "newacct"
	s := applyServer(old, 3)
	if err := s.hookOnAddressRotation(old, nw, 4); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if got := s.peerAliases[old]; got != nw {
		t.Fatalf("peerAliases[%q] = %q, want %q (old alias not recorded)", old, got, nw)
	}
	// The realistic resend is still addressed FROM the old alias; it must resolve.
	if err := s.hookOnAddressRotation(old, nw, 4); err != nil {
		t.Fatalf("idempotent resend from old alias should succeed, got: %v", err)
	}
	if s.contacts[nw].AliasIndex != 4 {
		t.Errorf("AliasIndex changed on idempotent resend: %d", s.contacts[nw].AliasIndex)
	}
	if _, revived := s.contacts[old]; revived {
		t.Error("old contact key revived by the resend")
	}
}

// After a contact rotates and we migrate, an ordinary message (or a rotation
// resend) that still arrives addressed from their OLD alias must clear the
// contacts-only gate and find the migrated ratchet session — otherwise an ack-lost
// resend dies at the gate and session lookup, wedging delivery permanently.
func TestPeerAliasResolutionGateAndSession(t *testing.T) {
	const old, nw = "oldacct", "newacct"
	s := applyServer(old, 3)
	if err := s.hookOnAddressRotation(old, nw, 4); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// Gate: a message addressed from the retired alias resolves to the accepted
	// contact instead of being rejected as an unknown sender.
	s.sessMu.Lock()
	allowed := s.allowMessageLocked(old)
	s.sessMu.Unlock()
	if !allowed {
		t.Error("message from retired alias rejected by the contacts-only gate")
	}

	// Session lookup: the established session migrated to nw must be reachable via
	// the old-alias key the resend still carries.
	if got := s.resolvePeerAccount(old); got != nw {
		t.Errorf("resolvePeerAccount(%q) = %q, want %q", old, got, nw)
	}
	// A stranger and the current account both resolve to themselves.
	if got := s.resolvePeerAccount("stranger"); got != "stranger" {
		t.Errorf("stranger resolved to %q, want itself", got)
	}
	if got := s.resolvePeerAccount(nw); got != nw {
		t.Errorf("current account resolved to %q, want itself", got)
	}
}

// peerAliases must survive a restart: it is persisted (not session-local) so an
// ack-lost resend arriving after a process bounce still resolves. Round-trip it
// through snapshot -> adopt and confirm the mapping is intact.
func TestPeerAliasPersistRoundTrip(t *testing.T) {
	const old, nw = "oldacct", "newacct"
	s := applyServer(old, 3)
	if err := s.hookOnAddressRotation(old, nw, 4); err != nil {
		t.Fatalf("apply: %v", err)
	}

	s.sessMu.Lock()
	data := s.snapshotLocked()
	s.sessMu.Unlock()
	if data.PeerAliases[old] != nw {
		t.Fatalf("snapshot dropped peer alias: %v", data.PeerAliases)
	}

	// A fresh process adopts the persisted state and must resolve identically.
	restarted := &Server{}
	restarted.sessMu.Lock()
	restarted.adoptDataLocked(data)
	restarted.sessMu.Unlock()
	if got := restarted.resolvePeerAccount(old); got != nw {
		t.Errorf("after restart resolvePeerAccount(%q) = %q, want %q", old, got, nw)
	}
}

// A contact that rotates twice before we ack the first must resolve BOTH retired
// aliases forward to the current account — the chain is collapsed, not left dangling.
func TestPeerAliasChainCollapses(t *testing.T) {
	const a0, a1, a2 = "alias0", "alias1", "alias2"
	s := applyServer(a0, 3)
	if err := s.hookOnAddressRotation(a0, a1, 4); err != nil {
		t.Fatalf("rotate 0->1: %v", err)
	}
	if err := s.hookOnAddressRotation(a1, a2, 5); err != nil {
		t.Fatalf("rotate 1->2: %v", err)
	}
	if got := s.resolvePeerAccount(a0); got != a2 {
		t.Errorf("oldest alias %q resolved to %q, want current %q", a0, got, a2)
	}
	if got := s.resolvePeerAccount(a1); got != a2 {
		t.Errorf("alias %q resolved to %q, want current %q", a1, got, a2)
	}
	if _, ok := s.peerAliases[a2]; ok {
		t.Error("current account must not be an alias key")
	}
}

// A stale or replayed index (<= stored) must be rejected and change nothing.
func TestOnAddressRotationRejectsRollback(t *testing.T) {
	const old, nw = "oldacct", "newacct"
	for _, idx := range []uint32{3, 2, 0} { // equal, lower, zero — all <= stored 3
		s := applyServer(old, 3)
		if err := s.hookOnAddressRotation(old, nw, idx); err == nil {
			t.Errorf("index %d (<= 3) should be rejected", idx)
		}
		if _, ok := s.contacts[old]; !ok {
			t.Errorf("index %d: contact was migrated despite rollback", idx)
		}
		if _, ok := s.contacts[nw]; ok {
			t.Errorf("index %d: new contact created despite rollback", idx)
		}
	}
}

// A rotation naming an unknown or non-accepted contact must be refused.
func TestOnAddressRotationRejectsUnknown(t *testing.T) {
	s := applyServer("oldacct", 3)
	if err := s.hookOnAddressRotation("stranger", "newacct", 4); err == nil {
		t.Error("rotation from an unknown contact should be refused")
	}
	// A pending (not accepted) contact is not eligible either.
	s.contacts["pending"] = chatstore.Contact{Account: "pending", Status: chatstore.StatusPendingIn, DHPub: dh(0x05)}
	if err := s.hookOnAddressRotation("pending", "newacct", 4); err == nil {
		t.Error("rotation from a pending contact should be refused")
	}
}

// A rotation whose target already names another accepted contact must be refused
// rather than silently merging two people.
func TestOnAddressRotationRejectsTargetCollision(t *testing.T) {
	const old, nw = "oldacct", "newacct"
	s := applyServer(old, 3)
	s.contacts[nw] = chatstore.Contact{Account: nw, Status: chatstore.StatusAccepted, DHPub: dh(0x22)}
	if err := s.hookOnAddressRotation(old, nw, 4); err == nil {
		t.Error("rotation onto an existing contact should be refused")
	}
	if _, ok := s.contacts[old]; !ok {
		t.Error("old contact removed despite refused collision")
	}
}
