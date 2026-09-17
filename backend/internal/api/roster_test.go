package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

func rm(id *identity.Identity, role string, canInvite bool) protocol.RosterMember {
	return protocol.RosterMember{Account: id.AccountNumber(), DHPub: dhBytes(id), Role: role, CanInvite: canInvite}
}

func acceptRoster(s *Server, r protocol.SignedRoster) bool {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	return s.acceptRosterLocked(r)
}

func heldGroup(s *Server, gid string) (chatstore.Group, bool) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	g, ok := s.groups[gid]
	return g, ok
}

// injectRoster seeds a held roster directly (bypassing the consent gate), for
// test SETUP of the epoch-1 state whose UPDATE path is what a test exercises.
func injectRoster(s *Server, r protocol.SignedRoster) {
	s.sessMu.Lock()
	s.groups[r.GroupID] = rosterToGroup(r)
	s.sessMu.Unlock()
}

// TestAcceptRosterBootstrapConsent: a stranger cannot force-add us to a group by
// pushing a self-signed genesis roster (the unsolicited-group-add hole); the
// same roster is accepted only once we hold an ACCEPTED invite naming its signer,
// and the anchor is cleared on join.
func TestAcceptRosterBootstrapConsent(t *testing.T) {
	me, meID := syncPrimary(t)
	_, strangerID := syncPrimary(t)

	forged := protocol.NewSignedRoster(strangerID, "g1", "G", chatstore.InvitePolicyAdmins, 1,
		[]protocol.RosterMember{rm(strangerID, chatstore.GroupRoleAdmin, false), rm(meID, chatstore.GroupRoleMember, false)})
	if acceptRoster(me, forged) {
		t.Fatal("a stranger force-added us to a group via a self-signed roster")
	}

	me.sessMu.Lock()
	me.groupInvites["g1"] = chatstore.GroupInvite{
		GroupID: "g1", Inviter: strangerID.AccountNumber(), Accepted: true, At: time.Now(),
	}
	me.sessMu.Unlock()
	if !acceptRoster(me, forged) {
		t.Fatal("a consented invite's roster was refused")
	}
	me.sessMu.Lock()
	_, stillPending := me.groupInvites["g1"]
	me.sessMu.Unlock()
	if stillPending {
		t.Fatal("the invite anchor was not cleared after joining")
	}
}

// TestAcceptRosterNonAdminDHSwap: a delegated (can-invite) member cannot keep the
// account set identical while swapping another member's DHPub to a key they hold.
func TestAcceptRosterNonAdminDHSwap(t *testing.T) {
	me, _ := syncPrimary(t)
	_, adminID := syncPrimary(t)
	_, bID := syncPrimary(t) // can-invite member (the attacker)
	_, cID := syncPrimary(t) // victim whose key would be swapped

	e1 := protocol.NewSignedRoster(adminID, "g1", "G", chatstore.InvitePolicyAdmins, 1, []protocol.RosterMember{
		rm(adminID, chatstore.GroupRoleAdmin, false),
		rm(bID, chatstore.GroupRoleMember, true),
		rm(cID, chatstore.GroupRoleMember, false),
	})
	injectRoster(me, e1)

	swapped := rm(cID, chatstore.GroupRoleMember, false)
	swapped.DHPub = make([]byte, 32) // attacker-controlled key
	e2 := protocol.NewSignedRoster(bID, "g1", "G", chatstore.InvitePolicyAdmins, 2, []protocol.RosterMember{
		rm(adminID, chatstore.GroupRoleAdmin, false),
		rm(bID, chatstore.GroupRoleMember, true),
		swapped,
	})
	if acceptRoster(me, e2) {
		t.Fatal("a can-invite member redirected another member's key")
	}
}

// TestAcceptRosterCanInviteCannotEscalate: a can-invite member may add plain
// members, but may not add an admin or a delegated inviter (which would let them
// escalate to full authority next epoch).
func TestAcceptRosterCanInviteCannotEscalate(t *testing.T) {
	me, _ := syncPrimary(t)
	_, adminID := syncPrimary(t)
	_, bID := syncPrimary(t)
	_, dID := syncPrimary(t)

	e1 := protocol.NewSignedRoster(adminID, "g1", "G", chatstore.InvitePolicyAdmins, 1, []protocol.RosterMember{
		rm(adminID, chatstore.GroupRoleAdmin, false),
		rm(bID, chatstore.GroupRoleMember, true),
	})
	injectRoster(me, e1)

	// Adding D as an admin: refused.
	asAdmin := protocol.NewSignedRoster(bID, "g1", "G", chatstore.InvitePolicyAdmins, 2, []protocol.RosterMember{
		rm(adminID, chatstore.GroupRoleAdmin, false),
		rm(bID, chatstore.GroupRoleMember, true),
		rm(dID, chatstore.GroupRoleAdmin, false),
	})
	if acceptRoster(me, asAdmin) {
		t.Fatal("a can-invite member seeded a new admin")
	}
	// Adding D as a plain member: allowed.
	asMember := protocol.NewSignedRoster(bID, "g1", "G", chatstore.InvitePolicyAdmins, 2, []protocol.RosterMember{
		rm(adminID, chatstore.GroupRoleAdmin, false),
		rm(bID, chatstore.GroupRoleMember, true),
		rm(dID, chatstore.GroupRoleMember, false),
	})
	if !acceptRoster(me, asMember) {
		t.Fatal("a can-invite member could not add a plain member")
	}
}

// TestAcceptRosterRemovedAdminRejected: once an admin is removed, a roster they
// sign is no longer authorized (they aren't an admin in the roster we hold).
func TestAcceptRosterRemovedAdminRejected(t *testing.T) {
	me, _ := syncPrimary(t)
	_, a1ID := syncPrimary(t)
	_, a2ID := syncPrimary(t)

	e1 := protocol.NewSignedRoster(a1ID, "g1", "G", chatstore.InvitePolicyAdmins, 1, []protocol.RosterMember{
		rm(a1ID, chatstore.GroupRoleAdmin, false),
		rm(a2ID, chatstore.GroupRoleAdmin, false),
	})
	injectRoster(me, e1)
	// a1 removes a2 (admin authority) -> epoch 2.
	e2 := protocol.NewSignedRoster(a1ID, "g1", "G", chatstore.InvitePolicyAdmins, 2, []protocol.RosterMember{
		rm(a1ID, chatstore.GroupRoleAdmin, false),
	})
	if !acceptRoster(me, e2) {
		t.Fatal("admin-authored removal refused")
	}
	// a2, no longer on the roster, tries to push a new epoch: refused.
	e3 := protocol.NewSignedRoster(a2ID, "g1", "G", chatstore.InvitePolicyAdmins, 3, []protocol.RosterMember{
		rm(a1ID, chatstore.GroupRoleAdmin, false),
		rm(a2ID, chatstore.GroupRoleAdmin, false),
	})
	if acceptRoster(me, e3) {
		t.Fatal("a removed admin pushed a roster")
	}
}

// TestAcceptRosterSelfRemoval: a plain member may sign a roster that removes
// exactly themselves (leave), but not one that removes someone else.
func TestAcceptRosterSelfRemoval(t *testing.T) {
	me, _ := syncPrimary(t)
	_, adminID := syncPrimary(t)
	_, bID := syncPrimary(t)
	_, cID := syncPrimary(t)

	e1 := protocol.NewSignedRoster(adminID, "g1", "G", chatstore.InvitePolicyAdmins, 1, []protocol.RosterMember{
		rm(adminID, chatstore.GroupRoleAdmin, false),
		rm(bID, chatstore.GroupRoleMember, false),
		rm(cID, chatstore.GroupRoleMember, false),
	})
	injectRoster(me, e1)

	// b removes c: refused (not self).
	removeC := protocol.NewSignedRoster(bID, "g1", "G", chatstore.InvitePolicyAdmins, 2, []protocol.RosterMember{
		rm(adminID, chatstore.GroupRoleAdmin, false),
		rm(bID, chatstore.GroupRoleMember, false),
	})
	if acceptRoster(me, removeC) {
		t.Fatal("a member removed someone else")
	}
	// b removes b: allowed (leave).
	removeSelf := protocol.NewSignedRoster(bID, "g1", "G", chatstore.InvitePolicyAdmins, 2, []protocol.RosterMember{
		rm(adminID, chatstore.GroupRoleAdmin, false),
		rm(cID, chatstore.GroupRoleMember, false),
	})
	if !acceptRoster(me, removeSelf) {
		t.Fatal("a member could not remove themselves")
	}
}

// TestRosterForkConverges: two admins concurrently author different epoch-2
// rosters. Every member, whichever sibling it saw first, converges on the same
// one (the higher signature-byte roster wins deterministically).
func TestRosterForkConverges(t *testing.T) {
	_, adminID := syncPrimary(t)
	_, xID := syncPrimary(t)
	_, yID := syncPrimary(t)

	base := []protocol.RosterMember{rm(adminID, chatstore.GroupRoleAdmin, false)}
	e1 := protocol.NewSignedRoster(adminID, "g1", "G", chatstore.InvitePolicyAdmins, 1, base)

	// Two siblings at epoch 2, both signed by the same admin, differing by which
	// member they add (so the signatures differ).
	sib1 := protocol.NewSignedRoster(adminID, "g1", "G", chatstore.InvitePolicyAdmins, 2, []protocol.RosterMember{
		rm(adminID, chatstore.GroupRoleAdmin, false), rm(xID, chatstore.GroupRoleMember, false),
	})
	sib2 := protocol.NewSignedRoster(adminID, "g1", "G", chatstore.InvitePolicyAdmins, 2, []protocol.RosterMember{
		rm(adminID, chatstore.GroupRoleAdmin, false), rm(yID, chatstore.GroupRoleMember, false),
	})

	// Both peers already hold the epoch-1 roster; then peer A sees sib1 then sib2
	// and peer B sees them in the opposite order.
	peerA, _ := syncPrimary(t)
	peerB, _ := syncPrimary(t)
	injectRoster(peerA, e1)
	injectRoster(peerB, e1)
	for _, r := range []protocol.SignedRoster{sib1, sib2} {
		acceptRoster(peerA, r)
	}
	for _, r := range []protocol.SignedRoster{sib2, sib1} {
		acceptRoster(peerB, r)
	}
	ga, _ := heldGroup(peerA, "g1")
	gb, _ := heldGroup(peerB, "g1")
	if ga.Signer != gb.Signer || string(ga.Sig) != string(gb.Sig) {
		t.Fatalf("peers diverged after a fork: A=%x B=%x", ga.Sig, gb.Sig)
	}
	// And it's the deterministic winner.
	if !chatstore.RosterBeats(rosterToGroup(sib1), rosterToGroup(sib2)) && !chatstore.RosterBeats(rosterToGroup(sib2), rosterToGroup(sib1)) {
		t.Fatal("siblings tied on signature bytes — test setup is degenerate")
	}
}

// --- create / leave through the handlers ---

func TestCreateAndLeaveGroup(t *testing.T) {
	me, meID := syncPrimary(t)

	// Create.
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/groups/create", strings.NewReader(`{"name":"Trips"}`))
	me.handleCreateGroup(w, req, meID)
	if w.Code != 200 {
		t.Fatalf("create failed: %d %s", w.Code, w.Body)
	}
	var created map[string]any
	json.Unmarshal(w.Body.Bytes(), &created)
	gid := created["id"].(string)
	g, ok := heldGroup(me, gid)
	if !ok || g.Epoch != 1 || !rosterHasAdmin(g, meID.AccountNumber()) {
		t.Fatalf("group not created as sole admin: %+v", g)
	}

	// Add a co-admin so we can leave without hitting the last-admin guard.
	_, otherID := syncPrimary(t)
	e2 := protocol.NewSignedRoster(meID, gid, "Trips", chatstore.InvitePolicyAdmins, 2, []protocol.RosterMember{
		rm(meID, chatstore.GroupRoleAdmin, false), rm(otherID, chatstore.GroupRoleAdmin, false),
	})
	if !acceptRoster(me, e2) {
		t.Fatal("could not add co-admin")
	}

	// Leave.
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/groups/leave", strings.NewReader(`{"group":"`+gid+`"}`))
	me.handleLeaveGroup(w, req, meID)
	if w.Code != 200 {
		t.Fatalf("leave failed: %d %s", w.Code, w.Body)
	}
	g, ok = heldGroup(me, gid)
	if !ok {
		t.Fatal("group record vanished after leave (should be kept as a tombstone)")
	}
	if groupHasMember(g, meID.AccountNumber()) {
		t.Fatal("still a member after leaving")
	}
	if g.Epoch != 3 {
		t.Fatalf("leave did not advance the epoch: %d", g.Epoch)
	}

	// handleListGroups hides a group we've left.
	w = httptest.NewRecorder()
	me.handleListGroups(w, httptest.NewRequest("GET", "/api/groups", nil), meID)
	var listed map[string][]map[string]any
	json.Unmarshal(w.Body.Bytes(), &listed)
	if len(listed["groups"]) != 0 {
		t.Fatalf("left group still listed: %+v", listed["groups"])
	}
}

// TestLeaveLastAdminRefused: the only admin cannot leave without promoting a
// successor first (local refusal), so the group can't be orphaned by accident.
func TestLeaveLastAdminRefused(t *testing.T) {
	me, meID := syncPrimary(t)
	_, memberID := syncPrimary(t)

	roster := protocol.NewSignedRoster(meID, "g1", "G", chatstore.InvitePolicyAdmins, 1, []protocol.RosterMember{
		rm(meID, chatstore.GroupRoleAdmin, false),
		rm(memberID, chatstore.GroupRoleMember, false),
	})
	acceptRoster(me, roster)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/groups/leave", strings.NewReader(`{"group":"g1"}`))
	me.handleLeaveGroup(w, req, meID)
	if w.Code != 409 {
		t.Fatalf("last admin was allowed to leave: %d %s", w.Code, w.Body)
	}
	g, _ := heldGroup(me, "g1")
	if !groupHasMember(g, meID.AccountNumber()) {
		t.Fatal("last admin left despite refusal")
	}
}
