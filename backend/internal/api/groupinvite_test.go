package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

func routeTo(target *Server) *groupTestOnion {
	return &groupTestOnion{fakeOnion: &fakeOnion{}, dial: syncFakeDialer{addr: target.pubLn.Addr().String()}}
}

func groupHas(s *Server, gid, acct string) bool {
	g, ok := heldGroup(s, gid)
	return ok && groupHasMember(g, acct)
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

func pendingInviteCount(s *Server) int {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	return len(s.groupInvites)
}

// TestGroupInviteAcceptNonAdmin walks the whole membership handshake with a
// NON-admin inviter: bob (a delegated can-invite member) invites carol, carol
// accepts, bob commits her into the roster and pushes it, and carol JOINS via
// the bootstrap consent anchor — proving the anchor, not an admin signature, is
// what carries a non-admin-authored join.
func TestGroupInviteAcceptNonAdmin(t *testing.T) {
	bob, bobID := syncPrimary(t)
	carol, carolID := syncPrimary(t)
	admin, _ := identity.New() // a real admin, but not a live server in this test

	// bob holds a group where he is a can-invite member and admin is the (offline)
	// admin. The admin signs the genesis; bob holds it as established state.
	e1 := protocol.NewSignedRoster(admin, "g1", "Trips", chatstore.InvitePolicyAdmins, 1, []protocol.RosterMember{
		rm(admin, chatstore.GroupRoleAdmin, false),
		rm(bobID, chatstore.GroupRoleMember, true),
	})
	injectRoster(bob, e1)

	bob.onion = routeTo(carol)
	carol.onion = routeTo(bob)

	// bob invites carol.
	w := httptest.NewRecorder()
	body := `{"group":"g1","account":"` + carolID.AccountNumber() + `"}`
	bob.handleInviteToGroup(w, httptest.NewRequest("POST", "/api/groups/invite", strings.NewReader(body)), bobID)
	if w.Code != 200 {
		t.Fatalf("invite failed: %d %s", w.Code, w.Body)
	}
	waitFor(t, 2*time.Second, func() bool { return pendingInviteCount(carol) == 1 })

	// carol accepts.
	w = httptest.NewRecorder()
	carol.handleAcceptGroupInvite(w, httptest.NewRequest("POST", "/api/groups/invites/accept", strings.NewReader(`{"group":"g1"}`)), carolID)
	if w.Code != 200 {
		t.Fatalf("accept failed: %d %s", w.Code, w.Body)
	}

	// bob commits her and pushes the roster; carol joins via the consent anchor.
	waitFor(t, 3*time.Second, func() bool { return groupHas(carol, "g1", carolID.AccountNumber()) })
	if !groupHas(bob, "g1", carolID.AccountNumber()) {
		t.Fatal("bob did not add carol to his roster")
	}
	g, _ := heldGroup(carol, "g1")
	if g.Epoch != 2 || !rosterHasAdmin(g, admin.AccountNumber()) {
		t.Fatalf("carol's adopted roster is wrong: %+v", g)
	}
	// The consent anchor is consumed once she's in.
	waitFor(t, time.Second, func() bool { return pendingInviteCount(carol) == 0 })
}

// TestGroupInviteRetryHealsDroppedRoster covers stranding mode two: bob received
// the accept and committed carol, but the roster push was lost. carol is
// "accepted" but not a member and can't self-repair. The retry re-sends her
// accept; bob sees she's already on the roster and RE-PUSHES (rather than
// committing again), so she joins — and bob's epoch does not bump a second time,
// so no fork is manufactured.
func TestGroupInviteRetryHealsDroppedRoster(t *testing.T) {
	bob, bobID := syncPrimary(t)
	carol, carolID := syncPrimary(t)

	// bob creates a group (sole admin).
	w := httptest.NewRecorder()
	bob.handleCreateGroup(w, httptest.NewRequest("POST", "/api/groups/create", strings.NewReader(`{"name":"Trips"}`)), bobID)
	var created map[string]any
	json.Unmarshal(w.Body.Bytes(), &created)
	gid := created["id"].(string)

	// bob commits carol but the roster never reaches her (simulated: no push).
	bob.sessMu.Lock()
	bob.commitAddMemberLocked(bobID, gid, carolID.AccountNumber(), "Carol", dhBytes(carolID))
	epochAfterCommit := bob.groups[gid].Epoch
	bob.sessMu.Unlock()
	if epochAfterCommit != 2 {
		t.Fatalf("commit did not reach epoch 2: %d", epochAfterCommit)
	}

	// carol accepted the invite (its consent anchor armed) but holds no roster.
	carol.sessMu.Lock()
	carol.groupInvites[gid] = chatstore.GroupInvite{
		GroupID: gid, Inviter: bobID.AccountNumber(), ReqID: "req-1", Accepted: true, At: time.Now(),
	}
	carol.sessMu.Unlock()

	bob.onion = routeTo(carol)
	carol.onion = routeTo(bob)

	// The retry tick re-sends the accept; bob re-pushes; carol joins.
	carol.groupInviteRetryTick(context.Background(), carolID)
	waitFor(t, 3*time.Second, func() bool { return groupHas(carol, gid, carolID.AccountNumber()) })

	g, _ := heldGroup(bob, gid)
	if g.Epoch != 2 {
		t.Fatalf("a retry inflated the epoch (manufactured a fork): %d", g.Epoch)
	}
}
