package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

func memberRole(s *Server, gid, acct string) (string, bool) {
	g, ok := heldGroup(s, gid)
	if !ok {
		return "", false
	}
	for _, m := range g.Members {
		if m.Account == acct {
			return m.Role, true
		}
	}
	return "", false
}

func post(t *testing.T, s *Server, h func(http.ResponseWriter, *http.Request, *identity.Identity), id *identity.Identity, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest("POST", "/x", strings.NewReader(body)), id)
	return w
}

// TestGroupPromoteAndPolicy: an admin can promote a member and flip the invite
// policy; the roster advances and the change sticks.
func TestGroupPromoteAndPolicy(t *testing.T) {
	admin, adminID := syncPrimary(t)
	_, bID := syncPrimary(t)

	e1 := protocol.NewSignedRoster(adminID, "g1", "G", chatstore.InvitePolicyAdmins, 1, []protocol.RosterMember{
		rm(adminID, chatstore.GroupRoleAdmin, false),
		rm(bID, chatstore.GroupRoleMember, false),
	})
	// admin is the signer (== self), so the genesis passes the real consent gate.
	if !acceptRoster(admin, e1) {
		t.Fatal("admin's own genesis roster was refused")
	}

	w := post(t, admin, admin.handlePromoteInGroup, adminID, `{"group":"g1","account":"`+bID.AccountNumber()+`"}`)
	if w.Code != 200 {
		t.Fatalf("promote failed: %d %s", w.Code, w.Body)
	}
	if role, _ := memberRole(admin, "g1", bID.AccountNumber()); role != chatstore.GroupRoleAdmin {
		t.Fatalf("member not promoted: role=%q", role)
	}

	w = post(t, admin, admin.handleSetGroupPolicy, adminID, `{"group":"g1","policy":"everyone"}`)
	if w.Code != 200 {
		t.Fatalf("policy change failed: %d %s", w.Code, w.Body)
	}
	if g, _ := heldGroup(admin, "g1"); g.Policy != chatstore.InvitePolicyEveryone || g.Epoch != 3 {
		t.Fatalf("policy/epoch wrong: %+v", g)
	}
}

// TestGroupAdminOpsRequireAdmin: a non-admin member is refused every admin op.
func TestGroupAdminOpsRequireAdmin(t *testing.T) {
	member, memberID := syncPrimary(t)
	_, adminID := syncPrimary(t)
	_, otherID := syncPrimary(t)

	e1 := protocol.NewSignedRoster(adminID, "g1", "G", chatstore.InvitePolicyAdmins, 1, []protocol.RosterMember{
		rm(adminID, chatstore.GroupRoleAdmin, false),
		rm(memberID, chatstore.GroupRoleMember, false),
		rm(otherID, chatstore.GroupRoleMember, false),
	})
	injectRoster(member, e1)

	other := otherID.AccountNumber()
	for _, tc := range []struct {
		name string
		h    func(http.ResponseWriter, *http.Request, *identity.Identity)
		body string
	}{
		{"remove", member.handleRemoveFromGroup, `{"group":"g1","account":"` + other + `"}`},
		{"promote", member.handlePromoteInGroup, `{"group":"g1","account":"` + other + `"}`},
		{"can-invite", member.handleSetCanInvite, `{"group":"g1","account":"` + other + `","allow":true}`},
		{"rename", member.handleRenameGroup, `{"group":"g1","name":"Hijacked"}`},
		{"policy", member.handleSetGroupPolicy, `{"group":"g1","policy":"everyone"}`},
	} {
		w := post(t, member, tc.h, memberID, tc.body)
		if w.Code != 403 {
			t.Fatalf("%s by a non-admin was not refused: %d %s", tc.name, w.Code, w.Body)
		}
	}
	if g, _ := heldGroup(member, "g1"); g.Epoch != 1 {
		t.Fatalf("a refused op still mutated the roster: epoch=%d", g.Epoch)
	}
}

// TestGroupRemoveNotifiesRemoved: an admin removes a member, and the removal
// roster is pushed to the removed member so their own client drops the group.
func TestGroupRemoveNotifiesRemoved(t *testing.T) {
	admin, adminID := syncPrimary(t)
	removed, removedID := syncPrimary(t)

	e1 := protocol.NewSignedRoster(adminID, "g1", "G", chatstore.InvitePolicyAdmins, 1, []protocol.RosterMember{
		rm(adminID, chatstore.GroupRoleAdmin, false),
		rm(removedID, chatstore.GroupRoleMember, false),
	})
	injectRoster(admin, e1)
	injectRoster(removed, e1) // the soon-to-be-removed member holds it too

	admin.onion = routeTo(removed)

	w := post(t, admin, admin.handleRemoveFromGroup, adminID, `{"group":"g1","account":"`+removedID.AccountNumber()+`"}`)
	if w.Code != 200 {
		t.Fatalf("remove failed: %d %s", w.Code, w.Body)
	}
	// The removed member adopts the new roster (signer is an admin they hold) and
	// their self-membership gate now excludes them.
	waitFor(t, 3*time.Second, func() bool { return !groupHas(removed, "g1", removedID.AccountNumber()) })
	if groupHas(admin, "g1", removedID.AccountNumber()) {
		t.Fatal("admin still lists the removed member")
	}

	// Traffic actually stops: a group message can no longer be delivered to the
	// removed member — their self-membership gate refuses it and stores nothing.
	// (This is what the leave/remove gates exist for; asserting roster state alone
	// wouldn't catch a regression that dropped the gate.)
	gm, err := protocol.NewGroupMessage(adminID, "g1", "after removal", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	env, err := protocol.SealGroupMessage(adminID, gm, removedID.AccountNumber(), removedID.Keys.DH.Public)
	if err != nil {
		t.Fatal(err)
	}
	toRemoved := syncFakeDialer{addr: removed.pubLn.Addr().String()}
	if err := protocol.SendGroupEnvelope(context.Background(), toRemoved, env, removedID.AccountNumber()); err == nil {
		t.Fatal("a removed member still accepts group traffic")
	}
	if hasGroupMessage(removed, "g1", adminID.AccountNumber(), "after removal", "in") {
		t.Fatal("a removed member stored a message for a group they were removed from")
	}
}
