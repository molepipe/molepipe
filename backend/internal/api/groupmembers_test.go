package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// TestGroupMemberListFriendStatus: the member list annotates each co-member with
// our 1:1 relationship, and can_message is true ONLY for an accepted contact —
// sharing a group is never enough.
func TestGroupMemberListFriendStatus(t *testing.T) {
	me, meID := syncPrimary(t)
	_, friendID := syncPrimary(t)
	_, strangerID := syncPrimary(t)

	me.sessMu.Lock()
	me.contacts[friendID.AccountNumber()] = chatstore.Contact{
		Account: friendID.AccountNumber(), Name: "Pat", Status: chatstore.StatusAccepted,
	}
	me.groups["g1"] = rosterToGroup(protocol.NewSignedRoster(meID, "g1", "G", chatstore.InvitePolicyAdmins, 1,
		[]protocol.RosterMember{
			rm(meID, chatstore.GroupRoleAdmin, false),
			rm(friendID, chatstore.GroupRoleMember, false),
			rm(strangerID, chatstore.GroupRoleMember, false),
		}))
	me.sessMu.Unlock()

	w := httptest.NewRecorder()
	me.handleListGroupMembers(w, httptest.NewRequest("GET", "/api/groups/members?group=g1", nil), meID)
	if w.Code != 200 {
		t.Fatalf("member list failed: %d %s", w.Code, w.Body)
	}
	var resp struct {
		Members []map[string]any `json:"members"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)

	got := map[string]map[string]any{}
	for _, m := range resp.Members {
		got[m["account"].(string)] = m
	}
	if s := got[meID.AccountNumber()]; s["friend_status"] != "self" || s["is_self"] != true {
		t.Fatalf("self entry wrong: %+v", s)
	}
	if s := got[friendID.AccountNumber()]; s["friend_status"] != "accepted" || s["can_message"] != true {
		t.Fatalf("friend entry wrong: %+v", s)
	}
	if s := got[strangerID.AccountNumber()]; s["friend_status"] != "none" || s["can_message"] != false {
		t.Fatalf("stranger co-member should not be messageable: %+v", s)
	}
}

// TestFriendRequestToBlockedRefused: a blocked account that resurfaces as a
// co-member cannot be re-friended from the member list — sending a friend
// request to it is refused, so blocking is not silently undone.
func TestFriendRequestToBlockedRefused(t *testing.T) {
	me, meID := syncPrimary(t)
	_, blockedID := syncPrimary(t)
	me.sessMu.Lock()
	me.contacts[blockedID.AccountNumber()] = chatstore.Contact{
		Account: blockedID.AccountNumber(), Status: chatstore.StatusBlocked,
	}
	me.sessMu.Unlock()

	w := httptest.NewRecorder()
	body := `{"account":"` + blockedID.AccountNumber() + `","name":"x"}`
	me.handleSendRequest(w, httptest.NewRequest("POST", "/api/friend-requests/send", strings.NewReader(body)), meID)
	if w.Code != 400 {
		t.Fatalf("friend request to a blocked account was not refused: %d %s", w.Code, w.Body)
	}
}

// TestGroupMembershipGrantsNoDM: a co-member we haven't friended cannot DM us
// (contacts-only gate), and neither their DM attempt nor a group message from
// them creates or upgrades a contact — group and 1:1 trust stay fully separate.
func TestGroupMembershipGrantsNoDM(t *testing.T) {
	alice, aliceID := syncPrimary(t)
	bob, bobID := syncPrimary(t)

	// Alice and Bob share a group but are NOT contacts.
	g := chatstore.Group{
		ID: "g1", Name: "G", Epoch: 1,
		Members: []chatstore.GroupMember{
			{Account: aliceID.AccountNumber(), DHPub: dhBytes(aliceID), Role: chatstore.GroupRoleAdmin},
			{Account: bobID.AccountNumber(), DHPub: dhBytes(bobID), Role: chatstore.GroupRoleMember},
		},
	}
	injectGroup(t, alice, g)
	injectGroup(t, bob, g)

	// Bob tries to DM Alice directly: refused, nothing stored, no contact created.
	toAlice := syncFakeDialer{addr: alice.pubLn.Addr().String()}
	err := protocol.SendMessage(context.Background(), toAlice, bobID, aliceID.AccountNumber(), "m1", "let me in")
	if err == nil {
		t.Fatal("a co-member DMed us without being a friend")
	}
	alice.sessMu.Lock()
	_, isContact := alice.contacts[bobID.AccountNumber()]
	dmStored := false
	for _, m := range alice.messages {
		if m.Peer == bobID.AccountNumber() {
			dmStored = true
		}
	}
	alice.sessMu.Unlock()
	if isContact {
		t.Fatal("a refused DM created a contact")
	}
	if dmStored {
		t.Fatal("a refused DM was stored")
	}

	// A legitimate GROUP message from Bob is accepted (roster gate) but still must
	// not make him a 1:1 contact.
	alice.onion = &groupTestOnion{fakeOnion: &fakeOnion{}, dial: syncFakeDialer{addr: bob.pubLn.Addr().String()}}
	gm, _ := protocol.NewGroupMessage(bobID, "g1", "hi group", time.Now())
	env, _ := protocol.SealGroupMessage(bobID, gm, aliceID.AccountNumber(), aliceID.Keys.DH.Public)
	if err := protocol.SendGroupEnvelope(context.Background(), toAlice, env, aliceID.AccountNumber()); err != nil {
		t.Fatalf("group message from a co-member was refused: %v", err)
	}
	if !hasGroupMessage(alice, "g1", bobID.AccountNumber(), "hi group", "in") {
		t.Fatal("group message from a co-member was not delivered")
	}
	alice.sessMu.Lock()
	_, nowContact := alice.contacts[bobID.AccountNumber()]
	alice.sessMu.Unlock()
	if nowContact {
		t.Fatal("receiving a group message added the sender as a 1:1 contact")
	}
}

// TestGroupUnreadAndMarkRead: inbound group messages count as unread until the
// group is marked read, and marking read clears the count (reusing the reads map
// keyed by group id).
func TestGroupUnreadAndMarkRead(t *testing.T) {
	me, meID := syncPrimary(t)
	_, bobID := syncPrimary(t)

	g := chatstore.Group{
		ID: "g1", Name: "G", Epoch: 1,
		Members: []chatstore.GroupMember{
			{Account: meID.AccountNumber(), DHPub: dhBytes(meID), Role: chatstore.GroupRoleAdmin},
			{Account: bobID.AccountNumber(), DHPub: dhBytes(bobID), Role: chatstore.GroupRoleMember},
		},
	}
	injectGroup(t, me, g)

	for _, txt := range []string{"one", "two"} {
		gm, _ := protocol.NewGroupMessage(bobID, "g1", txt, time.Now())
		me.sessMu.Lock()
		me.deliverGroupInboundLocked(gm, false)
		me.sessMu.Unlock()
	}

	unread := func() int {
		w := httptest.NewRecorder()
		me.handleListGroups(w, httptest.NewRequest("GET", "/api/groups", nil), meID)
		var resp struct {
			Groups []map[string]any `json:"groups"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		for _, gr := range resp.Groups {
			if gr["id"] == "g1" {
				return int(gr["unread"].(float64))
			}
		}
		t.Fatal("group not listed")
		return -1
	}
	if unread() != 2 {
		t.Fatalf("expected 2 unread, got %d", unread())
	}

	w := httptest.NewRecorder()
	me.handleMarkGroupRead(w, httptest.NewRequest("POST", "/api/groups/read", strings.NewReader(`{"group":"g1"}`)), meID)
	if w.Code != 200 {
		t.Fatalf("mark read failed: %d %s", w.Code, w.Body)
	}
	if unread() != 0 {
		t.Fatalf("expected 0 unread after mark-read, got %d", unread())
	}
}
