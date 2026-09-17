package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
	"github.com/molepipe/molepipe/backend/internal/tor"
)

// groupTestOnion is a tor.OnionService whose Dialer routes to a chosen peer's
// public listener, so groupFanOut can be exercised end-to-end in-process.
type groupTestOnion struct {
	*fakeOnion
	dial tor.Dialer
}

func (o *groupTestOnion) Dialer() tor.Dialer { return o.dial }

func dhBytes(id *identity.Identity) []byte {
	p := id.Keys.DH.Public
	return p[:]
}

func injectGroup(t *testing.T, srv *Server, g chatstore.Group) {
	t.Helper()
	srv.sessMu.Lock()
	srv.groups[g.ID] = g
	srv.sessMu.Unlock()
}

func hasGroupMessage(srv *Server, groupID, author, text, dir string) bool {
	srv.sessMu.Lock()
	defer srv.sessMu.Unlock()
	for _, m := range srv.messages {
		if m.GroupID == groupID && m.Author == author && m.Text == text && m.Direction == dir {
			return true
		}
	}
	return false
}

// TestGroupSendAndReceive walks the whole phase-2 path: an author seals a group
// message per member and fans it out; the receiving member decrypts, verifies
// the author signature, gates it to the roster, and files it as inbound.
func TestGroupSendAndReceive(t *testing.T) {
	alice, aliceID := syncPrimary(t)
	bob, bobID := syncPrimary(t)

	g := chatstore.Group{
		ID: "grp-1", Name: "Test Group", Epoch: 1, Policy: chatstore.InvitePolicyAdmins,
		Members: []chatstore.GroupMember{
			{Account: aliceID.AccountNumber(), DHPub: dhBytes(aliceID), Role: chatstore.GroupRoleAdmin},
			{Account: bobID.AccountNumber(), DHPub: dhBytes(bobID), Role: chatstore.GroupRoleMember},
		},
	}
	injectGroup(t, alice, g)
	injectGroup(t, bob, g)

	alice.onion = &groupTestOnion{fakeOnion: &fakeOnion{}, dial: syncFakeDialer{addr: bob.pubLn.Addr().String()}}

	gm, err := protocol.NewGroupMessage(aliceID, "grp-1", "hello group", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	alice.groupFanOut(aliceID, g, gm)

	if !hasGroupMessage(bob, "grp-1", aliceID.AccountNumber(), "hello group", "in") {
		t.Fatal("bob did not receive the group message")
	}
	// Invariant: a stored group message never carries a 1:1 Peer, or the contact
	// list and unread math would misattribute it.
	bob.sessMu.Lock()
	for _, m := range bob.messages {
		if m.GroupID != "" && m.Peer != "" {
			t.Fatalf("group message got a Peer set: %+v", m)
		}
	}
	bob.sessMu.Unlock()

	// Re-delivering the same message must de-dupe (gossip will re-offer it).
	alice.groupFanOut(aliceID, g, gm)
	n := 0
	bob.sessMu.Lock()
	for _, m := range bob.messages {
		if m.GroupID == "grp-1" {
			n++
		}
	}
	bob.sessMu.Unlock()
	if n != 1 {
		t.Fatalf("group message duplicated on re-delivery: %d copies", n)
	}
}

// TestGroupMessageFromNonMemberRejected: a valid-signed message whose author is
// not on the roster is refused and stored nowhere — the roster is the gate.
func TestGroupMessageFromNonMemberRejected(t *testing.T) {
	bob, bobID := syncPrimary(t)
	intruder, _ := identity.New()

	g := chatstore.Group{
		ID: "grp-1", Name: "Test Group", Epoch: 1,
		Members: []chatstore.GroupMember{
			{Account: bobID.AccountNumber(), DHPub: dhBytes(bobID), Role: chatstore.GroupRoleAdmin},
		},
	}
	injectGroup(t, bob, g)

	gm, _ := protocol.NewGroupMessage(intruder, "grp-1", "let me in", time.Now())
	env, err := protocol.SealGroupMessage(intruder, gm, bobID.AccountNumber(), bobID.Keys.DH.Public)
	if err != nil {
		t.Fatal(err)
	}
	toBob := syncFakeDialer{addr: bob.pubLn.Addr().String()}
	if err := protocol.SendGroupEnvelope(context.Background(), toBob, env, bobID.AccountNumber()); err == nil {
		t.Fatal("a non-member's group message was accepted")
	}
	if hasGroupMessage(bob, "grp-1", intruder.AccountNumber(), "let me in", "in") {
		t.Fatal("a non-member's group message was stored")
	}
}

// TestGroupMessageForUnknownGroupRejected: even a well-formed message for a group
// we don't belong to is refused (we can't be spammed into unknown groups).
func TestGroupMessageForUnknownGroupRejected(t *testing.T) {
	bob, bobID := syncPrimary(t)
	author, _ := identity.New()

	gm, _ := protocol.NewGroupMessage(author, "grp-unknown", "hi", time.Now())
	env, _ := protocol.SealGroupMessage(author, gm, bobID.AccountNumber(), bobID.Keys.DH.Public)
	toBob := syncFakeDialer{addr: bob.pubLn.Addr().String()}
	if err := protocol.SendGroupEnvelope(context.Background(), toBob, env, bobID.AccountNumber()); err == nil {
		t.Fatal("a message for an unknown group was accepted")
	}
}

// TestGroupGossipPull: a member who is missing messages pulls them from another
// member and files them silently (backfill must not notify), and the author
// signature is re-verified end to end.
func TestGroupGossipPull(t *testing.T) {
	alice, aliceID := syncPrimary(t)
	bob, bobID := syncPrimary(t)

	g := chatstore.Group{
		ID: "grp-1", Name: "Test Group", Epoch: 1,
		Members: []chatstore.GroupMember{
			{Account: aliceID.AccountNumber(), DHPub: dhBytes(aliceID), Role: chatstore.GroupRoleAdmin},
			{Account: bobID.AccountNumber(), DHPub: dhBytes(bobID), Role: chatstore.GroupRoleMember},
		},
	}
	injectGroup(t, alice, g)
	injectGroup(t, bob, g)

	// Seed bob with two messages alice doesn't have.
	for _, txt := range []string{"missed one", "missed two"} {
		gm, err := protocol.NewGroupMessage(bobID, "grp-1", txt, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		bob.sessMu.Lock()
		bob.deliverGroupInboundLocked(gm, false)
		bob.sessMu.Unlock()
	}

	// A notification during backfill would be the bug.
	notified := make(chan struct{}, 8)
	alice.SetInboundHook(func(_, _ string, _ int64, _ string) { notified <- struct{}{} })

	alice.onion = &groupTestOnion{fakeOnion: &fakeOnion{}, dial: syncFakeDialer{addr: bob.pubLn.Addr().String()}}
	alice.groupSyncPullFrom(context.Background(), aliceID, "grp-1", bobID.AccountNumber(), nil, 0)

	if !hasGroupMessage(alice, "grp-1", bobID.AccountNumber(), "missed one", "in") ||
		!hasGroupMessage(alice, "grp-1", bobID.AccountNumber(), "missed two", "in") {
		t.Fatal("gossip pull did not backfill the missing messages")
	}
	select {
	case <-notified:
		t.Fatal("gossip backfill raised a notification")
	case <-time.After(200 * time.Millisecond):
	}

	// Pulling again with those ids in the have-list returns nothing new.
	var have []string
	alice.sessMu.Lock()
	for _, m := range alice.messages {
		if m.GroupID == "grp-1" {
			have = append(have, m.ID)
		}
	}
	before := len(alice.messages)
	alice.sessMu.Unlock()
	alice.groupSyncPullFrom(context.Background(), aliceID, "grp-1", bobID.AccountNumber(), have, 0)
	alice.sessMu.Lock()
	after := len(alice.messages)
	alice.sessMu.Unlock()
	if after != before {
		t.Fatalf("gossip re-pull duplicated messages: %d -> %d", before, after)
	}
}

// TestGroupReplyGossipRoundTrip is the one test that proves group reply works
// end-to-end over the relay path: bob authors a REPLY (its quoted id is inside the
// author-signed blob), alice pulls it via gossip, and it must both verify at alice
// (so it lands at all) and arrive with the reply id intact. The failure it guards
// against is silent: if groupMessageFromRowLocked forgot to reproduce ReplyID when
// re-sealing, the re-signed bytes wouldn't match and alice would drop the message.
func TestGroupReplyGossipRoundTrip(t *testing.T) {
	alice, aliceID := syncPrimary(t)
	bob, bobID := syncPrimary(t)

	g := chatstore.Group{
		ID: "grp-1", Name: "Test Group", Epoch: 1,
		Members: []chatstore.GroupMember{
			{Account: aliceID.AccountNumber(), DHPub: dhBytes(aliceID), Role: chatstore.GroupRoleAdmin},
			{Account: bobID.AccountNumber(), DHPub: dhBytes(bobID), Role: chatstore.GroupRoleMember},
		},
	}
	injectGroup(t, alice, g)
	injectGroup(t, bob, g)

	// Bob authors a reply quoting some earlier message id.
	reply, err := protocol.NewGroupMessage(bobID, "grp-1", "replying now", time.Now(), "quoted-id-xyz")
	if err != nil {
		t.Fatal(err)
	}
	bob.sessMu.Lock()
	bob.deliverGroupInboundLocked(reply, false)
	bob.sessMu.Unlock()

	alice.onion = &groupTestOnion{fakeOnion: &fakeOnion{}, dial: syncFakeDialer{addr: bob.pubLn.Addr().String()}}
	alice.groupSyncPullFrom(context.Background(), aliceID, "grp-1", bobID.AccountNumber(), nil, 0)

	if !hasGroupMessage(alice, "grp-1", bobID.AccountNumber(), "replying now", "in") {
		t.Fatal("group reply did not survive the gossip round trip (verify likely failed)")
	}
	// And the quoted id must have come along on the stored row.
	alice.sessMu.Lock()
	var gotReplyID string
	for _, m := range alice.messages {
		if m.GroupID == "grp-1" && m.Text == "replying now" {
			gotReplyID = m.ReplyID
		}
	}
	alice.sessMu.Unlock()
	if gotReplyID != "quoted-id-xyz" {
		t.Fatalf("reply id lost across gossip: got %q", gotReplyID)
	}
}

// TestGroupSendReplyScopedToGroup is the authorization analogue of
// TestReactionAuthorization for group reply: the reply id a client sends is signed
// into the blob and fanned out to every member, so it must be proven to name a
// message in THIS group first. A foreign id (another group, or a 1:1) is dropped —
// the message still sends, just as a plain (non-reply) one — so it can never relay
// a quote pulled from an unrelated conversation. A real in-group id is preserved.
func TestGroupSendReplyScopedToGroup(t *testing.T) {
	alice, aliceID := syncPrimary(t)

	// Alice is the sole member of grp-1 (so the send fans out to nobody), and also
	// holds a message that belongs to a DIFFERENT group.
	g := chatstore.Group{
		ID: "grp-1", Name: "Solo", Epoch: 1,
		Members: []chatstore.GroupMember{{Account: aliceID.AccountNumber(), DHPub: dhBytes(aliceID), Role: chatstore.GroupRoleAdmin}},
	}
	injectGroup(t, alice, g)
	// A non-nil dialer: startSession's background loops read s.onion, so leaving the
	// dialer nil would nil-deref when one fires. Point it at alice's own listener —
	// this test never actually fans out (grp-1 is solo), the dialer just has to exist.
	alice.onion = &groupTestOnion{fakeOnion: &fakeOnion{}, dial: syncFakeDialer{addr: alice.pubLn.Addr().String()}}

	// Seed a real in-group message and a foreign-group message.
	real, _ := protocol.NewGroupMessage(aliceID, "grp-1", "the original", time.Now())
	alice.sessMu.Lock()
	alice.deliverGroupInboundLocked(real, false)
	alice.messages = append(alice.messages, chatMessage{ID: "foreign-id", GroupID: "grp-2", Text: "elsewhere", Direction: "in"})
	alice.sessMu.Unlock()
	realID := chatstore.GroupMessageID("grp-1", aliceID.AccountNumber(), "the original", real.At)

	send := func(replyID string) {
		body, _ := json.Marshal(map[string]any{"group": "grp-1", "text": "reply body " + replyID, "reply_to": map[string]string{"id": replyID}})
		req := httptest.NewRequest(http.MethodPost, "/api/groups/send", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		alice.handleSendGroupMessage(rec, req, aliceID)
		if rec.Code != http.StatusOK {
			t.Fatalf("send with reply %q: status %d", replyID, rec.Code)
		}
	}
	replyIDOf := func(text string) (string, bool) {
		alice.sessMu.Lock()
		defer alice.sessMu.Unlock()
		for _, m := range alice.messages {
			if m.Text == text {
				return m.ReplyID, true
			}
		}
		return "", false
	}

	// A foreign-group id is dropped: the message sends, but carries no reply id.
	send("foreign-id")
	if rid, ok := replyIDOf("reply body foreign-id"); !ok || rid != "" {
		t.Fatalf("foreign-group reply id was not dropped: %q (found=%v)", rid, ok)
	}
	// A real in-group id is preserved and signed in.
	send(realID)
	if rid, ok := replyIDOf("reply body " + realID); !ok || rid != realID {
		t.Fatalf("in-group reply id was not preserved: %q (found=%v)", rid, ok)
	}
}

// TestGroupSyncFromNonMemberRejected: a non-member cannot pull a group's history.
func TestGroupSyncFromNonMemberRejected(t *testing.T) {
	bob, bobID := syncPrimary(t)
	stranger, _ := identity.New()

	g := chatstore.Group{
		ID: "grp-1", Name: "Test Group", Epoch: 1,
		Members: []chatstore.GroupMember{
			{Account: bobID.AccountNumber(), DHPub: dhBytes(bobID), Role: chatstore.GroupRoleAdmin},
		},
	}
	injectGroup(t, bob, g)
	gm, _ := protocol.NewGroupMessage(bobID, "grp-1", "secret", time.Now())
	bob.sessMu.Lock()
	bob.deliverGroupInboundLocked(gm, false)
	bob.sessMu.Unlock()

	req := protocol.GroupSyncRequest{GroupID: "grp-1", Sender: stranger.AccountNumber()}
	req.Sig = protocol.SignGroupSync(stranger, "grp-1", nil, 0)
	toBob := syncFakeDialer{addr: bob.pubLn.Addr().String()}
	if _, _, _, err := protocol.GroupSyncPull(context.Background(), toBob, req, bobID.AccountNumber()); err == nil {
		t.Fatal("a non-member pulled group history")
	}
}

// TestGroupGossipBackfillsFormerAuthor: a message authored by someone no longer
// on the roster (removed) still backfills — its author signature proves it was
// written by a then-member, and removal must not erase their past messages for a
// member who was offline during their tenure.
func TestGroupGossipBackfillsFormerAuthor(t *testing.T) {
	alice, aliceID := syncPrimary(t)
	bob, bobID := syncPrimary(t)
	formerMember, _ := identity.New() // authored a message, since removed from the roster

	g := chatstore.Group{
		ID: "grp-1", Name: "Test Group", Epoch: 2,
		Members: []chatstore.GroupMember{
			{Account: aliceID.AccountNumber(), DHPub: dhBytes(aliceID), Role: chatstore.GroupRoleAdmin},
			{Account: bobID.AccountNumber(), DHPub: dhBytes(bobID), Role: chatstore.GroupRoleMember},
		},
	}
	injectGroup(t, alice, g)
	injectGroup(t, bob, g)

	// Bob holds a message from the former member (roster no longer lists them).
	gm, _ := protocol.NewGroupMessage(formerMember, "grp-1", "i was here", time.Now())
	bob.sessMu.Lock()
	bob.deliverGroupInboundLocked(gm, false)
	bob.sessMu.Unlock()

	alice.onion = &groupTestOnion{fakeOnion: &fakeOnion{}, dial: syncFakeDialer{addr: bob.pubLn.Addr().String()}}
	alice.groupSyncPullFrom(context.Background(), aliceID, "grp-1", bobID.AccountNumber(), nil, 0)

	if !hasGroupMessage(alice, "grp-1", formerMember.AccountNumber(), "i was here", "in") {
		t.Fatal("a former member's message was not backfilled via gossip")
	}
}

// liveReactionCount returns how many LIVE (non-tombstone) reactions with the given
// emoji sit on a message. Caller must not hold sessMu.
func liveReactionCount(s *Server, msgID, emoji string) int {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	n := 0
	for _, m := range s.messages {
		if m.ID != msgID {
			continue
		}
		for _, r := range chatstore.LiveReactions(m.Reactions) {
			if r.Emoji == emoji {
				n++
			}
		}
	}
	return n
}

// TestGroupReactionGossipAndResurrection is the test that proves build 4 the way
// TestGroupReplyGossipRoundTrip proved build 3. Two things in one pull:
//   - POSITIVE: a reaction bob placed while alice was offline is caught up by
//     gossip and lands LIVE on alice's copy of the message.
//   - RESURRECTION (the whole reason the design exists): alice already holds bob's
//     later UN-react (a tombstone); bob, having missed the remove, re-serves his
//     stale ADD. LWW must drop it — the reaction must NOT come back to life.
func TestGroupReactionGossipAndResurrection(t *testing.T) {
	alice, aliceID := syncPrimary(t)
	bob, bobID := syncPrimary(t)

	g := chatstore.Group{
		ID: "grp-1", Name: "Test Group", Epoch: 1,
		Members: []chatstore.GroupMember{
			{Account: aliceID.AccountNumber(), DHPub: dhBytes(aliceID), Role: chatstore.GroupRoleAdmin},
			{Account: bobID.AccountNumber(), DHPub: dhBytes(bobID), Role: chatstore.GroupRoleMember},
		},
	}
	injectGroup(t, alice, g)
	injectGroup(t, bob, g)

	// A message both hold, so a reaction has a target on each side.
	gm, _ := protocol.NewGroupMessage(aliceID, "grp-1", "react to me", time.Now())
	msgID := chatstore.GroupMessageID("grp-1", aliceID.AccountNumber(), "react to me", gm.At)
	for _, s := range []*Server{alice, bob} {
		s.sessMu.Lock()
		s.deliverGroupInboundLocked(gm, false)
		s.sessMu.Unlock()
	}

	base := time.Now()
	// Bob places ❤️ that alice never saw (positive-catch-up case).
	heart, _ := protocol.NewGroupReaction(bobID, "grp-1", msgID, "❤️", false, base)
	// Bob's 👍 add (t1) — the stale one he will re-serve.
	thumbAdd, _ := protocol.NewGroupReaction(bobID, "grp-1", msgID, "👍", false, base.Add(time.Second))
	// Bob's later 👍 remove (t2 > t1) — alice has this; bob does NOT.
	thumbRemove, _ := protocol.NewGroupReaction(bobID, "grp-1", msgID, "👍", true, base.Add(2*time.Second))

	// Bob's store: ❤️ live + the STALE 👍 add (he was offline for his own remove in
	// this scenario — modelled as: his store still holds the add he'll gossip).
	bob.sessMu.Lock()
	bob.applyGroupReactionLocked(heart)
	bob.applyGroupReactionLocked(thumbAdd)
	bob.sessMu.Unlock()

	// Alice's store: she already converged 👍 to REMOVED (add then remove).
	alice.sessMu.Lock()
	alice.applyGroupReactionLocked(thumbAdd)
	alice.applyGroupReactionLocked(thumbRemove)
	alice.sessMu.Unlock()
	if liveReactionCount(alice, msgID, "👍") != 0 {
		t.Fatal("precondition: alice should have un-reacted 👍 before the pull")
	}

	// Alice pulls from bob: bob re-serves ❤️(add) and 👍(stale add).
	alice.onion = &groupTestOnion{fakeOnion: &fakeOnion{}, dial: syncFakeDialer{addr: bob.pubLn.Addr().String()}}
	alice.groupSyncPullFrom(context.Background(), aliceID, "grp-1", bobID.AccountNumber(), nil, 0)

	if liveReactionCount(alice, msgID, "❤️") != 1 {
		t.Fatal("a reaction placed while alice was offline was not caught up by gossip")
	}
	if liveReactionCount(alice, msgID, "👍") != 0 {
		t.Fatal("a re-served STALE add resurrected an un-reacted reaction — LWW convergence is broken")
	}
}

// TestGroupReactScopedToGroup is the authorization analogue of
// TestGroupSendReplyScopedToGroup for the control endpoint: the target id we sign
// and fan out must name a message in THIS group. A foreign id (another group or a
// 1:1) is refused so a reaction can never be relayed against an unrelated message.
func TestGroupReactScopedToGroup(t *testing.T) {
	alice, aliceID := syncPrimary(t)

	g := chatstore.Group{
		ID: "grp-1", Name: "Solo", Epoch: 1,
		Members: []chatstore.GroupMember{{Account: aliceID.AccountNumber(), DHPub: dhBytes(aliceID), Role: chatstore.GroupRoleAdmin}},
	}
	injectGroup(t, alice, g)
	alice.onion = &groupTestOnion{fakeOnion: &fakeOnion{}, dial: syncFakeDialer{addr: alice.pubLn.Addr().String()}}

	real, _ := protocol.NewGroupMessage(aliceID, "grp-1", "the original", time.Now())
	realID := chatstore.GroupMessageID("grp-1", aliceID.AccountNumber(), "the original", real.At)
	alice.sessMu.Lock()
	alice.deliverGroupInboundLocked(real, false)
	alice.messages = append(alice.messages, chatMessage{ID: "foreign-id", GroupID: "grp-2", Text: "elsewhere", Direction: "in"})
	alice.sessMu.Unlock()

	react := func(id string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"group": "grp-1", "id": id, "emoji": "👍"})
		req := httptest.NewRequest(http.MethodPost, "/api/groups/react", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		alice.handleGroupReact(rec, req, aliceID)
		return rec
	}

	// A foreign-group id is refused, and nothing is written on it.
	if rec := react("foreign-id"); rec.Code == http.StatusOK {
		t.Fatalf("a foreign-group target was accepted: status %d", rec.Code)
	}
	if liveReactionCount(alice, "foreign-id", "👍") != 0 {
		t.Fatal("a reaction was applied to a foreign-group message")
	}
	// A real in-group id is accepted and the reaction lands.
	if rec := react(realID); rec.Code != http.StatusOK {
		t.Fatalf("an in-group target was refused: status %d", rec.Code)
	}
	if liveReactionCount(alice, realID, "👍") != 1 {
		t.Fatal("an in-group reaction was not applied")
	}
}

// reactionEntry returns the raw stored reaction (live OR tombstone) for
// (emoji, by) on a message. A live count alone can't tell a tombstone from a
// physical removal, so a convergence assertion needs the entry itself. Caller
// must not hold sessMu.
func reactionEntry(s *Server, msgID, emoji, by string) (chatstore.MessageReaction, bool) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	for _, m := range s.messages {
		if m.ID != msgID {
			continue
		}
		for _, r := range m.Reactions {
			if r.Emoji == emoji && r.By == by {
				return r, true
			}
		}
	}
	return chatstore.MessageReaction{}, false
}

// waitReactionCount polls until the live (emoji) count on s reaches want, or the
// deadline passes. The fan-out goroutine over the loopback dialer lands in a few
// ms; the generous deadline only removes scheduler flake — if it ever trips, the
// fan-out genuinely didn't deliver.
func waitReactionCount(t *testing.T, s *Server, msgID, emoji string, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := liveReactionCount(s, msgID, emoji)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("live %q count never reached %d (stuck at %d) — fan-out did not deliver", emoji, want, got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestGroupReactionLiveFanOutTwoServers is the integration test the single-account
// emulator could not stand in for. It drives the REAL control endpoint on one
// server and asserts the reaction travels — sealed, over the loopback transport,
// through the peer's /p2p/group-react handler and roster gate — onto a SECOND
// server that has its own identity and store. It proves both halves of the toggle
// over the wire: a live add lands on the peer, and a subsequent un-react (computed
// from alice's own state, not hand-built) converges the peer's copy to a
// TOMBSTONE — not a physical removal, which a later stale re-serve from a third
// member could resurrect. Only the Tor transport and the WebView lie outside what
// this covers.
func TestGroupReactionLiveFanOutTwoServers(t *testing.T) {
	alice, aliceID := syncPrimary(t)
	bob, bobID := syncPrimary(t)

	g := chatstore.Group{
		ID: "grp-1", Name: "Test Group", Epoch: 1,
		Members: []chatstore.GroupMember{
			{Account: aliceID.AccountNumber(), DHPub: dhBytes(aliceID), Role: chatstore.GroupRoleAdmin},
			{Account: bobID.AccountNumber(), DHPub: dhBytes(bobID), Role: chatstore.GroupRoleMember},
		},
	}
	injectGroup(t, alice, g)
	injectGroup(t, bob, g)

	// A message both members hold, so the reaction has a target on each side.
	gm, _ := protocol.NewGroupMessage(aliceID, "grp-1", "react to me", time.Now())
	msgID := chatstore.GroupMessageID("grp-1", aliceID.AccountNumber(), "react to me", gm.At)
	for _, s := range []*Server{alice, bob} {
		s.sessMu.Lock()
		s.deliverGroupInboundLocked(gm, false)
		s.sessMu.Unlock()
	}

	// Alice's onion dials bob, so her fan-out reaches his public /p2p handler.
	alice.onion = &groupTestOnion{fakeOnion: &fakeOnion{}, dial: syncFakeDialer{addr: bob.pubLn.Addr().String()}}

	react := func() *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"group": "grp-1", "id": msgID, "emoji": "👍"})
		req := httptest.NewRequest(http.MethodPost, "/api/groups/react", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		alice.handleGroupReact(rec, req, aliceID)
		return rec
	}

	// --- ADD (first toggle) ---
	if rec := react(); rec.Code != http.StatusOK {
		t.Fatalf("react add: status %d", rec.Code)
	}
	// Local apply is synchronous inside the handler, before the fan-out goroutine —
	// a clean boundary between "toggle broke" and "fan-out broke".
	if liveReactionCount(alice, msgID, "👍") != 1 {
		t.Fatal("alice's own reaction did not apply locally")
	}
	// The reaction crosses the wire and lands on bob.
	waitReactionCount(t, bob, msgID, "👍", 1)
	// It must arrive with a real timestamp — a zero At would lose every future LWW
	// comparison and silently freeze bob's copy.
	if r, ok := reactionEntry(bob, msgID, "👍", aliceID.AccountNumber()); !ok || r.Removed || r.At == 0 {
		t.Fatalf("bob's fanned-out reaction is wrong: entry=%+v ok=%v", r, ok)
	}

	// --- UN-REACT (second toggle, remove computed from alice's live state) ---
	if rec := react(); rec.Code != http.StatusOK {
		t.Fatalf("react remove: status %d", rec.Code)
	}
	if liveReactionCount(alice, msgID, "👍") != 0 {
		t.Fatal("alice's un-react did not apply locally")
	}
	waitReactionCount(t, bob, msgID, "👍", 0)
	// Convergence must be a TOMBSTONE, not an emptied slot: a physical removal would
	// let a later stale re-serve resurrect the reaction — the exact failure build 4
	// exists to prevent.
	if r, ok := reactionEntry(bob, msgID, "👍", aliceID.AccountNumber()); !ok || !r.Removed {
		t.Fatalf("bob did not converge to a tombstone after un-react: entry=%+v ok=%v", r, ok)
	}
}
