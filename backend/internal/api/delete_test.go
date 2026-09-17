package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// friendedPair returns two servers that can reach each other and are already
// accepted contacts, so message tests start from a working conversation.
func friendedPair(t *testing.T) (sA, sB *Server, accA, accB, tokA, tokB string) {
	t.Helper()
	sA, sB, accA, accB, tokA, tokB, bOnion := newPair(t)
	bOnion.up.Store(true)
	if r := sA.do(t, "POST", "/api/friend-requests/send", `{"account":"`+accB+`"}`, authHdr(sA, tokA)); r.Code != http.StatusOK {
		t.Fatalf("send request: %d (%s)", r.Code, r.Body)
	}
	if r := sB.do(t, "POST", "/api/friend-requests/accept", `{"account":"`+accA+`"}`, authHdr(sB, tokB)); r.Code != http.StatusOK {
		t.Fatalf("accept: %d (%s)", r.Code, r.Body)
	}
	return sA, sB, accA, accB, tokA, tokB
}

func messageIDs(t *testing.T, s *Server, tok string) []map[string]any {
	t.Helper()
	body := decode(t, s.do(t, "GET", "/api/messages", "", authHdr(s, tok)).Body)
	var out []map[string]any
	for _, raw := range body["messages"].([]any) {
		out = append(out, raw.(map[string]any))
	}
	return out
}

func TestDeleteForEveryoneRemovesItFromBothSides(t *testing.T) {
	sA, sB, _, accB, tokA, tokB := friendedPair(t)

	sendAndAwait(t, sA, tokA, accB, "regrettable")
	if got := sB.do(t, "GET", "/api/messages", "", authHdr(sB, tokB)).Body.String(); !strings.Contains(got, "regrettable") {
		t.Fatalf("B never received it: %s", got)
	}

	msgs := messageIDs(t, sA, tokA)
	if len(msgs) != 1 {
		t.Fatalf("expected one message on A, got %d", len(msgs))
	}
	id, _ := msgs[0]["id"].(string)

	r := sA.do(t, "POST", "/api/messages/delete", `{"id":"`+id+`"}`, authHdr(sA, tokA))
	if r.Code != http.StatusOK {
		t.Fatalf("delete: %d (%s)", r.Code, r.Body)
	}
	// The caller is told whether it actually landed, not just "deleted".
	if reached, _ := decode(t, r.Body)["reached"].(bool); !reached {
		t.Error("reached should be true when the peer was reachable")
	}
	if got := sA.do(t, "GET", "/api/messages", "", authHdr(sA, tokA)).Body.String(); strings.Contains(got, "regrettable") {
		t.Errorf("the sender's own copy survived: %s", got)
	}
	if got := sB.do(t, "GET", "/api/messages", "", authHdr(sB, tokB)).Body.String(); strings.Contains(got, "regrettable") {
		t.Errorf("the recipient's copy survived: %s", got)
	}
}

// The security of the whole feature: a signature proves who is asking, not what
// they may delete. A peer must not be able to delete OUR words from OUR device.
func TestDeleteCannotRemoveTheRecipientsOwnMessages(t *testing.T) {
	sA, sB, accA, accB, tokA, tokB := friendedPair(t)

	// B sends to A. On A this is an inbound message from B; on B it is outbound.
	sendAndAwait(t, sB, tokB, accA, "from-b")
	// A sends to B. On A this is outbound.
	sendAndAwait(t, sA, tokA, accB, "from-a")

	// Find A's OWN outbound message id, and have B try to delete it.
	var ownID string
	for _, m := range messageIDs(t, sA, tokA) {
		if m["direction"] == "out" {
			ownID, _ = m["id"].(string)
		}
	}
	if ownID == "" {
		t.Fatal("A has no outbound message to target")
	}

	// Drive the hook directly: this is what a peer's verified request reaches.
	if err := sA.hookOnDeleteMessage(accB, ownID); err == nil {
		t.Fatal("a peer was allowed to delete the recipient's own outbound message")
	}
	if got := sA.do(t, "GET", "/api/messages", "", authHdr(sA, tokA)).Body.String(); !strings.Contains(got, "from-a") {
		t.Errorf("A's own message was removed by a peer's request: %s", got)
	}
}

// A third party must not be able to delete a message they did not send, even
// with a well-formed request naming the correct ID.
func TestDeleteFromWrongSenderIsRefused(t *testing.T) {
	sA, sB, accA, _, tokA, tokB := friendedPair(t)
	sendAndAwait(t, sB, tokB, accA, "b-said-this")
	_ = tokB

	var inID string
	for _, m := range messageIDs(t, sA, tokA) {
		if m["direction"] == "in" {
			inID, _ = m["id"].(string)
		}
	}
	if inID == "" {
		t.Fatal("A has no inbound message")
	}
	// Some other account asking to delete B's message.
	stranger := "6obmoy6chv7h53forcoiioehxcsd2mpfn7xtlbucc45agi7ltl4iqvqd"
	if err := sA.hookOnDeleteMessage(stranger, inID); err == nil {
		t.Fatal("a stranger was allowed to delete another account's message")
	}
	if got := sA.do(t, "GET", "/api/messages", "", authHdr(sA, tokA)).Body.String(); !strings.Contains(got, "b-said-this") {
		t.Errorf("the message was removed by a stranger's request: %s", got)
	}
}

// Delete-for-me ("local":true) is a purely local removal: it works on any
// message — even an INCOMING one, even one long past the recall window — it
// records a tombstone so redelivery can't resurrect it, and it never contacts
// the peer, so the peer's own copy is untouched.
func TestDeleteForMeRemovesAnyMessageLocallyAndResistsRedelivery(t *testing.T) {
	sA, sB, accA, _, tokA, tokB := friendedPair(t)
	sendAndAwait(t, sB, tokB, accA, "keep-on-theirs")

	// Grab A's inbound copy and age it well past the window, to prove local
	// delete ignores both the direction and the recall-window checks.
	var inID, sender, text string
	var at time.Time
	sA.sessMu.Lock()
	for i := range sA.messages {
		if sA.messages[i].Direction == "in" {
			sA.messages[i].At = time.Now().Add(-2 * deleteWindow)
			inID = sA.messages[i].ID
			sender = sA.messages[i].Peer
			text = sA.messages[i].Text
			at = sA.messages[i].At
		}
	}
	sA.sessMu.Unlock()
	if inID == "" {
		t.Fatal("A has no inbound message to delete")
	}

	r := sA.do(t, "POST", "/api/messages/delete", `{"id":"`+inID+`","local":true}`, authHdr(sA, tokA))
	if r.Code != http.StatusOK {
		t.Fatalf("local delete of an incoming, out-of-window message: got %d (%s)", r.Code, r.Body)
	}
	if !strings.Contains(r.Body.String(), `"local":true`) {
		t.Errorf("local delete response missing the local flag: %s", r.Body)
	}
	if got := sA.do(t, "GET", "/api/messages", "", authHdr(sA, tokA)).Body.String(); strings.Contains(got, "keep-on-theirs") {
		t.Errorf("locally-deleted message is still present: %s", got)
	}

	// Tombstone recorded, and a redelivery (mailbox re-fetch / relay) is refused.
	sA.sessMu.Lock()
	tomb := false
	for _, d := range sA.deleted {
		if d == inID {
			tomb = true
		}
	}
	revived := sA.deliverInboundLocked(sender, inID, text, at, protocol.Reply{})
	sA.sessMu.Unlock()
	if !tomb {
		t.Error("local delete recorded no tombstone")
	}
	if revived {
		t.Error("a redelivered copy of a locally-deleted message was accepted")
	}
	if got := sA.do(t, "GET", "/api/messages", "", authHdr(sA, tokA)).Body.String(); strings.Contains(got, "keep-on-theirs") {
		t.Errorf("locally-deleted message reappeared after redelivery: %s", got)
	}

	// The peer never heard about it: their copy is untouched (no SendDeleteMessage).
	if got := sB.do(t, "GET", "/api/messages", "", authHdr(sB, tokB)).Body.String(); !strings.Contains(got, "keep-on-theirs") {
		t.Errorf("the peer's copy was removed by a local-only delete: %s", got)
	}
}

func TestDeleteOnlyAppliesToYourOwnSentMessages(t *testing.T) {
	sA, sB, accA, _, tokA, tokB := friendedPair(t)
	sendAndAwait(t, sB, tokB, accA, "theirs")

	var inID string
	for _, m := range messageIDs(t, sA, tokA) {
		if m["direction"] == "in" {
			inID, _ = m["id"].(string)
		}
	}
	r := sA.do(t, "POST", "/api/messages/delete", `{"id":"`+inID+`"}`, authHdr(sA, tokA))
	if r.Code != http.StatusBadRequest {
		t.Fatalf("deleting a received message: got %d, want 400", r.Code)
	}
}

// The window is enforced against our OWN record of when the message arrived, so
// a peer cannot reach back into old history.
func TestDeleteWindowIsEnforcedOnBothSides(t *testing.T) {
	sA, sB, accA, accB, tokA, tokB := friendedPair(t)
	sendAndAwait(t, sA, tokA, accB, "old news")

	// Age both copies past the window.
	age := func(s *Server) {
		s.sessMu.Lock()
		for i := range s.messages {
			s.messages[i].At = time.Now().Add(-2 * deleteWindow)
			s.messages[i].ID = chatstore.MessageID(s.messages[i].Direction, s.messages[i].Peer, s.messages[i].Text, s.messages[i].At)
		}
		s.sessMu.Unlock()
	}
	age(sA)
	age(sB)

	var outID string
	for _, m := range messageIDs(t, sA, tokA) {
		if m["direction"] == "out" {
			outID, _ = m["id"].(string)
		}
	}
	if r := sA.do(t, "POST", "/api/messages/delete", `{"id":"`+outID+`"}`, authHdr(sA, tokA)); r.Code != http.StatusBadRequest {
		t.Fatalf("sender side should refuse an old message: got %d (%s)", r.Code, r.Body)
	}

	// And the recipient refuses too, even if a modified sender asks anyway.
	var inID string
	for _, m := range messageIDs(t, sB, tokB) {
		if m["direction"] == "in" {
			inID, _ = m["id"].(string)
		}
	}
	if err := sB.hookOnDeleteMessage(accA, inID); err == nil {
		t.Fatal("the recipient honoured a delete for a message older than the window")
	}
}

// A deletion must survive a sync with a device that still holds the message,
// otherwise the deletion silently undoes itself.
func TestDeletionIsNotResurrectedByMerge(t *testing.T) {
	at := time.Now()
	id := chatstore.MessageID("in", "peer", "hello", at)
	withMessage := &chatstore.Data{Messages: []chatstore.Message{{Direction: "in", Peer: "peer", Text: "hello", At: at, ID: id}}}
	deleted := &chatstore.Data{Deleted: []string{id}}

	merged := chatstore.Merge(withMessage, deleted)
	if len(merged.Messages) != 0 {
		t.Fatalf("a deleted message came back through merge: %+v", merged.Messages)
	}
	// And the other argument order, since sync runs both ways.
	merged2 := chatstore.Merge(deleted, &chatstore.Data{Messages: []chatstore.Message{{Direction: "in", Peer: "peer", Text: "hello", At: at, ID: id}}})
	if len(merged2.Messages) != 0 {
		t.Fatalf("a deleted message came back through merge (reversed): %+v", merged2.Messages)
	}
	if len(merged.Deleted) != 1 {
		t.Fatalf("the tombstone must survive the merge: %+v", merged.Deleted)
	}
}

func TestDeleteRequiresSessionAndOrigin(t *testing.T) {
	sA, _, _, accB, tokA, _ := friendedPair(t)
	sendAndAwait(t, sA, tokA, accB, "x")
	id, _ := messageIDs(t, sA, tokA)[0]["id"].(string)
	body := `{"id":"` + id + `"}`

	if r := sA.do(t, "POST", "/api/messages/delete", body, map[string]string{"Origin": sA.origin()}); r.Code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", r.Code)
	}
	if r := sA.do(t, "POST", "/api/messages/delete", body,
		map[string]string{"Authorization": "Bearer " + tokA}); r.Code != http.StatusForbidden {
		t.Fatalf("no origin: got %d, want 403", r.Code)
	}
}

// An unreachable recipient is reported honestly rather than claimed as done.
func TestDeleteReportsWhenThePeerWasNotReached(t *testing.T) {
	sA, sB, accA, accB, tokA, tokB := friendedPair(t)
	_ = sB
	_ = accA
	sendAndAwait(t, sA, tokA, accB, "unreachable")
	_ = tokB

	// Take B's listener away so the delete cannot be delivered.
	sB.Shutdown(nil)

	id, _ := messageIDs(t, sA, tokA)[0]["id"].(string)
	r := sA.do(t, "POST", "/api/messages/delete", `{"id":"`+id+`"}`, authHdr(sA, tokA))
	if r.Code != http.StatusOK {
		t.Fatalf("delete: got %d, want 200 (%s)", r.Code, r.Body)
	}
	if reached, _ := decode(t, r.Body)["reached"].(bool); reached {
		t.Error("reached must be false when the peer could not be contacted")
	}
	// Our own copy still goes, and stays gone.
	if got := sA.do(t, "GET", "/api/messages", "", authHdr(sA, tokA)).Body.String(); strings.Contains(got, "unreachable") {
		t.Errorf("the local copy should still be removed: %s", got)
	}
}

// A client that gives up must not cancel delivery in flight. Before delivery
// contexts were decoupled from r.Context(), a browser tab closing mid-send
// aborted the write — observed on live Tor truncating a mailbox drop-off
// partway through the POST.
func TestDeliverySurvivesClientDisconnect(t *testing.T) {
	sA, sB, _, accB, tokA, tokB := friendedPair(t)

	// A request whose context is already dead, exactly as it would be after the
	// client hung up.
	dead, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest("POST", "/api/messages",
		strings.NewReader(`{"to":"`+accB+`","text":"sent as the tab closed"}`)).WithContext(dead)
	req.Host = "127.0.0.1:" + sA.port
	req.Header.Set("Origin", sA.origin())
	req.Header.Set("Authorization", "Bearer "+tokA)
	req.Header.Set("X-Control-Token", sA.controlToken)
	rr := httptest.NewRecorder()
	sA.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("send with a disconnected client: got %d, want 200 (%s)", rr.Code, rr.Body)
	}
	id, _ := decode(t, rr.Body)["id"].(string)
	awaitDelivered(t, sA, id)
	if got := sB.do(t, "GET", "/api/messages", "", authHdr(sB, tokB)).Body.String(); !strings.Contains(got, "sent as the tab closed") {
		t.Errorf("the message was not delivered after the client disconnected: %s", got)
	}
}
