package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
)

// sendAndAwait posts a message and waits for the outbox to actually deliver it.
// Sending is asynchronous now, so "the API returned 200" only means the message
// was accepted — the recipient has not necessarily seen it yet.
func sendAndAwait(t *testing.T, from *Server, tok, to, text string) string {
	t.Helper()
	r := from.do(t, "POST", "/api/messages", `{"to":"`+to+`","text":`+quote(text)+`}`, authHdr(from, tok))
	if r.Code != http.StatusOK {
		t.Fatalf("send: %d (%s)", r.Code, r.Body)
	}
	id, _ := decode(t, r.Body)["id"].(string)
	if id == "" {
		t.Fatal("send returned no message id")
	}
	awaitDelivered(t, from, id)
	return id
}

// awaitDelivered blocks until the sender's copy stops being pending.
func awaitDelivered(t *testing.T, s *Server, msgID string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.sessMu.Lock()
		_, queued := s.outbox[msgID]
		s.sessMu.Unlock()
		if !queued {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	s.sessMu.Lock()
	it := s.outbox[msgID]
	s.sessMu.Unlock()
	t.Fatalf("message %s was never delivered (attempts=%d, last error %q)", msgID, it.Attempts, it.LastError)
}

// awaitFailed blocks until automatic retrying gives up on a message.
func awaitFailed(t *testing.T, s *Server, msgID string) chatstore.OutboxItem {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		s.sessMu.Lock()
		it, ok := s.outbox[msgID]
		s.sessMu.Unlock()
		if ok && it.Failed {
			return it
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("message %s never reached the failed state", msgID)
	return chatstore.OutboxItem{}
}

func quote(s string) string { return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"` }

// The point of the change: the compose box is not held open for the seconds a
// Tor circuit takes.
func TestSendReturnsImmediatelyAndDeliversInBackground(t *testing.T) {
	sA, sB, _, accB, tokA, tokB := friendedPair(t)

	r := sA.do(t, "POST", "/api/messages", `{"to":"`+accB+`","text":"async hello"}`, authHdr(sA, tokA))
	if r.Code != http.StatusOK {
		t.Fatalf("send: %d (%s)", r.Code, r.Body)
	}
	body := decode(t, r.Body)
	if body["status"] != "queued" {
		t.Errorf("expected the send to be queued, got %v", body["status"])
	}
	id, _ := body["id"].(string)

	// It is in the sender's conversation straight away, marked pending, so the
	// message never vanishes between being typed and being delivered.
	found := false
	for _, m := range messageIDs(t, sA, tokA) {
		if m["id"] == id {
			found = true
			if m["delivery"] != chatstore.DeliveryPending && m["delivery"] != nil {
				t.Errorf("queued message should be pending, got %v", m["delivery"])
			}
		}
	}
	if !found {
		t.Fatal("the queued message is not in the sender's conversation")
	}

	awaitDelivered(t, sA, id)
	if got := sB.do(t, "GET", "/api/messages", "", authHdr(sB, tokB)).Body.String(); !strings.Contains(got, "async hello") {
		t.Errorf("recipient never got it: %s", got)
	}
	// Delivered messages carry no delivery marker.
	for _, m := range messageIDs(t, sA, tokA) {
		if m["id"] == id && m["delivery"] != nil {
			t.Errorf("delivered message still marked %v", m["delivery"])
		}
	}
}

// A send that cannot get through must survive, be retried, and end up honestly
// marked rather than silently lost — the behaviour that was missing before.
func TestUndeliverableSendIsRetriedThenMarkedFailed(t *testing.T) {
	sA, sB, accA, accB, tokA, tokB := friendedPair(t)
	_ = sB
	_ = accA
	_ = tokB

	// Cut the route.
	sA.onion = &flakyOnion{target: func() string { return "127.0.0.1:1" }}
	sA.onion.(*flakyOnion).up.Store(false)

	r := sA.do(t, "POST", "/api/messages", `{"to":"`+accB+`","text":"into the void"}`, authHdr(sA, tokA))
	if r.Code != http.StatusOK {
		t.Fatalf("send should still be accepted: %d (%s)", r.Code, r.Body)
	}
	id, _ := decode(t, r.Body)["id"].(string)

	// It stays in the conversation the whole time rather than disappearing.
	if got := sA.do(t, "GET", "/api/messages", "", authHdr(sA, tokA)).Body.String(); !strings.Contains(got, "into the void") {
		t.Fatalf("the undelivered message left the conversation: %s", got)
	}

	// Drive attempts to the cap.
	idA, _ := sA.vault.get(tokA)
	for range outboxMaxAttempts {
		sA.outboxTick(t.Context(), idA)
	}
	it := awaitFailed(t, sA, id)
	if it.LastError == "" {
		t.Error("a failed send should record why")
	}

	// The UI gets what it needs to offer a retry.
	var row map[string]any
	for _, m := range messageIDs(t, sA, tokA) {
		if m["id"] == id {
			row = m
		}
	}
	if row["delivery"] != chatstore.DeliveryFailed {
		t.Fatalf("expected the message to be marked failed, got %v", row["delivery"])
	}
	if row["error"] == nil {
		t.Error("a failed message should carry an error for the sender to see")
	}
}

// Retry must re-arm the existing queue entry, never append a second copy.
func TestRetryDoesNotDuplicateTheMessage(t *testing.T) {
	sA, sB, _, accB, tokA, tokB := friendedPair(t)
	_ = tokB

	sA.onion = &flakyOnion{target: func() string { return sB.publicAddr() }}
	sA.onion.(*flakyOnion).up.Store(false)
	r := sA.do(t, "POST", "/api/messages", `{"to":"`+accB+`","text":"retry me"}`, authHdr(sA, tokA))
	id, _ := decode(t, r.Body)["id"].(string)
	idA, _ := sA.vault.get(tokA)
	for range outboxMaxAttempts {
		sA.outboxTick(t.Context(), idA)
	}
	awaitFailed(t, sA, id)

	// Route restored; the user taps retry.
	sA.onion.(*flakyOnion).up.Store(true)
	if r := sA.do(t, "POST", "/api/messages/retry", `{"id":"`+id+`"}`, authHdr(sA, tokA)); r.Code != http.StatusOK {
		t.Fatalf("retry: %d (%s)", r.Code, r.Body)
	}
	awaitDelivered(t, sA, id)

	n := 0
	for _, m := range messageIDs(t, sA, tokA) {
		if m["text"] == "retry me" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("retry duplicated the message: %d copies", n)
	}
	if got := sB.do(t, "GET", "/api/messages", "", authHdr(sB, tokB)).Body.String(); !strings.Contains(got, "retry me") {
		t.Errorf("recipient never got the retried message: %s", got)
	}
}

// The queue is the thing that must survive the app closing mid-send.
func TestOutboxSurvivesLockAndUnlock(t *testing.T) {
	sA, sB, _, accB, tokA, _ := friendedPair(t)
	sA.onion = &flakyOnion{target: func() string { return sB.publicAddr() }}
	sA.onion.(*flakyOnion).up.Store(false)

	r := sA.do(t, "POST", "/api/messages", `{"to":"`+accB+`","text":"survives a restart"}`, authHdr(sA, tokA))
	id, _ := decode(t, r.Body)["id"].(string)

	sA.do(t, "POST", "/api/lock", "", authHdr(sA, tokA))
	tok2 := unlockWithPassword(t, sA, "pw")

	sA.sessMu.Lock()
	_, queued := sA.outbox[id]
	sA.sessMu.Unlock()
	if !queued {
		t.Fatal("the queued message did not survive lock/unlock")
	}
	if got := sA.do(t, "GET", "/api/messages", "", authHdr(sA, tok2)).Body.String(); !strings.Contains(got, "survives a restart") {
		t.Errorf("the message left the conversation across a restart: %s", got)
	}
}

// A message deleted for everyone must stop being sent.
func TestDeletingAQueuedMessageCancelsDelivery(t *testing.T) {
	dir := t.TempDir()
	_ = dir
	at := time.Now()
	data := &chatstore.Data{
		Messages: []chatstore.Message{{Direction: "out", Peer: "p", Text: "oops", At: at, ID: "mid-1"}},
		Outbox:   []chatstore.OutboxItem{{ID: "mid-1", To: "p", Text: "oops", QueuedAt: at}},
		Deleted:  []string{"mid-1"},
	}
	merged := chatstore.Merge(data, &chatstore.Data{})
	if len(merged.Outbox) != 0 {
		t.Fatalf("a deleted message is still queued for delivery: %+v", merged.Outbox)
	}
	if len(merged.Messages) != 0 {
		t.Fatalf("a deleted message survived: %+v", merged.Messages)
	}
}
