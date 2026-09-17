package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/tor"
)

// flakyOnion can be reached inbound but its outbound dialing can be switched
// off — the state a peer is in when the other side's onion descriptor hasn't
// propagated yet, which is exactly what stranded a requester before the retry
// queue existed.
type flakyOnion struct {
	target func() string
	up     atomic.Bool
}

func (o *flakyOnion) Start(context.Context, tor.OnionKey, string) (string, error) {
	return "flaky.onion", nil
}
func (o *flakyOnion) Ready() bool                       { return true }
func (o *flakyOnion) Dialable() bool                    { return true }
func (o *flakyOnion) StartClient(context.Context) error { return nil }
func (o *flakyOnion) Sweep() error                      { return nil }
func (o *flakyOnion) Stop() error                       { return nil }
func (o *flakyOnion) Dialer() tor.Dialer                { return flakyDialer{o} }
func (o *flakyOnion) BootstrapFrac() float32            { return 1.0 }
func (o *flakyOnion) LogLines() []string                { return nil }

type flakyDialer struct{ o *flakyOnion }

func (d flakyDialer) DialOnion(_ context.Context, _ string) (net.Conn, error) {
	if !d.o.up.Load() {
		return nil, fmt.Errorf("onion unreachable (descriptor not published yet)")
	}
	return net.Dial("tcp", d.o.target())
}

// newPair builds two servers that can reach each other, with B's outbound
// dialing under test control.
func newPair(t *testing.T) (sA, sB *Server, accA, accB, tokA, tokB string, bOnion *flakyOnion) {
	t.Helper()
	mk := func() (*identity.Store, string) {
		store, err := identity.NewStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		id, err := identity.New()
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Save(id, []byte("pw")); err != nil {
			t.Fatal(err)
		}
		return store, id.AccountNumber()
	}
	storeA, accA := mk()
	storeB, accB := mk()

	bOnion = &flakyOnion{target: func() string { return sA.publicAddr() }}
	sA = New(storeA, &routeOnion{target: func() string { return sB.publicAddr() }})
	sB = New(storeB, bOnion)
	for _, s := range []*Server{sA, sB} {
		if _, err := s.Start("127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Shutdown(nil) })
	}
	unlock := func(s *Server) string {
		r := s.do(t, "POST", "/api/unlock", `{"password":"pw"}`, map[string]string{"Origin": s.origin()})
		tok, _ := decode(t, r.Body)["session_token"].(string)
		if tok == "" {
			t.Fatal("unlock returned no token")
		}
		return tok
	}
	return sA, sB, accA, accB, unlock(sA), unlock(sB), bOnion
}

func authHdr(s *Server, tok string) map[string]string {
	return map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + tok}
}

func contactStatus(t *testing.T, s *Server, tok, account string) string {
	t.Helper()
	body := decode(t, s.do(t, "GET", "/api/contacts", "", authHdr(s, tok)).Body)
	for _, raw := range body["contacts"].([]any) {
		c := raw.(map[string]any)
		if c["account"] == account {
			return c["status"].(string)
		}
	}
	return ""
}

// The bug: B accepts while unable to reach A, so A never learns and is stuck at
// pending_out forever — and A cannot repair it, because the only self-heal path
// is an inbound message, which A is not allowed to send.
func TestAcceptPushRetriesUntilItLands(t *testing.T) {
	sA, sB, accA, accB, tokA, tokB, bOnion := newPair(t)

	if r := sA.do(t, "POST", "/api/friend-requests/send", `{"account":"`+accB+`"}`, authHdr(sA, tokA)); r.Code != http.StatusOK {
		t.Fatalf("send request: %d (%s)", r.Code, r.Body)
	}

	// B accepts while its outbound dialing is down.
	bOnion.up.Store(false)
	r := sB.do(t, "POST", "/api/friend-requests/accept", `{"account":"`+accA+`"}`, authHdr(sB, tokB))
	if r.Code != http.StatusOK {
		t.Fatalf("accept: %d (%s)", r.Code, r.Body)
	}
	// The accepter is told honestly that the other side hasn't heard yet.
	if notified, _ := decode(t, r.Body)["notified"].(bool); notified {
		t.Fatal("accept reported notified=true even though the push could not be sent")
	}
	if got := contactStatus(t, sA, tokA, accB); got != "accepted" {
		t.Logf("A is stranded at %q, as expected before the retry", got)
	} else {
		t.Fatal("A should not be accepted yet — the push never went out")
	}
	// A cannot message B: the exact symptom that was reported.
	if r := sA.do(t, "POST", "/api/messages", `{"to":"`+accB+`","text":"hi"}`, authHdr(sA, tokA)); r.Code == http.StatusOK {
		t.Fatal("A should not be able to message B while stranded")
	}
	// B's UI can see the debt.
	cs := sB.do(t, "GET", "/api/contacts", "", authHdr(sB, tokB)).Body.String()
	if !strings.Contains(cs, `"awaiting_accept":true`) {
		t.Fatalf("B should report the undelivered accept: %s", cs)
	}

	// Tor comes good; the retry tick delivers.
	bOnion.up.Store(true)
	idB, ok := sB.vault.get(tokB)
	if !ok {
		t.Fatal("B's vault is locked")
	}
	sB.acceptRetryTick(context.Background(), idB)

	if got := contactStatus(t, sA, tokA, accB); got != "accepted" {
		t.Fatalf("A should be accepted after the retry, got %q", got)
	}
	if cs := sB.do(t, "GET", "/api/contacts", "", authHdr(sB, tokB)).Body.String(); strings.Contains(cs, `"awaiting_accept":true`) {
		t.Fatalf("B should have cleared the debt after delivery: %s", cs)
	}
	// And the pair now works in the direction that was broken.
	sendAndAwait(t, sA, tokA, accB, "hi at last")
	if got := sB.do(t, "GET", "/api/messages", "", authHdr(sB, tokB)).Body.String(); !strings.Contains(got, "hi at last") {
		t.Errorf("B did not receive the message: %s", got)
	}
}

// The queue survives a lock/unlock cycle — the process can die between the
// accept and the retry.
func TestPendingAcceptSurvivesRestart(t *testing.T) {
	sA, sB, accA, accB, tokA, tokB, bOnion := newPair(t)
	_ = accB

	sA.do(t, "POST", "/api/friend-requests/send", `{"account":"`+accB+`"}`, authHdr(sA, tokA))
	bOnion.up.Store(false)
	sB.do(t, "POST", "/api/friend-requests/accept", `{"account":"`+accA+`"}`, authHdr(sB, tokB))

	// Lock and unlock B, which drops and reloads all session state from disk.
	sB.do(t, "POST", "/api/lock", "", authHdr(sB, tokB))
	r := sB.do(t, "POST", "/api/unlock", `{"password":"pw"}`, map[string]string{"Origin": sB.origin()})
	tokB2, _ := decode(t, r.Body)["session_token"].(string)
	if tokB2 == "" {
		t.Fatal("re-unlock failed")
	}
	if cs := sB.do(t, "GET", "/api/contacts", "", authHdr(sB, tokB2)).Body.String(); !strings.Contains(cs, `"awaiting_accept":true`) {
		t.Fatalf("the pending accept did not survive a restart: %s", cs)
	}

	bOnion.up.Store(true)
	idB, _ := sB.vault.get(tokB2)
	sB.acceptRetryTick(context.Background(), idB)
	if got := contactStatus(t, sA, tokA, accB); got != "accepted" {
		t.Fatalf("A should be accepted after the post-restart retry, got %q", got)
	}
}

// A peer that answers and refuses is final — retrying that forever is noise.
// (A already has us accepted, so the refusal means the debt is settled.)
func TestRefusedAcceptIsDroppedNotRetriedForever(t *testing.T) {
	sA, sB, accA, accB, tokA, tokB, bOnion := newPair(t)

	sA.do(t, "POST", "/api/friend-requests/send", `{"account":"`+accB+`"}`, authHdr(sA, tokA))
	bOnion.up.Store(false)
	sB.do(t, "POST", "/api/friend-requests/accept", `{"account":"`+accA+`"}`, authHdr(sB, tokB))

	// A gets to accepted by another route (B messages A is not possible here, so
	// simulate the equivalent: A already holds B as accepted, making any further
	// accept a 400 "no matching pending request").
	sA.sessMu.Lock()
	c := sA.contacts[accB]
	c.Status = "accepted"
	c.ReqID = ""
	sA.contacts[accB] = c
	sA.persistLocked()
	sA.sessMu.Unlock()

	bOnion.up.Store(true)
	idB, _ := sB.vault.get(tokB)

	// One refusal must NOT be treated as final: the peer's 400 is opaque and
	// also covers transient causes (its nonces are wiped by a restart).
	sB.acceptRetryTick(context.Background(), idB)
	sB.sessMu.Lock()
	afterOne := sB.awaitingAcceptLocked(accA)
	sB.sessMu.Unlock()
	if !afterOne {
		t.Fatal("a single refusal must not drop the retry — it may have been transient")
	}

	// Consistently refused, though, means the debt really is settled.
	for range maxAcceptRefusals {
		sB.acceptRetryTick(context.Background(), idB)
	}
	sB.sessMu.Lock()
	still := sB.awaitingAcceptLocked(accA)
	sB.sessMu.Unlock()
	if still {
		t.Fatal("a persistently refused accept should be dropped, not retried forever")
	}
}

// A transport failure must reset the refusal count: "we couldn't reach them" is
// not evidence that the debt is settled, so it must never contribute to giving up.
func TestTransportFailureResetsRefusalCount(t *testing.T) {
	sA, sB, accA, accB, tokA, tokB, bOnion := newPair(t)

	sA.do(t, "POST", "/api/friend-requests/send", `{"account":"`+accB+`"}`, authHdr(sA, tokA))
	bOnion.up.Store(false)
	sB.do(t, "POST", "/api/friend-requests/accept", `{"account":"`+accA+`"}`, authHdr(sB, tokB))
	idB, _ := sB.vault.get(tokB)

	// Many unreachable ticks: the count must stay at zero, not creep towards
	// the cap and silently abandon a requester who is merely offline.
	for range maxAcceptRefusals * 2 {
		sB.acceptRetryTick(context.Background(), idB)
	}
	sB.sessMu.Lock()
	p, ok := sB.pendingAccepts[accA]
	sB.sessMu.Unlock()
	if !ok {
		t.Fatal("unreachable retries must never drop the pending accept")
	}
	if p.Refusals != 0 {
		t.Fatalf("transport failures must not count as refusals, got %d", p.Refusals)
	}

	// And it still delivers once the peer becomes reachable.
	bOnion.up.Store(true)
	sB.acceptRetryTick(context.Background(), idB)
	if got := contactStatus(t, sA, tokA, accB); got != "accepted" {
		t.Fatalf("A should be accepted once reachable, got %q", got)
	}
}
