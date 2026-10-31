package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
	"github.com/molepipe/molepipe/backend/internal/session"
)

// befriend runs the real friend request/accept handshake over the in-process
// routing so both servers end up as mutually accepted contacts, each holding the
// other's X25519 DH key (populated from the exchanged signed cards). That DH key
// is what the v2 ratchet-init handler binds against in ratchetIdentityMatches, so
// establishing it through the genuine flow — not a hand-stuffed contact row —
// is what makes this an honest end-to-end test of the v2 path.
func befriend(t *testing.T, sA, sB *Server, accA, accB, tokA, tokB string) {
	t.Helper()
	if r := sA.do(t, "POST", "/api/friend-requests/send", `{"account":"`+codeOf(t, sB, tokB)+`"}`, authHdr(sA, tokA)); r.Code != http.StatusOK {
		t.Fatalf("send request: %d (%s)", r.Code, r.Body)
	}
	if r := sB.do(t, "POST", "/api/friend-requests/accept", `{"account":"`+accA+`"}`, authHdr(sB, tokB)); r.Code != http.StatusOK {
		t.Fatalf("accept: %d (%s)", r.Code, r.Body)
	}
	if got := contactStatus(t, sA, tokA, accB); got != "accepted" {
		t.Fatalf("A should be accepted after the reachable accept, got %q", got)
	}
	if got := contactStatus(t, sB, tokB, accA); got != "accepted" {
		t.Fatalf("B should be accepted, got %q", got)
	}
}

func hasMessage(t *testing.T, s *Server, tok, text string) bool {
	t.Helper()
	return strings.Contains(s.do(t, "GET", "/api/messages", "", authHdr(s, tok)).Body.String(), text)
}

// awaitMessage waits until the message text is visible through the API — used
// when a message is delivered out of band (e.g. an init the proxy forwards to B
// while telling A it failed) so there is no send call to synchronise on.
func awaitMessage(t *testing.T, s *Server, tok, text string) {
	t.Helper()
	for range 250 {
		if hasMessage(t, s, tok, text) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("message %q never arrived", text)
}

// messageCount reports how many stored messages contain text — a duplicate
// delivery shows up as a count above one.
func messageCount(t *testing.T, s *Server, tok, text string) int {
	t.Helper()
	return strings.Count(s.do(t, "GET", "/api/messages", "", authHdr(s, tok)).Body.String(), text)
}

// TestV2RatchetEndToEnd is the wiring proof for the Double Ratchet path: two
// servers with no prior session exchange messages in both directions and the
// crypto stands itself up transparently.
//
//   - A's first message to B has no session, so sendV2 fetches B's prekey bundle,
//     runs X3DH as the initiator, and ships an InitialRatchetEnvelope over
//     RatchetInitPath. B verifies, consumes the named one-time prekey, runs X3DH
//     as the responder, and decrypts.
//   - B's reply has a responder session already (created when it received A's
//     init), so it goes over the established RatchetMessagePath — and decrypting
//     it is what drives A's first receiving-chain DH ratchet step.
//   - A's second message rides the now fully-established sending chain.
//
// Delivery is asserted through the public API surface (POST /api/messages,
// GET /api/messages), so a green run means every layer from HTTP handler down to
// the AEAD is wired correctly.
func TestV2RatchetEndToEnd(t *testing.T) {
	sA, sB, accA, accB, tokA, tokB, bOnion := newPair(t)
	bOnion.up.Store(true) // both directions reachable for a real exchange
	befriend(t, sA, sB, accA, accB, tokA, tokB)

	// 1. A -> B: establishes the session (X3DH init over RatchetInitPath).
	sendAndAwait(t, sA, tokA, accB, "hello from A")
	if !hasMessage(t, sB, tokB, "hello from A") {
		t.Fatal("B never received A's establishing message")
	}
	// Both sides now hold a session for the peer.
	assertSession(t, sA, accB, "A->B established a session")
	assertSession(t, sB, accA, "B holds the responder session")

	// 2. B -> A: established path (RatchetMessagePath); drives A's recv ratchet.
	sendAndAwait(t, sB, tokB, accA, "hi back from B")
	if !hasMessage(t, sA, tokA, "hi back from B") {
		t.Fatal("A never received B's reply over the established session")
	}

	// 3. A -> B again: A's sending chain is fully established now.
	sendAndAwait(t, sA, tokA, accB, "second from A")
	if !hasMessage(t, sB, tokB, "second from A") {
		t.Fatal("B never received A's second message")
	}

	// 4. A few more round-trips to exercise the ratchet turning over repeatedly.
	sendAndAwait(t, sB, tokB, accA, "and B again")
	sendAndAwait(t, sA, tokA, accB, "third from A")
	if !hasMessage(t, sA, tokA, "and B again") || !hasMessage(t, sB, tokB, "third from A") {
		t.Fatal("later round-trips did not both land")
	}

	// The whole exchange must have established the session exactly ONCE: B should
	// have consumed exactly one one-time prekey. More than one would mean A
	// re-established on a later send instead of riding the ratchet — which is the
	// failure this assertion exists to catch, since a re-establishing sender would
	// otherwise let every message land green and hide the bug.
	if n := consumedOTPs(sB); n != 1 {
		t.Fatalf("expected exactly 1 one-time prekey consumed on B, got %d", n)
	}
}

// consumedOTPs counts one-time prekeys a server has marked consumed.
func consumedOTPs(s *Server) int {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	n := 0
	if s.prekeys != nil {
		for _, otp := range s.prekeys.OneTimePrekeys {
			if otp.Consumed {
				n++
			}
		}
	}
	return n
}

// TestV2RatchetInitFailureDoesNotPoisonSession is the regression test for the
// poisoning bug: if the very first handshake (X3DH init) is delivered but the
// send fails partway — the common case over real Tor, where the descriptor may
// not have propagated yet — the initiator must NOT flip the session to the
// established branch and start posting ordinary ratchet messages the peer cannot
// decrypt. It must resend the same handshake until the peer acks it.
//
// The setup routes A's outbound through a reverse proxy that lets the challenge
// and prekey-bundle fetch succeed (so A establishes its initiator session) but
// fails the init POST while "armed". Once disarmed, the retry must deliver.
func TestV2RatchetInitFailureDoesNotPoisonSession(t *testing.T) {
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

	var sA, sB *Server
	// A reverse proxy in front of B that fails the ratchet-init POST while armed,
	// but passes the challenge and prekey-bundle fetch through unharmed.
	var armed atomic.Bool
	armed.Store(true)
	var proxy *httptest.Server
	proxy = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protocol.RatchetInitPath && armed.Load() {
			http.Error(w, "init boom", http.StatusServiceUnavailable)
			return
		}
		rp := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: sB.publicAddr()})
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(proxy.Close)
	proxyAddr := strings.TrimPrefix(proxy.URL, "http://")

	// A dials the proxy; B dials A directly.
	sA = New(storeA, &routeOnion{target: func() string { return proxyAddr }})
	sB = New(storeB, &routeOnion{target: func() string { return sA.publicAddr() }})
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
	tokA, tokB := unlock(sA), unlock(sB)
	befriend(t, sA, sB, accA, accB, tokA, tokB)

	// A sends while the init POST is failing. The message stays queued; A must NOT
	// mark the session usable — a pending handshake is recorded instead.
	id := sendFireAndForget(t, sA, tokA, accB, "establish me")
	awaitFailedAttempt(t, sA, id)
	if !hasPendingInit(sA, accB) {
		t.Fatal("A should hold a pending (unacked) handshake after the init send failed")
	}
	if hasMessage(t, sB, tokB, "establish me") {
		t.Fatal("B must not have received a message while the handshake was failing")
	}

	// The proxy heals; the retry must resend the SAME handshake and land it.
	armed.Store(false)
	idA, ok := sA.vault.get(tokA)
	if !ok {
		t.Fatal("A's vault is locked")
	}
	sA.outboxTick(context.Background(), idA)
	awaitDelivered(t, sA, id)
	if !hasMessage(t, sB, tokB, "establish me") {
		t.Fatal("B never received the message after the handshake healed")
	}
	if hasPendingInit(sA, accB) {
		t.Fatal("A should have cleared the pending handshake once acked")
	}
	// And the session now works for an ordinary follow-up message both ways.
	sendAndAwait(t, sA, tokA, accB, "now established")
	if !hasMessage(t, sB, tokB, "now established") {
		t.Fatal("established-path message did not land after recovery")
	}
	if n := consumedOTPs(sB); n != 1 {
		t.Fatalf("recovery must consume exactly one OTP, got %d", n)
	}
}

// TestV2RatchetAckLostSurvivesOTPCleanup is the regression test for the
// cleanup-vs-idempotency interaction: the initiator's very first handshake
// REACHES the responder (which establishes the session, consumes its one-time
// prekey, and delivers the message) but the ACK is lost, so the initiator keeps
// resending the same handshake. Between the original delivery and the resend,
// the responder restarts — and its prekey cleanup drops the now-consumed
// one-time prekey row. A resend must still be recognised as an already-processed
// handshake (keyed on the init signature, which survives the cleanup and the
// restart) and acked idempotently, rather than re-establishing (impossible — the
// prekey is gone) and failing forever, which would re-poison the session.
//
// The setup routes A's outbound through a proxy that, while armed, forwards the
// init to B so B genuinely processes it, then returns 503 to A — an ack-lost
// delivery, distinct from the init-lost case in the poisoning test above.
func TestV2RatchetAckLostSurvivesOTPCleanup(t *testing.T) {
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

	var sA, sB *Server
	var armed atomic.Bool
	armed.Store(true)
	var proxy *httptest.Server
	proxy = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protocol.RatchetInitPath && armed.Load() {
			// Forward the init to B so it actually processes the handshake...
			body, _ := io.ReadAll(r.Body)
			req, _ := http.NewRequest(r.Method, "http://"+sB.publicAddr()+r.URL.Path, bytes.NewReader(body))
			req.Header = r.Header.Clone()
			if resp, err := http.DefaultClient.Do(req); err == nil {
				resp.Body.Close()
			}
			// ...but tell A it failed, so A keeps resending: the ack was lost.
			http.Error(w, "ack lost", http.StatusServiceUnavailable)
			return
		}
		rp := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: sB.publicAddr()})
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(proxy.Close)
	proxyAddr := strings.TrimPrefix(proxy.URL, "http://")

	sA = New(storeA, &routeOnion{target: func() string { return proxyAddr }})
	sB = New(storeB, &routeOnion{target: func() string { return sA.publicAddr() }})
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
	tokA, tokB := unlock(sA), unlock(sB)
	befriend(t, sA, sB, accA, accB, tokA, tokB)

	// A sends; the proxy delivers the init to B but reports failure to A.
	id := sendFireAndForget(t, sA, tokA, accB, "ack lost then cleanup")
	awaitFailedAttempt(t, sA, id)
	// This is the ack-lost case: B really did receive and process the handshake.
	awaitMessage(t, sB, tokB, "ack lost then cleanup")
	if !hasPendingInit(sA, accB) {
		t.Fatal("A should still hold the pending handshake — its ack was lost")
	}
	if got := consumedOTPs(sB); got != 1 {
		t.Fatalf("B should have consumed exactly one OTP processing the init, got %d", got)
	}

	// B restarts. Its prekey cleanup drops the consumed OTP row, destroying any
	// idempotency key that depended on the prekey still being present.
	sB.do(t, "POST", "/api/lock", "", authHdr(sB, tokB))
	r := sB.do(t, "POST", "/api/unlock", `{"password":"pw"}`, map[string]string{"Origin": sB.origin()})
	tokB2, _ := decode(t, r.Body)["session_token"].(string)
	if tokB2 == "" {
		t.Fatal("re-unlock failed")
	}
	if got := consumedOTPs(sB); got != 0 {
		t.Fatalf("cleanup should have dropped the consumed OTP row on unlock, got %d", got)
	}

	// The ack path heals. A resends the SAME init. B must recognise it as an
	// already-processed handshake (via the persisted signature) and ack it
	// idempotently — not try to re-establish against a prekey that no longer
	// exists, and not re-deliver the message.
	armed.Store(false)
	idA, ok := sA.vault.get(tokA)
	if !ok {
		t.Fatal("A's vault is locked")
	}
	sA.outboxTick(context.Background(), idA)
	awaitDelivered(t, sA, id)
	if hasPendingInit(sA, accB) {
		t.Fatal("A should have cleared the pending handshake after the idempotent ack")
	}
	if n := messageCount(t, sB, tokB2, "ack lost then cleanup"); n != 1 {
		t.Fatalf("B should hold exactly one copy of the message (no duplicate delivery), got %d", n)
	}
	// The session works for ordinary messages both ways afterwards.
	sendAndAwait(t, sA, tokA, accB, "established after ack-lost")
	if !hasMessage(t, sB, tokB2, "established after ack-lost") {
		t.Fatal("established-path message did not land after ack-lost recovery")
	}
}

func hasPendingInit(s *Server, account string) bool {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	_, ok := s.pendingInits[account]
	return ok
}

// sendFireAndForget posts a message and returns its id without waiting for
// delivery (the caller drives the outbox by hand).
func sendFireAndForget(t *testing.T, from *Server, tok, to, text string) string {
	t.Helper()
	r := from.do(t, "POST", "/api/messages", `{"to":"`+to+`","text":`+quote(text)+`}`, authHdr(from, tok))
	if r.Code != http.StatusOK {
		t.Fatalf("send: %d (%s)", r.Code, r.Body)
	}
	id, _ := decode(t, r.Body)["id"].(string)
	if id == "" {
		t.Fatal("send returned no message id")
	}
	return id
}

// awaitFailedAttempt waits until the message has at least one recorded delivery
// attempt (i.e. the background deliverNow has run and failed), without requiring
// it to reach the terminal Failed state.
func awaitFailedAttempt(t *testing.T, s *Server, msgID string) {
	t.Helper()
	for range 250 {
		s.sessMu.Lock()
		it, ok := s.outbox[msgID]
		s.sessMu.Unlock()
		if ok && it.Attempts > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("message never recorded a failed attempt")
}

// TestV2RatchetSurvivesRestart proves the ratchet session state is persisted:
// B locks and unlocks (dropping and reloading all session state from the
// encrypted store), and A's next message still decrypts on the reloaded session.
func TestV2RatchetSurvivesRestart(t *testing.T) {
	sA, sB, accA, accB, tokA, tokB, bOnion := newPair(t)
	bOnion.up.Store(true)
	befriend(t, sA, sB, accA, accB, tokA, tokB)

	sendAndAwait(t, sA, tokA, accB, "before restart")
	if !hasMessage(t, sB, tokB, "before restart") {
		t.Fatal("B never received the pre-restart message")
	}

	// Lock and unlock B — this flushes in-memory session state and reloads it
	// from disk, exactly as a process restart would.
	sB.do(t, "POST", "/api/lock", "", authHdr(sB, tokB))
	r := sB.do(t, "POST", "/api/unlock", `{"password":"pw"}`, map[string]string{"Origin": sB.origin()})
	tokB2, _ := decode(t, r.Body)["session_token"].(string)
	if tokB2 == "" {
		t.Fatal("re-unlock failed")
	}
	assertSession(t, sB, accA, "the responder session must survive a restart")

	// A sends again over the established session; B must still decrypt it on the
	// reloaded session rather than rejecting an undecryptable message.
	sendAndAwait(t, sA, tokA, accB, "after restart")
	if !hasMessage(t, sB, tokB2, "after restart") {
		t.Fatal("B did not decrypt the post-restart message on the reloaded session")
	}
}

// assertSession fails unless the server holds a persisted ratchet session for the
// given peer.
func assertSession(t *testing.T, s *Server, account, msg string) {
	t.Helper()
	mgr := s.ratchetMgr()
	if mgr == nil {
		t.Fatalf("%s: session manager is nil (locked?)", msg)
	}
	if _, ok := mgr.GetOrLoadSession(session.SessionKeyFor(account, "")); !ok {
		t.Fatalf("%s: no session held for %s", msg, account)
	}
}
