package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
	"github.com/molepipe/molepipe/backend/internal/tor"
	"github.com/molepipe/molepipe/backend/internal/unlockguard"
)

// routeOnion is a test OnionService whose Dialer routes to a fixed peer address
// (the other server's public listener), so two servers can talk without Tor.
type routeOnion struct{ target func() string }

func (o *routeOnion) Start(context.Context, tor.OnionKey, string) (string, error) {
	return "test.onion", nil
}
func (o *routeOnion) Ready() bool                       { return true }
func (o *routeOnion) Dialable() bool                    { return true }
func (o *routeOnion) StartClient(context.Context) error { return nil }
func (o *routeOnion) Sweep() error                      { return nil }
func (o *routeOnion) Stop() error                       { return nil }
func (o *routeOnion) Dialer() tor.Dialer                { return fixedDialer{o.target} }
func (o *routeOnion) BootstrapFrac() float32            { return 1.0 }
func (o *routeOnion) LogLines() []string                { return nil }

type fixedDialer struct{ target func() string }

func (d fixedDialer) DialOnion(_ context.Context, _ string) (net.Conn, error) {
	return net.Dial("tcp", d.target())
}

// newTestServer builds a server with a created identity and a live loopback
// listener so s.port/URL are populated and Origin/Host checks are exercised
// against real values. Returns the server and the identity's password.
func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	store, err := identity.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	const pw = "test-password"
	if err := store.Save(id, []byte(pw)); err != nil {
		t.Fatal(err)
	}
	s := New(store, nil)
	if _, err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(nil) })
	return s, pw
}

// do issues a request through the full middleware chain with a loopback Host.
func (s *Server) do(t *testing.T, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "127.0.0.1:" + s.port
	// The first-party UI carries the control-token capability on every /api call;
	// mirror that here so tests exercise the authorized path. A test can still
	// override X-Control-Token via headers to probe controlGuard directly.
	req.Header.Set("X-Control-Token", s.controlToken)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	return rr
}

func (s *Server) origin() string { return s.URL() }

func decode(t *testing.T, r io.Reader) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(r).Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return m
}

func TestUnlockThenIdentity(t *testing.T) {
	s, pw := newTestServer(t)

	// Wrong password → 401, no token.
	bad := s.do(t, "POST", "/api/unlock", `{"password":"nope"}`,
		map[string]string{"Origin": s.origin()})
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: got %d, want 401", bad.Code)
	}

	// Correct password → 200 + token + account number.
	ok := s.do(t, "POST", "/api/unlock", `{"password":"`+pw+`"}`,
		map[string]string{"Origin": s.origin()})
	if ok.Code != http.StatusOK {
		t.Fatalf("unlock: got %d, want 200 (%s)", ok.Code, ok.Body)
	}
	body := decode(t, ok.Body)
	token, _ := body["session_token"].(string)
	if token == "" {
		t.Fatal("no session token returned")
	}
	acct, _ := body["account_number"].(string)
	if len(acct) != 56 {
		t.Fatalf("account number looks wrong: %q", acct)
	}

	// /api/identity with the token → 200 + same account.
	idResp := s.do(t, "GET", "/api/identity", "",
		map[string]string{"Authorization": "Bearer " + token})
	if idResp.Code != http.StatusOK {
		t.Fatalf("identity: got %d, want 200", idResp.Code)
	}
	if decode(t, idResp.Body)["account_number"] != acct {
		t.Fatal("identity account number mismatch")
	}
}

func TestIdentityRequiresToken(t *testing.T) {
	s, _ := newTestServer(t)
	// No token.
	if r := s.do(t, "GET", "/api/identity", "", nil); r.Code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", r.Code)
	}
	// Wrong token.
	r := s.do(t, "GET", "/api/identity", "",
		map[string]string{"Authorization": "Bearer wrongtoken"})
	if r.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: got %d, want 401", r.Code)
	}
}

func TestStatusIsTokenlessAndHidesAccount(t *testing.T) {
	s, _ := newTestServer(t)
	r := s.do(t, "GET", "/api/status", "", nil)
	if r.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", r.Code)
	}
	body := decode(t, r.Body)
	if body["has_identity"] != true {
		t.Error("expected has_identity=true")
	}
	if _, leaked := body["account_number"]; leaked {
		t.Error("status leaked the account number")
	}
}

func TestUnlockRejectsMissingOrigin(t *testing.T) {
	s, pw := newTestServer(t)
	// Absent Origin must fail closed.
	r := s.do(t, "POST", "/api/unlock", `{"password":"`+pw+`"}`, nil)
	if r.Code != http.StatusForbidden {
		t.Fatalf("missing origin: got %d, want 403", r.Code)
	}
}

func TestUnlockRejectsForeignOrigin(t *testing.T) {
	s, pw := newTestServer(t)
	r := s.do(t, "POST", "/api/unlock", `{"password":"`+pw+`"}`,
		map[string]string{"Origin": "https://evil.example"})
	if r.Code != http.StatusForbidden {
		t.Fatalf("foreign origin: got %d, want 403", r.Code)
	}
}

func TestRejectsForeignHost(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Host = "evil.example" // DNS-rebinding attacker's Host
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("foreign host: got %d, want 403", rr.Code)
	}
}

func TestLockClearsVault(t *testing.T) {
	s, pw := newTestServer(t)
	unlock := s.do(t, "POST", "/api/unlock", `{"password":"`+pw+`"}`,
		map[string]string{"Origin": s.origin()})
	token := decode(t, unlock.Body)["session_token"].(string)

	// Lock with token + origin.
	lock := s.do(t, "POST", "/api/lock", "",
		map[string]string{"Authorization": "Bearer " + token, "Origin": s.origin()})
	if lock.Code != http.StatusOK {
		t.Fatalf("lock: got %d, want 200", lock.Code)
	}
	if s.vault.unlocked() {
		t.Error("vault still unlocked after lock")
	}
	// The old token must no longer work.
	after := s.do(t, "GET", "/api/identity", "",
		map[string]string{"Authorization": "Bearer " + token})
	if after.Code != http.StatusUnauthorized {
		t.Fatalf("identity after lock: got %d, want 401", after.Code)
	}
}

// fakeOnion is a test double for tor.OnionService — no real Arti/network.
type fakeOnion struct {
	mu           sync.Mutex
	started      int
	stopped      int
	swept        int
	lastAddr     string
	lastPubHex   string
	clientStarts int
}

// clientStarts counts client-mode starts, so tests can assert a secondary
// still brings Tor up rather than being left with no transport.
func (f *fakeOnion) StartClient(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clientStarts++
	return nil
}

func (f *fakeOnion) Start(_ context.Context, key tor.OnionKey, localAddr string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started++
	f.lastAddr = localAddr
	f.lastPubHex = hex.EncodeToString(key.Public[:])
	return "test.onion", nil
}
func (f *fakeOnion) Ready() bool        { return false }
func (f *fakeOnion) Dialable() bool     { return false }
func (f *fakeOnion) Dialer() tor.Dialer { return tor.SocksDialer{} }
func (f *fakeOnion) Sweep() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.swept++
	return nil
}
func (f *fakeOnion) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped++
	return nil
}
func (f *fakeOnion) BootstrapFrac() float32 { return 0 }
func (f *fakeOnion) LogLines() []string     { return nil }

// Unlock must start the onion service, pointed at the PUBLIC listener (never the
// control port); lock must stop it.
func TestOnionLifecycleOnUnlockLock(t *testing.T) {
	store, err := identity.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	const pw = "pw"
	if err := store.Save(id, []byte(pw)); err != nil {
		t.Fatal(err)
	}
	fake := &fakeOnion{}
	s := New(store, fake)
	if _, err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(nil) })

	// Startup (locked) must sweep any stale onion key from a prior run.
	fake.mu.Lock()
	swept := fake.swept
	fake.mu.Unlock()
	if swept != 1 {
		t.Errorf("Sweep called %d times at startup, want 1", swept)
	}

	unlock := s.do(t, "POST", "/api/unlock", `{"password":"`+pw+`"}`,
		map[string]string{"Origin": s.origin()})
	token := decode(t, unlock.Body)["session_token"].(string)
	s.WaitReady()

	fake.mu.Lock()
	started, stoppedAfterUnlock, addr := fake.started, fake.stopped, fake.lastAddr
	fake.mu.Unlock()
	if started != 1 {
		t.Fatalf("onion Start called %d times, want 1", started)
	}
	if addr != s.publicAddr() {
		t.Errorf("onion forwards to %q, want the public listener %q (never the control port)", addr, s.publicAddr())
	}
	if addr == s.URL()[len("http://"):] {
		t.Error("onion is pointed at the control port — control plane would be exposed over Tor")
	}

	// A normal Log out (no erase-after-failed-unlocks policy) DEFERS the onion
	// teardown by a grace window so a quick re-unlock stays reachable — it must
	// NOT stop the onion immediately, and a teardown must be pending.
	s.do(t, "POST", "/api/lock", "",
		map[string]string{"Authorization": "Bearer " + token, "Origin": s.origin()})
	fake.mu.Lock()
	stoppedAfterLock := fake.stopped
	fake.mu.Unlock()
	if stoppedAfterLock != stoppedAfterUnlock {
		t.Errorf("onion stopped immediately on lock (%d→%d); the grace should defer it", stoppedAfterUnlock, stoppedAfterLock)
	}
	s.graceMu.Lock()
	pending := s.graceTimer != nil
	s.graceMu.Unlock()
	if !pending {
		t.Error("no grace teardown pending after a normal lock")
	}
}

// graceTestServer builds an unlocked-capable server with a fake onion.
func graceTestServer(t *testing.T) (*Server, *fakeOnion, string) {
	t.Helper()
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
	fake := &fakeOnion{}
	s := New(store, fake)
	if _, err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(nil) })
	return s, fake, "pw"
}

// A quick re-unlock inside the grace window reuses the still-running onion: no
// second Start (no republish) and the pending teardown is cancelled.
func TestLockGraceReuseOnQuickUnlock(t *testing.T) {
	s, fake, pw := graceTestServer(t)
	unlock := func() string {
		r := s.do(t, "POST", "/api/unlock", `{"password":"`+pw+`"}`, map[string]string{"Origin": s.origin()})
		s.WaitReady()
		return decode(t, r.Body)["session_token"].(string)
	}
	tok := unlock()
	fake.mu.Lock()
	started1, stopped1 := fake.started, fake.stopped
	fake.mu.Unlock()

	s.do(t, "POST", "/api/lock", "", map[string]string{"Authorization": "Bearer " + tok, "Origin": s.origin()})
	_ = unlock() // re-unlock within the grace window

	fake.mu.Lock()
	started2, stopped2 := fake.started, fake.stopped
	fake.mu.Unlock()
	if started2 != started1 {
		t.Errorf("re-unlock within grace re-Started the onion (%d→%d); it should reuse the running one", started1, started2)
	}
	if stopped2 != stopped1 {
		t.Errorf("re-unlock within grace stopped the onion (%d→%d); grace should cancel without teardown", stopped1, stopped2)
	}
	s.graceMu.Lock()
	pending := s.graceTimer != nil
	s.graceMu.Unlock()
	if pending {
		t.Error("grace teardown still pending after re-unlock; it should be cancelled")
	}
}

// With erase-after-failed-unlocks enabled (higher-threat posture), a lock tears
// the onion down immediately — no grace, no key left at rest.
func TestLockWipeEnabledStopsImmediately(t *testing.T) {
	s, fake, pw := graceTestServer(t)
	if err := s.guard.SetWipePolicy(true, unlockguard.DefaultWipeThreshold); err != nil {
		t.Fatal(err)
	}
	r := s.do(t, "POST", "/api/unlock", `{"password":"`+pw+`"}`, map[string]string{"Origin": s.origin()})
	tok := decode(t, r.Body)["session_token"].(string)
	fake.mu.Lock()
	stopped1 := fake.stopped
	fake.mu.Unlock()

	s.do(t, "POST", "/api/lock", "", map[string]string{"Authorization": "Bearer " + tok, "Origin": s.origin()})
	fake.mu.Lock()
	stopped2 := fake.stopped
	fake.mu.Unlock()
	if stopped2 <= stopped1 {
		t.Errorf("wipe-enabled lock did not stop the onion immediately (%d→%d)", stopped1, stopped2)
	}
	s.graceMu.Lock()
	pending := s.graceTimer != nil
	s.graceMu.Unlock()
	if pending {
		t.Error("wipe-enabled lock armed a grace teardown; it must tear down at once")
	}
}

// The onion-facing public handler serves any Host (a .onion peer request); the
// control routes reject the same request — the control plane is never on Tor.
func TestPublicListenerServesOnionHostControlRejects(t *testing.T) {
	s, _ := newTestServer(t)

	ctrl := s.do(t, "GET", "/", "", nil) // loopback Host from do()
	_ = ctrl

	// Control rejects a .onion Host outright.
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "abcdef.onion"
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("control accepted .onion Host: %d", rr.Code)
	}

	// Public handler serves it.
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Host = "abcdef.onion"
	rr2 := httptest.NewRecorder()
	logRequests(http.HandlerFunc(s.handlePublicRoot)).ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("public handler rejected .onion Host: %d", rr2.Code)
	}
	if !strings.Contains(rr2.Body.String(), "reachable") {
		t.Errorf("unexpected public body: %q", rr2.Body.String())
	}
}

// The control server must send a strict CSP that forbids external connections,
// so the no-external-calls guarantee is browser-enforced, not audit-only.
func TestSecurityHeaders(t *testing.T) {
	s, _ := newTestServer(t)
	rr := s.do(t, "GET", "/api/status", "", nil)

	csp := rr.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "connect-src 'self'", "script-src 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q; got %q", want, csp)
		}
	}
	if strings.Contains(csp, "connect-src 'self' ") && strings.Contains(csp, "http") {
		t.Errorf("CSP appears to allow an external host: %q", csp)
	}
	// connect-src must allow blob: so the UI can fetch a page-created image blob
	// back out for gallery-save and forward-to-another-chat. A revert to bare
	// 'self' silently rebreaks both (fetch(blob:) → "Failed to fetch").
	if !strings.Contains(csp, "connect-src 'self' blob:") {
		t.Errorf("CSP must allow blob: in connect-src for image save/forward; got %q", csp)
	}
	if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := rr.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
}

// Contacts and messages must survive a lock + fresh server restart, decrypted
// under the identity's seed-derived key.
func TestContactsAndMessagesPersist(t *testing.T) {
	dir := t.TempDir()
	store, err := identity.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	const pw = "pw"
	if err := store.Save(id, []byte(pw)); err != nil {
		t.Fatal(err)
	}
	peer, _ := identity.New()
	peerAcct := peer.AccountNumber()

	// Session 1: unlock, add a contact, receive a message, then shut down.
	s1 := New(store, nil)
	if _, err := s1.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	tok1 := decode(t, s1.do(t, "POST", "/api/unlock", `{"password":"`+pw+`"}`,
		map[string]string{"Origin": s1.origin()}).Body)["session_token"].(string)
	add := s1.do(t, "POST", "/api/contacts", `{"account":"`+peerAcct+`","name":"Peer"}`,
		map[string]string{"Origin": s1.origin(), "Authorization": "Bearer " + tok1})
	if add.Code != http.StatusOK {
		t.Fatalf("add contact: %d", add.Code)
	}
	s1.deliverMessage(peerAcct, "", "persisted hello", protocol.Reply{}) // simulate an inbound message
	s1.Shutdown(nil)                                   // clears memory, keeps the encrypted file

	// Session 2: brand-new server over the same data dir + identity.
	store2, _ := identity.NewStore(dir)
	s2 := New(store2, nil)
	if _, err := s2.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s2.Shutdown(nil) })
	tok2 := decode(t, s2.do(t, "POST", "/api/unlock", `{"password":"`+pw+`"}`,
		map[string]string{"Origin": s2.origin()}).Body)["session_token"].(string)

	contacts := s2.do(t, "GET", "/api/contacts", "", map[string]string{"Authorization": "Bearer " + tok2})
	if !strings.Contains(contacts.Body.String(), peerAcct) {
		t.Error("contact did not persist across restart")
	}
	msgs := s2.do(t, "GET", "/api/messages", "", map[string]string{"Authorization": "Bearer " + tok2})
	if !strings.Contains(msgs.Body.String(), "persisted hello") {
		t.Error("message did not persist across restart")
	}
}

// The full friend-request state machine across two servers dialing each other:
// request → pending → accept → both accepted → message flows; and messaging is
// blocked until acceptance.
func TestFriendRequestFlow(t *testing.T) {
	mk := func() (*identity.Store, string) {
		dir := t.TempDir()
		store, _ := identity.NewStore(dir)
		id, _ := identity.New()
		store.Save(id, []byte("pw"))
		return store, id.AccountNumber()
	}
	storeA, accA := mk()
	storeB, accB := mk()

	var sA, sB *Server
	sA = New(storeA, &routeOnion{target: func() string { return sB.publicAddr() }})
	sB = New(storeB, &routeOnion{target: func() string { return sA.publicAddr() }})
	for _, s := range []*Server{sA, sB} {
		if _, err := s.Start("127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Shutdown(nil) })
	}
	unlock := func(s *Server) string {
		return decode(t, s.do(t, "POST", "/api/unlock", `{"password":"pw"}`, map[string]string{"Origin": s.origin()}).Body)["session_token"].(string)
	}
	tokA, tokB := unlock(sA), unlock(sB)
	hdr := func(s *Server, tok string) map[string]string {
		return map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + tok}
	}

	// A cannot message B before they're friends.
	pre := sA.do(t, "POST", "/api/messages", `{"to":"`+accB+`","text":"early"}`, hdr(sA, tokA))
	if pre.Code == http.StatusOK {
		t.Fatal("messaging allowed before acceptance")
	}

	// A sends a friend request to B.
	sent := sA.do(t, "POST", "/api/friend-requests/send", `{"account":"`+accB+`"}`, hdr(sA, tokA))
	if sent.Code != http.StatusOK {
		t.Fatalf("send request: %d (%s)", sent.Code, sent.Body)
	}
	// B sees it as a pending request.
	reqs := sB.do(t, "GET", "/api/friend-requests", "", hdr(sB, tokB))
	if !strings.Contains(reqs.Body.String(), accA) {
		t.Fatalf("B has no pending request from A: %s", reqs.Body)
	}

	// B accepts → pushes accept back to A.
	acc := sB.do(t, "POST", "/api/friend-requests/accept", `{"account":"`+accA+`"}`, hdr(sB, tokB))
	if acc.Code != http.StatusOK {
		t.Fatalf("accept: %d (%s)", acc.Code, acc.Body)
	}

	// Both now list the other as an accepted contact (one contact each, so the
	// account and an "accepted" status both appearing confirms it).
	if cs := sB.do(t, "GET", "/api/contacts", "", hdr(sB, tokB)).Body.String(); !strings.Contains(cs, accA) || !strings.Contains(cs, `"status":"accepted"`) {
		t.Errorf("B does not have A accepted: %s", cs)
	}
	if cs := sA.do(t, "GET", "/api/contacts", "", hdr(sA, tokA)).Body.String(); !strings.Contains(cs, accB) || !strings.Contains(cs, `"status":"accepted"`) {
		t.Errorf("A does not have B accepted (accept push failed): %s", cs)
	}

	// A can now message B, and B receives it.
	sendAndAwait(t, sA, tokA, accB, "hey friend")
	if got := sB.do(t, "GET", "/api/messages", "", hdr(sB, tokB)).Body.String(); !strings.Contains(got, "hey friend") {
		t.Errorf("B did not receive the message: %s", got)
	}
}

// An accept for a request we never sent is rejected.
func TestFriendAcceptWithoutPendingRejected(t *testing.T) {
	store, err := identity.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := identity.New()
	store.Save(id, []byte("pw"))
	s := New(store, nil)
	if _, err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(nil) })
	s.do(t, "POST", "/api/unlock", `{"password":"pw"}`, map[string]string{"Origin": s.origin()})

	stranger, _ := identity.New()
	if err := s.hookOnFriendAccept(stranger.AccountNumber(), "Mallory", "some-req-id"); err == nil {
		t.Fatal("accept without a matching pending_out was applied")
	}
}

// Create an identity from the API, refuse to overwrite, unlock it, and recover
// the same account from its phrase on a fresh store.
func TestCreateUnlockRecoverFromAPI(t *testing.T) {
	dir := t.TempDir()
	store, _ := identity.NewStore(dir)
	s := New(store, nil)
	if _, err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(nil) })

	if store.Exists() {
		t.Fatal("identity should not exist before create")
	}
	create := s.do(t, "POST", "/api/create", `{"password":"Test1234!"}`, map[string]string{"Origin": s.origin()})
	if create.Code != http.StatusOK {
		t.Fatalf("create: %d (%s)", create.Code, create.Body)
	}
	body := decode(t, create.Body)
	acct, _ := body["account_number"].(string)
	phrase, _ := body["recovery_phrase"].(string)
	if len(acct) != 56 {
		t.Fatalf("bad account: %q", acct)
	}
	if len(strings.Fields(phrase)) != 24 {
		t.Fatalf("recovery phrase not 24 words: %q", phrase)
	}
	if !store.Exists() {
		t.Fatal("identity not saved")
	}
	// Refuse to overwrite.
	if again := s.do(t, "POST", "/api/create", `{"password":"x"}`, map[string]string{"Origin": s.origin()}); again.Code != http.StatusConflict {
		t.Fatalf("second create: got %d, want 409", again.Code)
	}
	// Unlock with the chosen password → same account.
	unlock := s.do(t, "POST", "/api/unlock", `{"password":"Test1234!"}`, map[string]string{"Origin": s.origin()})
	if unlock.Code != http.StatusOK || decode(t, unlock.Body)["account_number"] != acct {
		t.Fatalf("unlock after create failed: %d", unlock.Code)
	}

	// Recover the same account from the phrase on a fresh device.
	store2, _ := identity.NewStore(t.TempDir())
	s2 := New(store2, nil)
	if _, err := s2.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s2.Shutdown(nil) })
	body2, _ := json.Marshal(map[string]string{"mnemonic": phrase, "password": "Recover1!"})
	rec := s2.do(t, "POST", "/api/recover", string(body2), map[string]string{"Origin": s2.origin()})
	if rec.Code != http.StatusOK {
		t.Fatalf("recover: %d (%s)", rec.Code, rec.Body)
	}
	if decode(t, rec.Body)["account_number"] != acct {
		t.Error("recover did not reproduce the same account")
	}
}

func TestBlockAndDeleteContact(t *testing.T) {
	s, pw := newTestServer(t)
	tok := decode(t, s.do(t, "POST", "/api/unlock", `{"password":"`+pw+`"}`, map[string]string{"Origin": s.origin()}).Body)["session_token"].(string)
	hdr := map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + tok}

	peer, _ := identity.New()
	acct := peer.AccountNumber()
	s.do(t, "POST", "/api/contacts", `{"account":"`+acct+`","name":"P"}`, hdr)

	// Block → gone from the list and messages from them rejected.
	if b := s.do(t, "POST", "/api/contacts/block", `{"account":"`+acct+`"}`, hdr); b.Code != http.StatusOK {
		t.Fatalf("block: %d", b.Code)
	}
	if cs := s.do(t, "GET", "/api/contacts", "", hdr).Body.String(); strings.Contains(cs, acct) {
		t.Errorf("blocked contact still listed: %s", cs)
	}
	if s.hookAllowMessage(acct) {
		t.Error("blocked account can still message")
	}

	// Delete → gone.
	peer2, _ := identity.New()
	acct2 := peer2.AccountNumber()
	s.do(t, "POST", "/api/contacts", `{"account":"`+acct2+`","name":"Q"}`, hdr)
	if d := s.do(t, "POST", "/api/contacts/delete", `{"account":"`+acct2+`"}`, hdr); d.Code != http.StatusOK {
		t.Fatalf("delete: %d", d.Code)
	}
	if cs := s.do(t, "GET", "/api/contacts", "", hdr).Body.String(); strings.Contains(cs, acct2) {
		t.Errorf("deleted contact still listed: %s", cs)
	}
}

func TestUnlockNoIdentity(t *testing.T) {
	store, err := identity.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(store, nil)
	if _, err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(nil) })

	r := s.do(t, "POST", "/api/unlock", `{"password":"x"}`,
		map[string]string{"Origin": s.origin()})
	if r.Code != http.StatusConflict {
		t.Fatalf("unlock with no identity: got %d, want 409", r.Code)
	}
}

func TestRecoverPanic(t *testing.T) {
	// A handler that panics must not crash the process; recoverPanic should
	// catch it and return 500.
	panicker := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})
	handler := recoverPanic(panicker)

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
	if !strings.Contains(rr.Body.String(), "internal error") {
		t.Errorf("body = %q, want 'internal error'", rr.Body.String())
	}
}

func TestRecoverPanicPassesThrough(t *testing.T) {
	// A non-panicking handler must pass through unchanged.
	normal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	handler := recoverPanic(normal)

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if rr.Body.String() != "ok" {
		t.Errorf("body = %q, want 'ok'", rr.Body.String())
	}
}

func TestDisplayNameRejectsWhitespaceOnly(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"valid name", "Alice", "Alice", false},
		{"trimmed", "  Bob  ", "Bob", false},
		{"whitespace only", "   ", "", true},
		{"empty", "", "", true},
		{"tab and spaces", "\t\n  \n\t", "", true},
		{"unicode trimmed", "  \u00e9l\u00e8ve  ", "\u00e9l\u00e8ve", false},
		{"max length preserved", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678一二", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678一二", false},
		{"over max truncated", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789一二三四五六七八", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789一二", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateDisplayName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDisplayName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("validateDisplayName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
