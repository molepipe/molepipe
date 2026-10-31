package api

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
	"github.com/molepipe/molepipe/backend/internal/tor"
)

// helloQuery builds the stamp FetchProfileAs puts on the profile GET, signed by
// `from` and bound to `recipient`.
func helloQuery(from *identity.Identity, recipient string, ts int64) string {
	q := url.Values{}
	q.Set("from", from.AccountNumber())
	q.Set("ts", strconv.FormatInt(ts, 10))
	q.Set("sig", base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(from.Keys.Signing.Private, protocol.HelloSigningBlob(ts, recipient))))
	return "?" + q.Encode()
}

// profileGet hits the REAL handler and returns its status and body, so the
// non-oracle property is asserted against what peers actually see.
func profileGet(s *Server, query string) (int, string) {
	rec := httptest.NewRecorder()
	s.handleP2PProfile(rec, httptest.NewRequest("GET", protocol.ProfilePath+query, nil))
	return rec.Code, rec.Body.String()
}

func presenceOf(s *Server, acct string) string {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	return s.presence[acct]
}

// An accepted contact's verified hello promotes them to online WITHOUT our ever
// having dialed them. This is the whole point of the change: while our own
// descriptor is still publishing we are invisible to their probes, so their
// inbound hello is the only thing that can tell us they are there.
func TestPresenceHelloUpgradesAnAcceptedContact(t *testing.T) {
	s, id := mailboxTestServer(t, "127.0.0.1:1")
	alice, _ := identity.New()

	s.sessMu.Lock()
	s.contacts[alice.AccountNumber()] = chatstore.Contact{
		Account: alice.AccountNumber(), Status: chatstore.StatusAccepted,
	}
	s.presence = map[string]string{alice.AccountNumber(): presenceOffline}
	s.sessMu.Unlock()

	code, _ := profileGet(s, helloQuery(alice, id.AccountNumber(), time.Now().Unix()))
	if code != http.StatusOK {
		t.Fatalf("profile GET with a hello: got %d, want 200", code)
	}
	if got := presenceOf(s, alice.AccountNumber()); got != presenceOnline {
		t.Errorf("presence = %q, want %q", got, presenceOnline)
	}
}

// The endpoint must stay a non-oracle. /p2p/profile is public, so the card served
// to a valid hello, a forged one, and no hello at all has to be byte-identical —
// otherwise anyone on Tor could probe us to learn whether a given account is a
// contact of ours, which is the social-graph leak the gated mailbox closed.
func TestPresenceHelloNeverChangesTheResponse(t *testing.T) {
	s, id := mailboxTestServer(t, "127.0.0.1:1")
	alice, _ := identity.New()
	mallory, _ := identity.New()

	s.sessMu.Lock()
	s.contacts[alice.AccountNumber()] = chatstore.Contact{
		Account: alice.AccountNumber(), Status: chatstore.StatusAccepted,
	}
	s.sessMu.Unlock()

	ts := time.Now().Unix()
	codeBare, bodyBare := profileGet(s, "")
	codeGood, bodyGood := profileGet(s, helloQuery(alice, id.AccountNumber(), ts))
	// Mallory signs her own hello but claims to be alice: a forgery.
	forged := url.Values{}
	forged.Set("from", alice.AccountNumber())
	forged.Set("ts", strconv.FormatInt(ts, 10))
	forged.Set("sig", base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(mallory.Keys.Signing.Private, protocol.HelloSigningBlob(ts, id.AccountNumber()))))
	codeForged, bodyForged := profileGet(s, "?"+forged.Encode())
	// Junk that cannot even be parsed must take the same path.
	codeJunk, bodyJunk := profileGet(s, "?from=nonsense&ts=notanumber&sig=!!!")

	for _, c := range []struct {
		name string
		code int
		body string
	}{
		{"valid hello", codeGood, bodyGood},
		{"forged hello", codeForged, bodyForged},
		{"unparseable hello", codeJunk, bodyJunk},
	} {
		if c.code != codeBare || c.body != bodyBare {
			t.Errorf("%s changed the response (%d/%q vs bare %d/%q) — the endpoint is an oracle",
				c.name, c.code, c.body, codeBare, bodyBare)
		}
	}
	// The forgery must also not have moved presence. Asserted unconditionally from
	// a known-offline start: the valid hello above legitimately set online, so
	// reading presence as-is would only ever be checking that earlier call.
	s.sessMu.Lock()
	s.presence[alice.AccountNumber()] = presenceOffline
	s.sessMu.Unlock()
	profileGet(s, "?"+forged.Encode())
	if got := presenceOf(s, alice.AccountNumber()); got != presenceOffline {
		t.Errorf("a forged hello moved presence to %q", got)
	}
}

// A verified hello from someone who is not an accepted contact proves who they
// are, but not that we want to track them. The hook gates on status, so a
// stranger or a merely-pending contact gets no presence entry at all.
func TestPresenceHelloIgnoresNonContacts(t *testing.T) {
	s, id := mailboxTestServer(t, "127.0.0.1:1")
	stranger, _ := identity.New()
	pending, _ := identity.New()

	s.sessMu.Lock()
	s.contacts[pending.AccountNumber()] = chatstore.Contact{
		Account: pending.AccountNumber(), Status: chatstore.StatusPendingOut,
	}
	s.sessMu.Unlock()

	ts := time.Now().Unix()
	for _, who := range []*identity.Identity{stranger, pending} {
		if code, _ := profileGet(s, helloQuery(who, id.AccountNumber(), ts)); code != http.StatusOK {
			t.Fatalf("profile GET: got %d, want 200", code)
		}
		if got := presenceOf(s, who.AccountNumber()); got != "" {
			t.Errorf("non-contact %s got presence %q, want none", who.AccountNumber()[:8], got)
		}
	}
}

// The hook is upgrade-only. A hello proves THEY can reach US, which is not
// presence's usual claim (that we can reach them), so it may promote but must
// never downgrade — the outbound sweep stays authoritative. A hello arriving
// while a contact is already online must leave them online, and nothing the hook
// can be handed may write offline.
func TestPresenceHelloOnlyEverPromotes(t *testing.T) {
	s, _ := mailboxTestServer(t, "127.0.0.1:1")
	alice, _ := identity.New()

	s.sessMu.Lock()
	s.contacts[alice.AccountNumber()] = chatstore.Contact{
		Account: alice.AccountNumber(), Status: chatstore.StatusAccepted,
	}
	s.sessMu.Unlock()

	for _, start := range []string{presenceOffline, presenceMailbox, presenceUnknown, presenceOnline, ""} {
		s.sessMu.Lock()
		s.presence = map[string]string{alice.AccountNumber(): start}
		s.sessMu.Unlock()
		s.hookPeerOnline(alice.AccountNumber())
		if got := presenceOf(s, alice.AccountNumber()); got != presenceOnline {
			t.Errorf("from %q: presence = %q, want %q", start, got, presenceOnline)
		}
	}
}

// readyOnion is a routeOnion whose Ready() is controllable, so the publish gate
// can be driven both ways. Dialable stays true throughout: that is the real
// asymmetry — we can dial out long before our own descriptor is published.
type readyOnion struct {
	target func() string
	ready  atomic.Bool
}

func (o *readyOnion) Start(context.Context, tor.OnionKey, string) (string, error) {
	return "test.onion", nil
}
func (o *readyOnion) Ready() bool                       { return o.ready.Load() }
func (o *readyOnion) Dialable() bool                    { return true }
func (o *readyOnion) StartClient(context.Context) error { return nil }
func (o *readyOnion) Sweep() error                      { return nil }
func (o *readyOnion) Stop() error                       { return nil }
func (o *readyOnion) Dialer() tor.Dialer                { return fixedDialer{o.target} }
func (o *readyOnion) BootstrapFrac() float32            { return 1.0 }
func (o *readyOnion) LogLines() []string                { return nil }

// End to end over a real HTTP round trip: the probe stamps its profile fetch
// while our onion is unpublished, the peer on the other side verifies the stamp
// and marks us online — and once we are published the stamping stops, because a
// contact's own sweep can find us by then and the hello would be telling them
// what they can already see.
func TestProbeAnnouncesOnlyWhileUnpublished(t *testing.T) {
	bob, _ := identity.New()
	bobPeer := protocol.NewPeer(bob, protocol.Hooks{DisplayName: func() string { return "Bob" }})
	// Two counters, deliberately. `stamped` is whether the request CARRIED a
	// hello, which is what the publish gate decides; `announced` is whether bob
	// accepted it. Asserting only the latter would let the gate break silently:
	// two fetches in the same second produce the same ts and — ed25519 being
	// deterministic — the same signature, so bob's replay jar would reject the
	// second hello and keep `announced` at 1 whether the gate stamped or not.
	var stamped, announced atomic.Int64

	mux := http.NewServeMux()
	mux.HandleFunc(protocol.ProfilePath, func(w http.ResponseWriter, r *http.Request) {
		if q := r.URL.Query(); q.Get("from") != "" {
			stamped.Add(1)
			ts, _ := strconv.ParseInt(q.Get("ts"), 10, 64)
			sig, _ := base64.RawURLEncoding.DecodeString(q.Get("sig"))
			if bobPeer.ServeProfileHello(q.Get("from"), ts, sig) {
				announced.Add(1)
			}
		}
		writeJSON(w, http.StatusOK, bobPeer.ProfileCard())
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	onion := &readyOnion{target: func() string { return srv.Listener.Addr().String() }}
	s := newServerOnOnion(t, onion)
	tok := unlockOn(t, s)
	id, ok := s.vault.get(tok)
	if !ok {
		t.Fatal("session did not validate")
	}

	s.sessMu.Lock()
	s.contacts[bob.AccountNumber()] = chatstore.Contact{
		Account: bob.AccountNumber(), Status: chatstore.StatusAccepted,
	}
	s.sessMu.Unlock()

	// Unpublished: the stamp must ride the fetch, and bob must accept it.
	onion.ready.Store(false)
	if _, err := s.fetchProfileAnnouncing(context.Background(), id, bob.AccountNumber()); err != nil {
		t.Fatalf("probe while unpublished: %v", err)
	}
	if got := stamped.Load(); got != 1 {
		t.Fatalf("stamped fetches while unpublished = %d, want 1", got)
	}
	if got := announced.Load(); got != 1 {
		t.Fatalf("hellos accepted while unpublished = %d, want 1", got)
	}

	// Published: a contact's own sweep can reach us now, so stop announcing.
	onion.ready.Store(true)
	if _, err := s.fetchProfileAnnouncing(context.Background(), id, bob.AccountNumber()); err != nil {
		t.Fatalf("probe while published: %v", err)
	}
	if got := stamped.Load(); got != 1 {
		t.Errorf("stamped fetches after publishing = %d, want still 1 (steady state must not stamp)", got)
	}
	if got := announced.Load(); got != 1 {
		t.Errorf("hellos accepted after publishing = %d, want still 1", got)
	}

	// Flapped: the service re-established an intro point and Ready() dipped, but
	// the descriptor never left the HSDirs. Publication is latched, so the stamp
	// stays off — reading Ready() live here resumed announcing eight times on a
	// device that had been published for three minutes.
	onion.ready.Store(false)
	if _, err := s.fetchProfileAnnouncing(context.Background(), id, bob.AccountNumber()); err != nil {
		t.Fatalf("probe during a Ready() dip: %v", err)
	}
	if got := stamped.Load(); got != 1 {
		t.Errorf("stamped fetches after a Ready() dip = %d, want still 1 (publication is latched, not re-tested)", got)
	}

	// A genuine teardown is a republish: the new descriptor has to reach the
	// HSDirs before anyone can look us up, so the stamp comes back.
	s.forgetReachEvidence()
	if _, err := s.fetchProfileAnnouncing(context.Background(), id, bob.AccountNumber()); err != nil {
		t.Fatalf("probe after republish: %v", err)
	}
	if got := stamped.Load(); got != 2 {
		t.Errorf("stamped fetches after a republish = %d, want 2 (a new publication must announce again)", got)
	}
}

// TestPresenceHelloRejectCounterCountsOnlyFailures pins what the field log means.
// The counter exists to disambiguate "hellos arrive and are thrown out" from
// "no hello ever arrives", so a valid hello must NOT move it and an anonymous
// fetch must not either — otherwise a healthy device logs rejects and the signal
// is worthless.
func TestPresenceHelloRejectCounterCountsOnlyFailures(t *testing.T) {
	s, id := mailboxTestServer(t, "127.0.0.1:1")
	alice, _ := identity.New()
	mallory, _ := identity.New()

	s.sessMu.Lock()
	s.contacts[alice.AccountNumber()] = chatstore.Contact{
		Account: alice.AccountNumber(), Status: chatstore.StatusAccepted,
	}
	s.sessMu.Unlock()

	now := time.Now().Unix()

	before := s.helloRejects.Load()
	profileGet(s, helloQuery(alice, id.AccountNumber(), now))
	if got := s.helloRejects.Load(); got != before {
		t.Errorf("a valid hello moved the reject counter: %d -> %d", before, got)
	}

	// Mallory signs her own stamp but claims to be alice.
	forged := url.Values{}
	forged.Set("from", alice.AccountNumber())
	forged.Set("ts", strconv.FormatInt(now, 10))
	forged.Set("sig", base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(mallory.Keys.Signing.Private, protocol.HelloSigningBlob(now, id.AccountNumber()))))

	// Every failure shape the handler can see, including the two that never reach
	// ServeProfileHello because the query itself does not parse. A clock skewed
	// past the window lands in the first case, which is the field fault this
	// counter is here to make visible.
	cases := map[string]string{
		"stale":           helloQuery(alice, id.AccountNumber(), now-int64((10*time.Minute)/time.Second)),
		"future":          helloQuery(alice, id.AccountNumber(), now+int64((10*time.Minute)/time.Second)),
		"forged":          "?" + forged.Encode(),
		"unparseable-ts":  "?from=" + alice.AccountNumber() + "&ts=not-a-number&sig=AAAA",
		"unparseable-sig": "?from=" + alice.AccountNumber() + "&ts=" + strconv.FormatInt(now, 10) + "&sig=!!!",
	}
	for name, q := range cases {
		n := s.helloRejects.Load()
		profileGet(s, q)
		if got := s.helloRejects.Load(); got != n+1 {
			t.Errorf("%s hello: reject counter %d -> %d, want +1", name, n, got)
		}
	}

	// An anonymous fetch carries no hello at all — the normal add-contact lookup
	// path — and must not count as a reject.
	n := s.helloRejects.Load()
	profileGet(s, "")
	if got := s.helloRejects.Load(); got != n {
		t.Errorf("an anonymous fetch moved the reject counter: %d -> %d", n, got)
	}
}

// A failed outbound probe must NOT demote a contact whose hello just arrived.
// Observed on device before this: the hello promoted the dot and the next sweep
// put it straight back to offline, three times in 75s, because while their
// descriptor is still publishing they can reach us and we cannot reach them.
func TestRecentHelloSurvivesAFailedProbe(t *testing.T) {
	bob, _ := identity.New()
	// Nothing listens here, so every probe fails: this is the asymmetric window.
	onion := &readyOnion{target: func() string { return "127.0.0.1:1" }}
	onion.ready.Store(true) // published, so the probe is not also stamping
	s := newServerOnOnion(t, onion)
	tok := unlockOn(t, s)
	id, ok := s.vault.get(tok)
	if !ok {
		t.Fatal("session did not validate")
	}

	acct := bob.AccountNumber()
	s.sessMu.Lock()
	s.contacts[acct] = chatstore.Contact{Account: acct, Status: chatstore.StatusAccepted}
	s.presence = map[string]string{acct: presenceOnline}
	s.helloAt = map[string]time.Time{acct: time.Now()}
	s.sessMu.Unlock()

	s.probeContact(context.Background(), id, acct)
	if got := presenceOf(s, acct); got != presenceOnline {
		t.Errorf("presence after a failed probe with a fresh hello = %q, want %q", got, presenceOnline)
	}
}

// ...but the hold is a window, not a latch: once hellos stop arriving the dot
// must fall. Otherwise a contact who genuinely went away reads online forever.
func TestStaleHelloDoesNotHoldContactOnline(t *testing.T) {
	bob, _ := identity.New()
	onion := &readyOnion{target: func() string { return "127.0.0.1:1" }}
	onion.ready.Store(true)
	s := newServerOnOnion(t, onion)
	tok := unlockOn(t, s)
	id, _ := s.vault.get(tok)

	acct := bob.AccountNumber()
	s.sessMu.Lock()
	s.contacts[acct] = chatstore.Contact{Account: acct, Status: chatstore.StatusAccepted}
	s.presence = map[string]string{acct: presenceOnline}
	s.helloAt = map[string]time.Time{acct: time.Now().Add(-helloStickiness - time.Second)}
	s.sessMu.Unlock()

	s.probeContact(context.Background(), id, acct)
	if got := presenceOf(s, acct); got != presenceOffline {
		t.Errorf("presence after a failed probe with a stale hello = %q, want %q", got, presenceOffline)
	}
}

// The hold must not invent reachability for a contact who never announced: with
// no hello at all the probe's own verdict stands, which is the pre-change path.
func TestNoHelloLeavesTheProbeVerdictAlone(t *testing.T) {
	bob, _ := identity.New()
	onion := &readyOnion{target: func() string { return "127.0.0.1:1" }}
	onion.ready.Store(true)
	s := newServerOnOnion(t, onion)
	tok := unlockOn(t, s)
	id, _ := s.vault.get(tok)

	acct := bob.AccountNumber()
	s.sessMu.Lock()
	s.contacts[acct] = chatstore.Contact{Account: acct, Status: chatstore.StatusAccepted}
	s.presence = map[string]string{acct: presenceOnline}
	s.helloAt = nil
	s.sessMu.Unlock()

	s.probeContact(context.Background(), id, acct)
	if got := presenceOf(s, acct); got != presenceOffline {
		t.Errorf("presence after a failed probe with no hello = %q, want %q", got, presenceOffline)
	}
}

// An accepted hello refreshes the window even when the dot is already online —
// that is what keeps a long unpublished peer from flickering between hellos.
func TestAcceptedHelloRefreshesTheStickinessWindow(t *testing.T) {
	s, id := mailboxTestServer(t, "127.0.0.1:1")
	alice, _ := identity.New()
	acct := alice.AccountNumber()

	s.sessMu.Lock()
	s.contacts[acct] = chatstore.Contact{Account: acct, Status: chatstore.StatusAccepted}
	s.presence = map[string]string{acct: presenceOnline}
	stale := time.Now().Add(-helloStickiness - time.Second)
	s.helloAt = map[string]time.Time{acct: stale}
	s.sessMu.Unlock()

	profileGet(s, helloQuery(alice, id.AccountNumber(), time.Now().Unix()))

	s.sessMu.Lock()
	got := s.helloAt[acct]
	s.sessMu.Unlock()
	if !got.After(stale) {
		t.Errorf("helloAt not refreshed by an accepted hello (still %v)", got)
	}
}
