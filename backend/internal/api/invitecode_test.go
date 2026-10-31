package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

func inviteTestServer() *Server {
	id, err := identity.New()
	if err != nil {
		panic(err)
	}
	return &Server{contacts: map[string]chatstore.Contact{}, sessID: id}
}

// Strict: the account is not addable without a current code. A tokenless (bare
// account) request is refused whether or not auto-refresh is on.
func TestInviteTokenlessRejected(t *testing.T) {
	for _, auto := range []bool{false, true} {
		s := inviteTestServer()
		s.autoRefresh = auto
		s.inviteToken = "LIVE"
		if err := s.hookOnFriendRequest("alice", "Alice", "r1", "", s.sessID.AccountNumber()); err == nil {
			t.Fatalf("tokenless add must be rejected (autoRefresh=%v)", auto)
		}
		if _, ok := s.contacts["alice"]; ok {
			t.Fatal("a rejected tokenless request must not create a pending_in")
		}
	}
}

// The degenerate empty==empty case: an un-minted device (empty stored token) must
// still reject a tokenless request rather than admit it. Guards the ordering of
// admitInviteTokenLocked (the s.inviteToken=="" clause must come first).
func TestInviteEmptyStoredTokenRejectsEmptyIncoming(t *testing.T) {
	s := inviteTestServer()
	s.inviteToken = "" // never minted
	if err := s.hookOnFriendRequest("alice", "Alice", "r1", "", s.sessID.AccountNumber()); err == nil {
		t.Fatal("empty stored token must reject an empty incoming token, not admit it")
	}
}

// A request bearing the current token is admitted and lands as pending_in.
func TestInviteValidTokenAdmitted(t *testing.T) {
	s := inviteTestServer()
	s.inviteToken = "LIVE"
	if err := s.hookOnFriendRequest("alice", "Alice", "r1", "LIVE", s.sessID.AccountNumber()); err != nil {
		t.Fatalf("valid-token add rejected: %v", err)
	}
	if s.contacts["alice"].Status != chatstore.StatusPendingIn {
		t.Fatal("alice should be pending_in after presenting the current code")
	}
}

// A forged/garbage token (never the live one) is refused.
func TestInviteForgedTokenRejected(t *testing.T) {
	s := inviteTestServer()
	s.inviteToken = "LIVE"
	if err := s.hookOnFriendRequest("mallory", "Mallory", "r1", "GARBAGE", s.sessID.AccountNumber()); err == nil {
		t.Fatal("forged token must be rejected")
	}
}

// Auto-refresh ON: a redemption rotates the token, so the code works exactly once
// — a second, different requester presenting the same (now rotated-away) code is
// turned away.
func TestInviteAutoRefreshRotatesToken(t *testing.T) {
	s := inviteTestServer()
	s.autoRefresh = true
	s.inviteToken = "LIVE"

	if err := s.hookOnFriendRequest("alice", "Alice", "r1", "LIVE", s.sessID.AccountNumber()); err != nil {
		t.Fatalf("valid-token add rejected: %v", err)
	}
	if s.inviteToken == "LIVE" || s.inviteToken == "" {
		t.Fatalf("auto-refresh must rotate to a fresh non-empty token, got %q", s.inviteToken)
	}
	if err := s.hookOnFriendRequest("mallory", "Mallory", "r2", "LIVE", s.sessID.AccountNumber()); err == nil {
		t.Fatal("the used code must not work for a second person under auto-refresh")
	}
	if _, ok := s.contacts["mallory"]; ok {
		t.Fatal("rejected reuse must not create a pending_in")
	}
}

// Auto-refresh OFF: the current code stays valid and reusable across adds by
// different people until the user manually refreshes it.
func TestInviteNoAutoRefreshReusable(t *testing.T) {
	s := inviteTestServer()
	s.autoRefresh = false
	s.inviteToken = "LIVE"

	if err := s.hookOnFriendRequest("alice", "Alice", "r1", "LIVE", s.sessID.AccountNumber()); err != nil {
		t.Fatalf("first add rejected: %v", err)
	}
	if s.inviteToken != "LIVE" {
		t.Fatalf("without auto-refresh the token must not rotate, got %q", s.inviteToken)
	}
	if err := s.hookOnFriendRequest("bob", "Bob", "r2", "LIVE", s.sessID.AccountNumber()); err != nil {
		t.Fatalf("reusable code rejected for a second person: %v", err)
	}
	if s.contacts["alice"].Status != chatstore.StatusPendingIn || s.contacts["bob"].Status != chatstore.StatusPendingIn {
		t.Fatal("both should be pending_in with a reusable code")
	}
}

// The retry hazard under auto-refresh: attempt 1 lands and rotates the token, its
// response is lost, and attempt 2 re-sends the same (now stale) token. Because the
// sender is already pending_in, the retry hits the refresh/dedupe path with no
// token re-check, so it is NOT rejected — the sender doesn't see a failure for a
// request that in fact landed.
func TestInviteRetryWithStaleTokenExempted(t *testing.T) {
	s := inviteTestServer()
	s.autoRefresh = true
	s.inviteToken = "LIVE"

	if err := s.hookOnFriendRequest("alice", "Alice", "r1", "LIVE", s.sessID.AccountNumber()); err != nil {
		t.Fatalf("first attempt rejected: %v", err)
	}
	if err := s.hookOnFriendRequest("alice", "Alice", "r1", "LIVE", s.sessID.AccountNumber()); err != nil {
		t.Fatalf("retry from an already-pending sender must be exempt, got: %v", err)
	}
}

// shareCodeLocked always returns the versioned code carrying the current token,
// round-trippable back to the same account+token; it falls back to the bare
// account only in the brief pre-mint window (empty token).
func TestShareCodeLocked(t *testing.T) {
	s := inviteTestServer()
	const acct = "aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllllmmmmnnnn"

	if got := s.shareCodeLocked(acct); got != acct {
		t.Fatalf("pre-mint (empty token): share code = %q, want bare account", got)
	}

	s.inviteToken = "TOKEN"
	code := s.shareCodeLocked(acct)
	if code == acct {
		t.Fatal("with a token, the share code should carry it, not be bare")
	}
	gotAcct, gotTok := protocol.ParseInviteCode(code)
	if gotAcct != acct || gotTok != "TOKEN" {
		t.Fatalf("round-trip = (%q,%q), want (%q,TOKEN)", gotAcct, gotTok, acct)
	}
}

// Option-1 seam: once rotation is active the friend code (and its QR) must carry
// the CURRENT ALIAS onion, never the permanent m/0'/0' account. This is the line
// that actually hides the account key — a redeemer parsing the code learns only a
// rotating alias. Before any rotation the code still carries the primary (nothing to
// hide yet); the token is orthogonal to which account the code names.
func TestInviteCodeCarriesAliasAfterRotation(t *testing.T) {
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	alias, err := id.AliasAccount(0)
	if err != nil {
		t.Fatal(err)
	}
	s := inviteTestServer()
	s.inviteToken = "TOK"

	// Pre-rotation: advertised == primary, code carries the primary.
	if got := s.advertisedAccountLocked(id); got != id.AccountNumber() {
		t.Fatalf("pre-rotation advertised = %q, want primary", got)
	}
	if acct, _ := protocol.ParseInviteCode(s.inviteCodeResponseLocked(id).Code); acct != id.AccountNumber() {
		t.Fatalf("pre-rotation code account = %q, want primary", acct)
	}

	// After a rotation to alias 0: advertised == alias; code carries the alias and
	// never the permanent onion.
	s.rotation = &chatstore.RotationState{CurrentIndex: 0, CurrentAccount: alias}
	if got := s.advertisedAccountLocked(id); got != alias {
		t.Fatalf("post-rotation advertised = %q, want alias %q", got, alias)
	}
	acct, tok := protocol.ParseInviteCode(s.inviteCodeResponseLocked(id).Code)
	if acct != alias {
		t.Fatalf("post-rotation code account = %q, want alias %q", acct, alias)
	}
	if acct == id.AccountNumber() {
		t.Fatal("friend code leaked the permanent account after rotation")
	}
	if tok != "TOK" {
		t.Fatalf("code token = %q, want TOK (rotation must not disturb the token)", tok)
	}
}

// ensureInviteTokenLocked mints a token when none exists (migration/first unlock)
// and leaves an existing one untouched.
func TestEnsureInviteTokenLocked(t *testing.T) {
	s := inviteTestServer()
	s.ensureInviteTokenLocked()
	if s.inviteToken == "" {
		t.Fatal("ensureInviteTokenLocked must mint a token when none exists")
	}
	first := s.inviteToken
	s.ensureInviteTokenLocked()
	if s.inviteToken != first {
		t.Fatal("ensureInviteTokenLocked must not replace an existing token")
	}
}

func TestNewInviteTokenUniqueAndSafe(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, err := newInviteToken()
		if err != nil {
			t.Fatal(err)
		}
		if tok == "" || strings.Contains(tok, ":") {
			t.Fatalf("token %q must be non-empty and contain no ':' delimiter", tok)
		}
		if seen[tok] {
			t.Fatalf("duplicate token minted: %q", tok)
		}
		seen[tok] = true
	}
}

// handleInviteCode drives enable → refresh → disable and returns a code that
// reflects each transition. The code always carries a token (always-on).
func TestHandleInviteCodeLifecycle(t *testing.T) {
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	s := inviteTestServer()
	s.inviteToken = "SEED" // as if minted on unlock

	post := func(action string) inviteCodeResponse {
		t.Helper()
		r := httptest.NewRequest("POST", "/api/invite-code", strings.NewReader(`{"action":"`+action+`"}`))
		w := httptest.NewRecorder()
		s.handleInviteCode(w, r, id)
		if w.Code != 200 {
			t.Fatalf("action %q: status %d, body %s", action, w.Code, w.Body.String())
		}
		var resp inviteCodeResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}

	on := post("enable")
	if !on.AutoRefresh {
		t.Fatalf("enable: %+v, want auto_refresh on", on)
	}
	acct, tok := protocol.ParseInviteCode(on.Code)
	if acct != id.AccountNumber() || tok == "" {
		t.Fatalf("code = %q, want current account + token", on.Code)
	}
	if on.QR == "" {
		t.Fatal("response should always carry a QR of the code")
	}

	refreshed := post("refresh")
	if refreshed.Code == on.Code {
		t.Fatal("refresh must mint a new code")
	}
	if !refreshed.AutoRefresh {
		t.Fatal("refresh must not change the auto-refresh toggle")
	}

	off := post("disable")
	if off.AutoRefresh {
		t.Fatalf("disable: %+v, want auto_refresh off", off)
	}
	if _, tok := protocol.ParseInviteCode(off.Code); tok == "" {
		t.Fatal("code must still carry a token when auto-refresh is off (reusable code)")
	}
}
