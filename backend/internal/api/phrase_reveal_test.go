package api

import (
	"net/http"
	"strings"
	"testing"
)

// The onboarding wizard promises the recovery phrase can always be viewed again,
// so phrase-reveal must return the real 24-word phrase — but only to the full
// password, never to a session token alone.
func TestPhraseRevealReturnsThePhrase(t *testing.T) {
	s, pw := newTestServer(t)
	tok := unlockWithPassword(t, s, pw)
	hdr := map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + tok}

	r := s.do(t, "POST", "/api/security", `{"action":"phrase-reveal","password":"`+pw+`"}`, hdr)
	if r.Code != http.StatusOK {
		t.Fatalf("reveal: got %d, want 200 (%s)", r.Code, r.Body)
	}
	phrase, _ := decode(t, r.Body)["recovery_phrase"].(string)
	if n := len(strings.Fields(phrase)); n != 24 {
		t.Fatalf("expected a 24-word phrase, got %d words: %q", n, phrase)
	}
}

// A wrong password is a plain 401 with no phrase — the guard against an
// unattended unlocked screen surrendering the account. It must not consult the
// duress code or advance any erase counter (mirrors wipe-set / duress-set).
func TestPhraseRevealRefusesWrongPassword(t *testing.T) {
	s, pw := newTestServer(t)
	tok := unlockWithPassword(t, s, pw)
	hdr := map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + tok}

	r := s.do(t, "POST", "/api/security", `{"action":"phrase-reveal","password":"not-the-password"}`, hdr)
	if r.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: got %d, want 401 (%s)", r.Code, r.Body)
	}
	if p, _ := decode(t, r.Body)["recovery_phrase"].(string); p != "" {
		t.Fatalf("a failed reveal still leaked a phrase: %q", p)
	}
}

// The reveal prompt is deliberately duress-inert: the duress code fires only at
// the unlock prompt, never at a settings re-auth (same as wipe-set / duress-set,
// which also go straight to store.Load). Typing the duress code here must be a
// plain 401 that leaks no phrase AND does not wipe — the real store stays intact,
// so the real password still reveals the real phrase afterwards.
func TestPhraseRevealIgnoresTheDuressCode(t *testing.T) {
	s, pw := newTestServer(t)
	tok := unlockWithPassword(t, s, pw)
	hdr := map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + tok}
	armDuress(t, s, tok, pw, testDuressCode)

	r := s.do(t, "POST", "/api/security", `{"action":"phrase-reveal","password":"`+testDuressCode+`"}`, hdr)
	if r.Code != http.StatusUnauthorized {
		t.Fatalf("duress code at reveal: got %d, want 401 — it must not fire here (%s)", r.Code, r.Body)
	}
	if p, _ := decode(t, r.Body)["recovery_phrase"].(string); p != "" {
		t.Fatalf("the duress code leaked a phrase: %q", p)
	}

	// The real store must survive: the real password still reveals the real phrase.
	real := s.do(t, "POST", "/api/security", `{"action":"phrase-reveal","password":"`+pw+`"}`, hdr)
	if real.Code != http.StatusOK {
		t.Fatalf("after a duress-code attempt the real reveal got %d, want 200 — the store was disturbed (%s)", real.Code, real.Body)
	}
	if n := len(strings.Fields(decode(t, real.Body)["recovery_phrase"].(string))); n != 24 {
		t.Fatalf("real phrase after duress attempt: got %d words, want 24", n)
	}
}

// Like every mutating route: a token but no Origin is refused.
func TestPhraseRevealKeepsTheGuards(t *testing.T) {
	s, pw := newTestServer(t)
	tok := unlockWithPassword(t, s, pw)

	if r := s.do(t, "POST", "/api/security", `{"action":"phrase-reveal","password":"`+pw+`"}`, map[string]string{
		"Authorization": "Bearer " + tok, // no Origin
	}); r.Code != http.StatusForbidden {
		t.Fatalf("reveal without an Origin should be 403, got %d", r.Code)
	}
}
