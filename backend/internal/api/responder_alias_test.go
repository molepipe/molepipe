package api

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/crypto"
	"github.com/molepipe/molepipe/backend/internal/identity"
)

// responderTestServer builds a server that has rotated once (current = alias 0)
// with one in-grace history alias (alias 1), both with their real signing keys
// resident — the shape responderForRequest resolves against.
func responderTestServer(t *testing.T, idn *identity.Identity) (*Server, string, string) {
	t.Helper()
	s := rotationTestServer(&fakeExtraHost{})
	s.sessID = idn
	s.aliasSigningKeys = map[string]crypto.SigningKeyPair{}

	cur, err := idn.AliasAccount(0)
	if err != nil {
		t.Fatal(err)
	}
	hist, err := idn.AliasAccount(1)
	if err != nil {
		t.Fatal(err)
	}
	s.rotation = &chatstore.RotationState{
		CurrentIndex:   0,
		CurrentAccount: cur,
		History:        []chatstore.AliasRecord{{Index: 1, Account: hist, RetireAt: time.Now().Add(3 * 24 * time.Hour)}},
	}
	s.sessMu.Lock()
	if err := s.cacheAliasSigningKeyLocked(idn, 0, cur); err != nil {
		t.Fatal(err)
	}
	if err := s.cacheAliasSigningKeyLocked(idn, 1, hist); err != nil {
		t.Fatal(err)
	}
	s.localAliasAccounts = []string{cur, hist}
	s.sessMu.Unlock()
	return s, cur, hist
}

func aliasPriv(t *testing.T, idn *identity.Identity, index uint32) []byte {
	t.Helper()
	kp, err := idn.AliasSigningKey(index)
	if err != nil {
		t.Fatal(err)
	}
	return kp.Private
}

// responderForRequest resolves the account (and its signing key) a request must be
// answered AS from the dialed Host, constrained to the live set: current alias,
// in-grace alias, and — post-rotation, still — the primary onion. Anything outside
// the set (garbage/empty Host) falls back to the advertised alias, never the
// primary, so a malformed Host cannot coax the permanent address back out.
func TestResponderForRequestResolvesDialedAlias(t *testing.T) {
	idn, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	s, cur, hist := responderTestServer(t, idn)
	primary := idn.AccountNumber()

	cases := []struct {
		name     string
		host     string
		wantAcct string
		wantKey  []byte
	}{
		{"current-alias", cur + ".onion:80", cur, aliasPriv(t, idn, 0)},
		{"in-grace-alias", hist + ".onion", hist, aliasPriv(t, idn, 1)},
		{"primary-still-live", primary + ".onion:80", primary, idn.Keys.Signing.Private},
		{"garbage-host-falls-back-to-advertised", "deadbeef.onion", cur, aliasPriv(t, idn, 0)},
		{"empty-host-falls-back-to-advertised", "", cur, aliasPriv(t, idn, 0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			acct, priv, err := s.responderForRequest(idn, &http.Request{Host: tc.host})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if acct != tc.wantAcct {
				t.Fatalf("account = %s, want %s", acct, tc.wantAcct)
			}
			if !bytes.Equal(priv, tc.wantKey) {
				t.Fatalf("signing key does not match the expected account's key")
			}
		})
	}
}

// A request dialed at a live alias whose signing key is NOT resident (e.g. republish
// succeeded but the key was evicted) must fail loud, so the handler emits its generic
// reject rather than silently answering — and leaking — the primary account.
func TestResponderForRequestFailsLoudOnMissingAliasKey(t *testing.T) {
	idn, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	s, _, hist := responderTestServer(t, idn)

	s.sessMu.Lock()
	delete(s.aliasSigningKeys, hist) // key gone, but alias still in the live set
	s.sessMu.Unlock()

	if _, _, err := s.responderForRequest(idn, &http.Request{Host: hist + ".onion"}); err == nil {
		t.Fatal("a live alias with no resident signing key must fail loud, not fall back to primary")
	}
}

// Before any rotation (nil rotation state, no aliases), a garbage Host resolves to
// the primary account with the primary key — the advertised account IS the primary,
// so a never-rotated node answers exactly as it always did.
func TestResponderForRequestPreRotationIsPrimary(t *testing.T) {
	idn, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	s := rotationTestServer(&fakeExtraHost{})
	s.sessID = idn

	acct, priv, err := s.responderForRequest(idn, &http.Request{Host: "whatever.onion"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if acct != idn.AccountNumber() {
		t.Fatalf("account = %s, want primary %s", acct, idn.AccountNumber())
	}
	if !bytes.Equal(priv, idn.Keys.Signing.Private) {
		t.Fatal("pre-rotation must sign with the primary key")
	}
}
