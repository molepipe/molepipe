package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/crypto"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// rotateBToAlias0 gives sB a current alias (index 0) as its advertised account,
// optionally caching the alias signing key. It mutates rotation state directly
// (not performRotationLocked) so the test never touches the onion host.
func rotateBToAlias0(t *testing.T, sB *Server, cacheKey bool) string {
	t.Helper()
	idnB := sB.currentIdentity()
	aliasAcct, err := idnB.AliasAccount(0)
	if err != nil {
		t.Fatal(err)
	}
	sB.sessMu.Lock()
	defer sB.sessMu.Unlock()
	sB.rotation = &chatstore.RotationState{CurrentIndex: 0, CurrentAccount: aliasAcct}
	if sB.aliasSigningKeys == nil {
		sB.aliasSigningKeys = map[string]crypto.SigningKeyPair{}
	}
	if cacheKey {
		if err := sB.cacheAliasSigningKeyLocked(idnB, 0, aliasAcct); err != nil {
			t.Fatal(err)
		}
	}
	sB.setLiveAliasAccountsLocked([]string{aliasAcct}) // also pushes to the peer's recipient candidates
	return aliasAcct
}

// gatedPrekeyRequest builds a prekey-bundle request that passes sB's gate: a fresh
// challenge nonce from sB, signed as accepted contact sA over the dialed account.
func gatedPrekeyRequest(t *testing.T, sA, sB *Server, from, dialed string) *http.Request {
	t.Helper()
	ch := sB.currentPeer().Challenge() // registers the nonce in sB's jar
	sig := ed25519.Sign(sA.currentIdentity().Keys.Signing.Private,
		protocol.PrekeyBundleSigningBlob(ch.Nonce, dialed))
	body, err := json.Marshal(protocol.PrekeyBundleRequest{From: from, Nonce: ch.Nonce, Sig: sig})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", protocol.PrekeyBundlePath, bytes.NewReader(body))
	r.Host = dialed + ".onion" // the account the client dialed
	return r
}

// After sB rotates, an accepted contact who dials sB's alias must receive a prekey
// bundle that verifies under the ALIAS account (which is what the client checks it
// against) and NOT under the primary — the served signed prekey is re-signed with
// the alias key so a post-rotation new-friend bootstrap succeeds without exposing
// the primary identity.
func TestPrekeyBundleServedAsAliasVerifiesUnderAlias(t *testing.T) {
	sA, sB, accA, accB, tokA, tokB, bOnion := newPair(t)
	bOnion.up.Store(true) // both directions reachable so the accept handshake completes
	befriend(t, sA, sB, accA, accB, tokA, tokB)

	alias := rotateBToAlias0(t, sB, true)
	aliasEd, err := identity.AccountNumberFromString(alias)
	if err != nil {
		t.Fatal(err)
	}
	primaryEd, err := identity.AccountNumberFromString(accB)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	sB.handleP2PPrekeyBundle(rec, gatedPrekeyRequest(t, sA, sB, accA, alias))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var bundle crypto.PrekeyBundle
	if err := json.Unmarshal(rec.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	if err := crypto.VerifyBundle(bundle, aliasEd); err != nil {
		t.Fatalf("served bundle must verify under the dialed alias: %v", err)
	}
	if err := crypto.VerifyBundle(bundle, primaryEd); err == nil {
		t.Fatal("served bundle must NOT verify under the primary account")
	}
	if !bytes.Equal(bundle.IdentityPub, aliasEd) {
		t.Fatal("served bundle must present the alias identity, not the primary")
	}
}

// A request dialed at a live alias whose signing key is not resident must be
// rejected BEFORE the build hook consumes a one-time prekey: the responder is
// resolved first, so an unresolvable alias burns no OTP (and never falls back to
// serving — and leaking — the primary). The request is otherwise fully valid
// (fresh nonce, accepted-contact signature), so the missing key is the sole cause.
func TestPrekeyBundleAliasKeyMissingConsumesNoOTP(t *testing.T) {
	sA, sB, accA, accB, tokA, tokB, bOnion := newPair(t)
	bOnion.up.Store(true) // both directions reachable so the accept handshake completes
	befriend(t, sA, sB, accA, accB, tokA, tokB)

	alias := rotateBToAlias0(t, sB, false) // alias live, but its key NOT resident

	before := consumedOTPs(sB)
	rec := httptest.NewRecorder()
	sB.handleP2PPrekeyBundle(rec, gatedPrekeyRequest(t, sA, sB, accA, alias))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	if after := consumedOTPs(sB); after != before {
		t.Fatalf("rejected request consumed %d one-time prekeys (before=%d); must consume none", after-before, before)
	}
}
