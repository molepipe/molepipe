package protocol

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

// signCardUnder builds a self-signed Profile card signed under an ARBITRARY wire
// version, mirroring Peer.ProfileCard exactly but choosing the signature domain.
// ProfileCard always signs under protoVerCurrent (1); this lets the test forge a
// genuinely v2-signed card so the cross-version verify path can be exercised
// against a real second version while the production window stays [1,1].
func signCardUnder(t *testing.T, id *identity.Identity, version uint16, name, avatar string) Profile {
	t.Helper()
	acct := id.AccountNumber()
	dh := id.Keys.DH.Public
	sig := ed25519.Sign(id.Keys.Signing.Private,
		signBlob(sigContextFor(version), []byte("profile"), []byte(acct), []byte(name), dh[:], []byte(avatar)))
	return Profile{Account: acct, DisplayName: name, DHPub: dh[:], AvatarHash: avatar, Sig: sig, Ver: version}
}

// TestProfileCrossVersion is the end-to-end proof that the version machinery
// tolerates a real second version — the "v2 dry-run", made durable. It does NOT
// touch the production window (protoVerMin/protoVerCurrent stay 1, so production
// keeps verifying only under [1]); instead it drives the arg-taking core
// verifyProfileSigUnder with explicit candidate lists, exactly as the production
// wrapper would once the window opens. Two v-lists model two builds:
//   - {2,1} = a v2-capable build (tries its own v2 first, falls back to v1)
//   - {1}   = a v1-only build (the peer that predates v2)
func TestProfileCrossVersion(t *testing.T) {
	// Direct distinctness guard. Every "accept" below is only meaningful if the
	// two domains genuinely differ; if sigContextFor(2) returned the v1 bytes the
	// whole test would pass vacuously (the same symmetric-drift blindness the
	// golden vectors exist to catch). Assert it head-on.
	if bytes.Equal(sigContextFor(1), sigContextFor(2)) {
		t.Fatal("sigContextFor(1) == sigContextFor(2): v1/v2 domains not distinct, cross-version proof is vacuous")
	}

	id, err := identity.New()
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	ed, err := identity.AccountNumberFromString(id.AccountNumber())
	if err != nil {
		t.Fatalf("AccountNumberFromString: %v", err)
	}

	v1Card := signCardUnder(t, id, 1, "Alice", "")
	v2Card := signCardUnder(t, id, 2, "Alice", "")

	newBuild := []uint16{2, 1} // v2-capable verifier
	oldBuild := []uint16{1}    // v1-only verifier

	// A v2-capable build verifies an OLDER (v1) peer's card — the whole point of
	// version tolerance: newer verifies older by falling back through candidates.
	if !verifyProfileSigUnder(newBuild, ed, v1Card.Account, v1Card) {
		t.Fatal("v2-capable verifier rejected a v1 card (newer must verify older)")
	}
	// A v2-capable build verifies a v2 card (two new builds interoperate).
	if !verifyProfileSigUnder(newBuild, ed, v2Card.Account, v2Card) {
		t.Fatal("v2-capable verifier rejected a v2 card")
	}
	// A v1-only build verifies a v1 card (the world before v2, unchanged).
	if !verifyProfileSigUnder(oldBuild, ed, v1Card.Account, v1Card) {
		t.Fatal("v1-only verifier rejected a v1 card")
	}

	// CENTERPIECE. A v1-only build must REJECT a v2 card: it has no v2 domain to
	// try, so the signature cannot validate. This is the one assertion that fails
	// if sigContextFor(2) is not genuinely distinct — everything else can pass on
	// a collapsed domain, this cannot. It also documents the real limit: an older
	// build cannot verify a newer peer's card, which is why a v2 build negotiates
	// DOWN to sign under v1 when it detects a v1 peer (see the negotiate ties).
	if verifyProfileSigUnder(oldBuild, ed, v2Card.Account, v2Card) {
		t.Fatal("v1-only verifier ACCEPTED a v2 card — domains collapsed; version separation is broken")
	}

	// The Ver field is a hint, not a selector, across the real fallback: a v2 card
	// carrying a LYING v1 hint still verifies on a v2-capable build, because the
	// verifier tries every candidate rather than trusting the byte.
	lying := v2Card
	lying.Ver = 1
	if !verifyProfileSigUnder(newBuild, ed, lying.Account, lying) {
		t.Fatal("v2-capable verifier trusted a lying Ver hint and rejected a valid v2 card")
	}
	// Symmetrically, a v1 card with an inflated v2 hint still verifies (fallback
	// reaches v1). Bounds the hint's influence to zero in both directions.
	inflated := v1Card
	inflated.Ver = 2
	if !verifyProfileSigUnder(newBuild, ed, inflated.Account, inflated) {
		t.Fatal("v2-capable verifier trusted an inflated Ver hint and rejected a valid v1 card")
	}

	// Tie the signature layer to the negotiation layer: what a build SIGNS under
	// is what negotiate picks. A v2 build meeting a v1-only peer negotiates down
	// to 1 (so it signs the v1 domain the peer can verify); two v2 builds pick 2.
	if v, err := negotiate(1, 1, 2); err != nil || v != 1 {
		t.Fatalf("negotiate(v1-peer, v2-build) = %d,%v; want 1,<nil> (v2 build must sign v1 for a v1 peer)", v, err)
	}
	if v, err := negotiate(2, 1, 2); err != nil || v != 2 {
		t.Fatalf("negotiate(v2-peer, v2-build) = %d,%v; want 2,<nil>", v, err)
	}
	// And a v1-only build (max 1) meeting a v2 peer clamps down to 1, never
	// reaching for a v2 domain it cannot produce.
	if v, err := negotiate(2, 1, 1); err != nil || v != 1 {
		t.Fatalf("negotiate(v2-peer, v1-build) = %d,%v; want 1,<nil>", v, err)
	}
}
