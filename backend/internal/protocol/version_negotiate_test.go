package protocol

import (
	"testing"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

// TestNegotiate exercises the version-overlap logic with SYNTHETIC bounds. While
// the real window is protoVerMin == protoVerCurrent == 1, no genuine
// advertisement can drive negotiate below the floor, so the reject path would be
// untestable if it only ever saw the package consts. Passing bounds explicitly
// lets us prove the clamp and the reject now, before a real v2 exists.
func TestNegotiate(t *testing.T) {
	cases := []struct {
		name                     string
		theirMax, ourMin, ourMax uint16
		want                     uint16
		wantErr                  bool
	}{
		{"absent-is-v1-at-v1-floor", 0, 1, 1, 1, false},
		{"exact-match-v1", 1, 1, 1, 1, false},
		{"newer-peer-clamped-down", 2, 1, 1, 1, false},
		// Absent Ver means literal v1, NOT "our floor": once the floor rises above
		// 1, a Ver-less (v1) peer no longer overlaps and must be rejected.
		{"absent-is-v1-not-floor", 0, 2, 3, 0, true},
		{"pick-shared-max", 3, 2, 3, 3, false},
		{"pick-lower-shared", 2, 2, 3, 2, false},
		{"clamp-to-our-max", 5, 2, 3, 3, false},
		{"peer-below-our-floor", 1, 2, 3, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := negotiate(c.theirMax, c.ourMin, c.ourMax)
			if c.wantErr {
				if err == nil {
					t.Fatalf("negotiate(%d,%d,%d) = %d, want error", c.theirMax, c.ourMin, c.ourMax, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("negotiate(%d,%d,%d) unexpected error: %v", c.theirMax, c.ourMin, c.ourMax, err)
			}
			if got != c.want {
				t.Fatalf("negotiate(%d,%d,%d) = %d, want %d", c.theirMax, c.ourMin, c.ourMax, got, c.want)
			}
		})
	}
}

// TestNegotiateVersionAtV1 pins the live behaviour: with the sole version being
// 1, every advertisement resolves to 1 and nothing is ever rejected — the seam
// is behaviour-neutral today.
func TestNegotiateVersionAtV1(t *testing.T) {
	for _, theirMax := range []uint16{0, 1, 2, 65535} {
		v, err := negotiateVersion(theirMax)
		if err != nil {
			t.Fatalf("negotiateVersion(%d) unexpected error: %v", theirMax, err)
		}
		if v != 1 {
			t.Fatalf("negotiateVersion(%d) = %d, want 1", theirMax, v)
		}
	}
}

func TestVersionSupported(t *testing.T) {
	if !versionSupported(1) {
		t.Fatal("versionSupported(1) = false, want true")
	}
	if versionSupported(0) {
		t.Fatal("versionSupported(0) = true, want false")
	}
	if versionSupported(2) {
		t.Fatal("versionSupported(2) = true, want false")
	}
}

// TestCandidateVersions checks the hint-first fallback ordering. At v1 the list
// is always exactly [1], whether the hint is present, absent, or bogus — so an
// unsupported hint can never leave the verifier with nothing to try.
func TestCandidateVersions(t *testing.T) {
	for _, hint := range []uint16{0, 1, 2, 99} {
		got := candidateVersions(hint)
		if len(got) != 1 || got[0] != 1 {
			t.Fatalf("candidateVersions(%d) = %v, want [1]", hint, got)
		}
	}
}

// TestVerifyProfileSigHintTolerant is the property that makes the dry-run target
// (the self-signed card) version-tolerant: a correct signature verifies, a wrong
// or absent Ver HINT still verifies by fallback, and tampering still fails.
func TestVerifyProfileSigHintTolerant(t *testing.T) {
	id, err := identity.New()
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	peer := NewPeer(id, Hooks{
		DisplayName: func() string { return "Alice" },
		AvatarHash:  func() string { return "" },
	})
	card := peer.ProfileCard()
	ed, err := identity.AccountNumberFromString(card.Account)
	if err != nil {
		t.Fatalf("AccountNumberFromString: %v", err)
	}

	if card.Ver != protoVerCurrent {
		t.Fatalf("card.Ver = %d, want %d (ProfileCard must advertise current)", card.Ver, protoVerCurrent)
	}
	if !verifyProfileSig(ed, card.Account, card) {
		t.Fatal("verifyProfileSig rejected a freshly signed card")
	}

	// A flipped/bogus Ver hint must NOT cause a spurious reject — the verifier
	// falls back across supported versions rather than trusting the hint.
	bogus := card
	bogus.Ver = 99
	if !verifyProfileSig(ed, bogus.Account, bogus) {
		t.Fatal("verifyProfileSig rejected a valid card carrying a bogus Ver hint")
	}
	absent := card
	absent.Ver = 0
	if !verifyProfileSig(ed, absent.Account, absent) {
		t.Fatal("verifyProfileSig rejected a valid card with Ver absent (older-peer case)")
	}

	// Tampering with a signed field must still fail.
	tampered := card
	tampered.DisplayName = "Mallory"
	if verifyProfileSig(ed, tampered.Account, tampered) {
		t.Fatal("verifyProfileSig accepted a card with a tampered display name")
	}

	// A different identity's key must not verify this card.
	other, _ := identity.New()
	otherEd, _ := identity.AccountNumberFromString(other.AccountNumber())
	if verifyProfileSig(otherEd, card.Account, card) {
		t.Fatal("verifyProfileSig accepted a card under the wrong verifying key")
	}
}
