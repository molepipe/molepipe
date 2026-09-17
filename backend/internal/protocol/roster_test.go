package protocol

import (
	"testing"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

func rosterMember(id *identity.Identity, role string) RosterMember {
	dh := id.Keys.DH.Public
	return RosterMember{Account: id.AccountNumber(), DHPub: dh[:], Role: role}
}

// TestSignedRosterRoundTrip: a signed roster verifies, and its signature is
// order-independent (members reversed still verify — the blob is sorted).
func TestSignedRosterRoundTrip(t *testing.T) {
	admin, _ := identity.New()
	member, _ := identity.New()
	members := []RosterMember{rosterMember(admin, "admin"), rosterMember(member, "member")}
	r := NewSignedRoster(admin, "grp-1", "Test", "admins", 3, members)
	if !r.Verify() {
		t.Fatal("freshly signed roster failed to verify")
	}
	// Reorder members: the canonical blob sorts by account, so the stored order
	// must not matter (this is what lets Merge/gossip reorder without breaking it).
	r.Members = []RosterMember{r.Members[1], r.Members[0]}
	if !r.Verify() {
		t.Fatal("roster failed to verify after member reorder")
	}
}

// TestSignedRosterTamper: mutating any covered field breaks the signature.
func TestSignedRosterTamper(t *testing.T) {
	admin, _ := identity.New()
	member, _ := identity.New()
	base := NewSignedRoster(admin, "grp-1", "Test", "admins", 1,
		[]RosterMember{rosterMember(admin, "admin"), rosterMember(member, "member")})

	cases := map[string]func(r *SignedRoster){
		"name":        func(r *SignedRoster) { r.Name = "Evil" },
		"epoch":       func(r *SignedRoster) { r.Epoch = 99 },
		"policy":      func(r *SignedRoster) { r.Policy = "everyone" },
		"member-role": func(r *SignedRoster) { r.Members[1].Role = "admin" },
		"member-dh":   func(r *SignedRoster) { r.Members[1].DHPub = make([]byte, 32) },
		"add-member":  func(r *SignedRoster) { r.Members = append(r.Members, rosterMember(admin, "member")) },
		"group-id":    func(r *SignedRoster) { r.GroupID = "grp-2" },
	}
	for name, mutate := range cases {
		r := base
		r.Members = append([]RosterMember(nil), base.Members...)
		mutate(&r)
		if r.Verify() {
			t.Fatalf("tampering with %s still verified", name)
		}
	}
}

// TestSignedRosterWrongSigner: a valid signature under one key does not verify
// if Signer names a different account.
func TestSignedRosterWrongSigner(t *testing.T) {
	admin, _ := identity.New()
	other, _ := identity.New()
	r := NewSignedRoster(admin, "grp-1", "Test", "admins", 1, []RosterMember{rosterMember(admin, "admin")})
	r.Signer = other.AccountNumber()
	if r.Verify() {
		t.Fatal("roster verified under a mismatched signer")
	}
}
