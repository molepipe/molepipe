package protocol

import (
	"crypto/ed25519"
	"encoding/binary"
	"sort"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

// groupRosterContext is the signing label for a group roster, distinct from the
// message ("group-message") and sync ("group-sync") labels so signed bytes can
// never be replayed across group paths.
const groupRosterContext = "group-roster"

// RosterMember is one member as carried in a signed roster on the wire. It is
// the protocol-level twin of chatstore.GroupMember; the api layer converts
// between them, exactly as it does for group messages, so protocol stays
// self-contained (no chatstore import) and the signed bytes are canonical.
type RosterMember struct {
	Account   string `json:"account"`
	DHPub     []byte `json:"dh_pub,omitempty"` // X25519 key to seal group messages to them
	Role      string `json:"role"`             // "admin" | "member"
	CanInvite bool   `json:"can_invite,omitempty"`
	Name      string `json:"name,omitempty"`
}

// SignedRoster is a group's membership state, authored and signed by a COMMITTER
// — an admin (full authority) or a member making a constrained change (adding a
// member, or removing themselves). Epoch increases on every change and the
// highest epoch wins on reconcile. The signature covers the CANONICAL
// serialization (sorted members, length-prefixed) rather than any JSON wrapper,
// so a stored roster survives disk round-trips through chatstore and gossip
// forwarding without invalidating — the same property that lets any member
// re-serve a roster it holds. Signer is bound implicitly: the signature verifies
// only under its key.
type SignedRoster struct {
	GroupID string         `json:"group_id"`
	Name    string         `json:"name"`
	Epoch   uint64         `json:"epoch"`
	Policy  string         `json:"policy"`
	Members []RosterMember `json:"members"`
	Signer  string         `json:"signer"` // committer account whose key signs Sig
	Sig     []byte         `json:"sig"`
}

// rosterSignBlob builds the canonical signed bytes: fixed header fields, then
// members SORTED by account, each field length-prefixed via signBlob. Sorting
// here (and in Verify, which recomputes from the parsed struct) means member
// order on the wire or on disk can never change the signature.
func rosterSignBlob(groupID, name string, epoch uint64, policy string, members []RosterMember) []byte {
	sorted := append([]RosterMember(nil), members...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Account < sorted[j].Account })
	var ep [8]byte
	binary.BigEndian.PutUint64(ep[:], epoch)
	parts := [][]byte{
		sigContextFor(protoVerCurrent), []byte(groupRosterContext),
		[]byte(groupID), []byte(name), ep[:], []byte(policy),
	}
	for _, m := range sorted {
		var ci byte
		if m.CanInvite {
			ci = 1
		}
		parts = append(parts, []byte(m.Account), m.DHPub, []byte(m.Role), []byte{ci}, []byte(m.Name))
	}
	return signBlob(parts...)
}

// NewSignedRoster builds and signs a roster as id (the committer). Callers are
// responsible for the authority rules (only an admin may remove/promote/rename;
// a member may only add or self-remove); this just produces a valid signature.
func NewSignedRoster(id *identity.Identity, groupID, name, policy string, epoch uint64, members []RosterMember) SignedRoster {
	sig := ed25519.Sign(id.Keys.Signing.Private, rosterSignBlob(groupID, name, epoch, policy, members))
	return SignedRoster{
		GroupID: groupID, Name: name, Epoch: epoch, Policy: policy,
		Members: members, Signer: id.AccountNumber(), Sig: sig,
	}
}

// Verify reports whether the committer's signature is valid over the canonical
// roster. It does NOT decide authority — the caller checks whether Signer was
// entitled to make this change relative to the roster it already holds.
func (r SignedRoster) Verify() bool {
	signerEd, err := identity.AccountNumberFromString(r.Signer)
	if err != nil {
		return false
	}
	return ed25519.Verify(signerEd, rosterSignBlob(r.GroupID, r.Name, r.Epoch, r.Policy, r.Members), r.Sig)
}
