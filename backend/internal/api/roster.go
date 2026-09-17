package api

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

const (
	maxGroupMembers        = 256     // bound a peer-supplied roster before we store it
	maxGroupNameRunes      = 64      // attacker-controlled; cap group and member names
	groupRosterMaxBodyByte = 1 << 18 // 256 KiB: a full roster (256 members) + overhead
)

// clampGroupName bounds a name at creation so OUR OWN rosters always validate.
// It is applied to inputs BEFORE signing, never to a received roster — clamping
// a signed field after the fact would invalidate the signature, so peer rosters
// are rejected by validateRoster instead of trimmed.
func clampGroupName(s string) string {
	r := []rune(s)
	if len(r) > maxGroupNameRunes {
		r = r[:maxGroupNameRunes]
	}
	return string(r)
}

// validateRoster bounds and sanity-checks a peer-supplied roster before it is
// trusted or stored. It does NOT alter anything (that would break the signature);
// an out-of-bounds roster is simply refused.
func validateRoster(r protocol.SignedRoster) bool {
	if len([]rune(r.Name)) > maxGroupNameRunes || len(r.Members) > maxGroupMembers {
		return false
	}
	if r.Policy != chatstore.InvitePolicyAdmins && r.Policy != chatstore.InvitePolicyEveryone {
		return false
	}
	if _, err := identity.AccountNumberFromString(r.Signer); err != nil {
		return false
	}
	seen := make(map[string]bool, len(r.Members))
	for _, m := range r.Members {
		if _, err := identity.AccountNumberFromString(m.Account); err != nil {
			return false
		}
		if seen[m.Account] {
			return false // a duplicate account would make membership ambiguous
		}
		seen[m.Account] = true
		if len(m.DHPub) != 32 {
			return false // every member needs a real X25519 key to receive
		}
		if m.Role != chatstore.GroupRoleAdmin && m.Role != chatstore.GroupRoleMember {
			return false
		}
		if len([]rune(m.Name)) > maxGroupNameRunes {
			return false
		}
	}
	return true
}

// rosterToGroup converts a verified, validated wire roster into the stored form,
// carrying the committer signature so it can be re-served later. No field is
// altered — the stored bytes must reproduce the signature.
func rosterToGroup(r protocol.SignedRoster) chatstore.Group {
	members := make([]chatstore.GroupMember, 0, len(r.Members))
	for _, m := range r.Members {
		members = append(members, chatstore.GroupMember{
			Account:   m.Account,
			DHPub:     append([]byte(nil), m.DHPub...),
			Role:      m.Role,
			CanInvite: m.CanInvite,
			Name:      m.Name,
		})
	}
	return chatstore.Group{
		ID: r.GroupID, Name: r.Name, Epoch: r.Epoch, Policy: r.Policy,
		Members: members, Signer: r.Signer, Sig: r.Sig,
	}
}

// groupToRoster re-emits a stored roster onto the wire with its original
// committer signature, so a member can forward the roster it holds unchanged.
func groupToRoster(g chatstore.Group) protocol.SignedRoster {
	members := make([]protocol.RosterMember, 0, len(g.Members))
	for _, m := range g.Members {
		members = append(members, protocol.RosterMember{
			Account: m.Account, DHPub: m.DHPub, Role: m.Role, CanInvite: m.CanInvite, Name: m.Name,
		})
	}
	return protocol.SignedRoster{
		GroupID: g.ID, Name: g.Name, Epoch: g.Epoch, Policy: g.Policy,
		Members: members, Signer: g.Signer, Sig: g.Sig,
	}
}

// --- authority model ---

// rosterHasAdmin reports whether acct is an ADMIN on the roster.
func rosterHasAdmin(g chatstore.Group, acct string) bool {
	for _, m := range g.Members {
		if m.Account == acct && m.Role == chatstore.GroupRoleAdmin {
			return true
		}
	}
	return false
}

// canInvite reports whether acct may add new members: admins always may, and a
// non-admin may if the policy is "everyone" or they hold a delegated CanInvite.
func canInvite(g chatstore.Group, acct string) bool {
	for _, m := range g.Members {
		if m.Account != acct {
			continue
		}
		if m.Role == chatstore.GroupRoleAdmin {
			return true
		}
		return g.Policy == chatstore.InvitePolicyEveryone || m.CanInvite
	}
	return false
}

func adminCount(g chatstore.Group) int {
	n := 0
	for _, m := range g.Members {
		if m.Role == chatstore.GroupRoleAdmin {
			n++
		}
	}
	return n
}

func indexMembers(g chatstore.Group) map[string]chatstore.GroupMember {
	m := make(map[string]chatstore.GroupMember, len(g.Members))
	for _, gm := range g.Members {
		m[gm.Account] = gm
	}
	return m
}

// sameMember reports byte-for-byte equality of every field. The additive check
// relies on this: comparing account SETS alone would let a delegated inviter
// keep the set identical while swapping another member's DHPub to a key they
// control, redirecting that member's group traffic to themselves.
func sameMember(a, b chatstore.GroupMember) bool {
	return a.Account == b.Account && bytes.Equal(a.DHPub, b.DHPub) &&
		a.Role == b.Role && a.CanInvite == b.CanInvite && a.Name == b.Name
}

// nonAdminDeltaAllowed decides whether a NON-admin signer was entitled to move
// the roster from old to ng. Only two shapes are allowed, and each existing
// member must be untouched:
//   - Additive: the signer has invite rights, no existing member is changed or
//     removed, and every newly added member is a plain member with no CanInvite
//     (so a delegated inviter can neither mint an admin nor delegate onward, which
//     would let them escalate to full authority on the next epoch).
//   - Self-removal: the delta removes exactly the signer and nothing else (leave).
//
// Name and policy are admin-only, so a non-admin may not change them.
func nonAdminDeltaAllowed(old, ng chatstore.Group, signer string) bool {
	if ng.Name != old.Name || ng.Policy != old.Policy {
		return false
	}
	oldM := indexMembers(old)
	newM := indexMembers(ng)

	if _, inNew := newM[signer]; !inNew {
		// Self-removal: everyone except the signer must survive byte-identical.
		if len(ng.Members) != len(old.Members)-1 {
			return false
		}
		for acct, om := range oldM {
			if acct == signer {
				continue
			}
			nm, ok := newM[acct]
			if !ok || !sameMember(om, nm) {
				return false
			}
		}
		return true
	}

	// Additive.
	if !canInvite(old, signer) {
		return false
	}
	for acct, om := range oldM {
		nm, ok := newM[acct]
		if !ok || !sameMember(om, nm) {
			return false // an existing member was removed or mutated
		}
	}
	for acct, nm := range newM {
		if _, existed := oldM[acct]; existed {
			continue
		}
		if nm.Role != chatstore.GroupRoleMember || nm.CanInvite {
			return false // no fresh admins, no delegated invite rights
		}
	}
	return true
}

// rosterChangeAuthorized decides whether signer was entitled to advance the
// roster from old to ng: an admin (on the roster we already hold) may make any
// change; a non-admin member may make only a constrained additive or
// self-removal change.
func rosterChangeAuthorized(old, ng chatstore.Group, signer string) bool {
	if rosterHasAdmin(old, signer) {
		return true
	}
	if groupHasMember(old, signer) {
		return nonAdminDeltaAllowed(old, ng, signer)
	}
	return false
}

// bootstrapConsentLocked decides whether we may accept a FIRST roster for a
// group we don't hold yet. Consent is the ONLY thing that can gate this: every
// other property of a genesis roster is chosen by whoever signed it, so an
// admin check is worthless — an attacker simply lists themselves as admin and
// us as a member, adding us to a group we never joined. We accept a genesis
// only if we created it, or we hold an ACCEPTED invite for this group naming the
// signer as the inviter — and it actually lists us. That is the same trust
// boundary as accepting the invite in the first place (TOFU on that inviter);
// it does not let the inviter forge anything they couldn't already. Caller holds
// sessMu.
func (s *Server) bootstrapConsentLocked(ng chatstore.Group, signer string) bool {
	if !groupHasMember(ng, s.myAccount) {
		return false
	}
	if signer == s.myAccount {
		return true // our own create
	}
	inv, ok := s.groupInvites[ng.ID]
	return ok && inv.Accepted && inv.Inviter == signer
}

// clearGroupInviteLocked drops any received-invite record for a group (on join
// or decline). Caller holds sessMu.
func (s *Server) clearGroupInviteLocked(groupID string) {
	delete(s.groupInvites, groupID)
}

// acceptRosterLocked is the SINGLE trust gate for every inbound roster — the
// push endpoint, the roster carried in a sync response, and (later) an invite.
// It verifies the signature, bounds the roster, then applies the acceptance
// rule; returns true iff the stored roster changed. Caller holds sessMu.
//
//   - No roster held yet (invite / a group we don't know): trust on first use,
//     accepting only a roster a claimed admin signed.
//   - A newer/better roster (RosterBeats): accept iff the signer was authorized
//     relative to the roster we currently hold.
//   - Otherwise: ignored.
func (s *Server) acceptRosterLocked(r protocol.SignedRoster) bool {
	if r.GroupID == "" || !r.Verify() || !validateRoster(r) {
		return false
	}
	ng := rosterToGroup(r)
	old, held := s.groups[r.GroupID]
	if !held {
		if !s.bootstrapConsentLocked(ng, r.Signer) {
			return false
		}
		s.groups[ng.ID] = ng
		s.clearGroupInviteLocked(ng.ID) // we're in now; the anchor has done its job
		s.persistLocked()
		return true
	}
	if !chatstore.RosterBeats(ng, old) {
		return false
	}
	if !rosterChangeAuthorized(old, ng, r.Signer) {
		return false
	}
	s.groups[ng.ID] = ng
	s.persistLocked()
	return true
}

// handleP2PGroupRoster receives a pushed roster from any member. It always
// answers 200: whether we adopt the roster is our private decision (older,
// unauthorized, or forged rosters are dropped silently), and the pusher only
// needs to know the push was received, not whether it "won".
func (s *Server) handleP2PGroupRoster(w http.ResponseWriter, r *http.Request) {
	if s.currentPeer() == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Roster protocol.SignedRoster `json:"roster"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, groupRosterMaxBodyByte)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.sessMu.Lock()
	s.acceptRosterLocked(req.Roster)
	s.sessMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// pushRosterToMembers best-effort delivers a roster to every other member, so a
// membership change lands promptly rather than waiting for the next gossip
// sweep. Unreachable members reconcile it via group-sync when they return.
func (s *Server) pushRosterToMembers(g chatstore.Group) {
	if s.onion == nil {
		return
	}
	// Snapshot our account under the lock: this runs in a detached goroutine that
	// can outlive the request, racing clearSession's reset of myAccount.
	s.sessMu.Lock()
	self := s.myAccount
	s.sessMu.Unlock()
	r := groupToRoster(g)
	for _, m := range g.Members {
		if m.Account == self {
			continue
		}
		ctx, cancel := deliveryContext(groupOpTimeout)
		err := protocol.SendRoster(ctx, s.onion.Dialer(), r, m.Account)
		cancel()
		if err != nil {
			log.Printf("roster push to a member failed (will reconcile via gossip): %v", err)
		}
	}
}
