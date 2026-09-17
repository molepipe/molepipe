package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// commitAdminRosterLocked signs and stores an admin-authored roster edit
// (epoch+1) over the given members/name/policy. It requires that WE are an admin
// of the group — the authority gate for remove/promote/rename/policy/can-invite.
// Returns the updated group. Caller holds sessMu.
func (s *Server) commitAdminRosterLocked(id *identity.Identity, groupID, name, policy string, members []protocol.RosterMember) (chatstore.Group, bool) {
	g, ok := s.groups[groupID]
	if !ok || !rosterHasAdmin(g, s.myAccount) || id == nil {
		return chatstore.Group{}, false
	}
	roster := protocol.NewSignedRoster(id, groupID, name, policy, g.Epoch+1, members)
	if !s.acceptRosterLocked(roster) {
		return chatstore.Group{}, false
	}
	return s.groups[groupID], true
}

// rosterWithout returns the wire member list minus one account.
func rosterWithout(members []chatstore.GroupMember, account string) []protocol.RosterMember {
	out := make([]protocol.RosterMember, 0, len(members))
	for _, m := range members {
		if m.Account == account {
			continue
		}
		out = append(out, protocol.RosterMember{
			Account: m.Account, DHPub: m.DHPub, Role: m.Role, CanInvite: m.CanInvite, Name: m.Name,
		})
	}
	return out
}

// rosterMutating returns the wire member list with one member's fields changed by
// f. Members not matching account are copied unchanged.
func rosterMutating(members []chatstore.GroupMember, account string, f func(*protocol.RosterMember)) []protocol.RosterMember {
	out := make([]protocol.RosterMember, 0, len(members))
	for _, m := range members {
		rm := protocol.RosterMember{Account: m.Account, DHPub: m.DHPub, Role: m.Role, CanInvite: m.CanInvite, Name: m.Name}
		if m.Account == account {
			f(&rm)
		}
		out = append(out, rm)
	}
	return out
}

// decodeGroupAccount reads {group, account}, validating the account. Returns
// ("","") after writing an error.
func decodeGroupAccount(w http.ResponseWriter, r *http.Request) (group, account string) {
	var req struct {
		Group   string `json:"group"`
		Account string `json:"account"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return "", ""
	}
	if _, err := identity.AccountNumberFromString(req.Account); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid account number"})
		return "", ""
	}
	return req.Group, req.Account
}

// handleRemoveFromGroup removes a member (admin-only). The new roster is pushed
// to the remaining members AND to the removed account, so their client adopts it
// (signer is an admin they still recognise) and corrects its own view — otherwise
// they'd keep listing the group and composing into it while every send is refused.
func (s *Server) handleRemoveFromGroup(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	group, account := decodeGroupAccount(w, r)
	if group == "" {
		return
	}
	s.sessMu.Lock()
	g, ok := s.groups[group]
	if !ok || !groupHasMember(g, s.myAccount) {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no such group"})
		return
	}
	if !rosterHasAdmin(g, s.myAccount) {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "only an admin can remove members"})
		return
	}
	if account == s.myAccount {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "use leave to remove yourself"})
		return
	}
	if !groupHasMember(g, account) {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "not a member"})
		return
	}
	updated, ok := s.commitAdminRosterLocked(id, group, g.Name, g.Policy, rosterWithout(g.Members, account))
	if !ok {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not remove member"})
		return
	}
	removalRoster := groupToRoster(updated)
	s.sessMu.Unlock()

	go s.pushRosterToMembers(updated)
	go s.pushRosterTo(removalRoster, account) // notify the removed member
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// handlePromoteInGroup promotes a member to admin (admin-only).
func (s *Server) handlePromoteInGroup(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	group, account := decodeGroupAccount(w, r)
	if group == "" {
		return
	}
	updated, ok := s.editMemberRole(id, group, account, func(m *protocol.RosterMember) {
		m.Role = chatstore.GroupRoleAdmin
		m.CanInvite = false // redundant on an admin; keep the record canonical
	}, w)
	if !ok {
		return
	}
	go s.pushRosterToMembers(updated)
	writeJSON(w, http.StatusOK, map[string]string{"status": "promoted"})
}

// handleSetCanInvite grants or revokes a non-admin member's delegated invite
// right (admin-only).
func (s *Server) handleSetCanInvite(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		Group   string `json:"group"`
		Account string `json:"account"`
		Allow   bool   `json:"allow"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if _, err := identity.AccountNumberFromString(req.Account); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid account number"})
		return
	}
	s.sessMu.Lock()
	if g, ok := s.groups[req.Group]; ok && rosterHasAdmin(g, req.Account) {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "admins can already invite"})
		return
	}
	s.sessMu.Unlock()
	updated, ok := s.editMemberRole(id, req.Group, req.Account, func(m *protocol.RosterMember) {
		m.CanInvite = req.Allow
	}, w)
	if !ok {
		return
	}
	go s.pushRosterToMembers(updated)
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// editMemberRole is the shared admin-only path for promote / can-invite: it
// verifies the group, our admin authority and the target's membership, applies f
// to the target's roster entry, and commits. Writes the error and returns
// ok=false on any failure. Caller must NOT hold sessMu.
func (s *Server) editMemberRole(id *identity.Identity, group, account string, f func(*protocol.RosterMember), w http.ResponseWriter) (chatstore.Group, bool) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	g, ok := s.groups[group]
	if !ok || !groupHasMember(g, s.myAccount) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no such group"})
		return chatstore.Group{}, false
	}
	if !rosterHasAdmin(g, s.myAccount) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "only an admin can do that"})
		return chatstore.Group{}, false
	}
	if !groupHasMember(g, account) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "not a member"})
		return chatstore.Group{}, false
	}
	updated, ok := s.commitAdminRosterLocked(id, group, g.Name, g.Policy, rosterMutating(g.Members, account, f))
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update member"})
		return chatstore.Group{}, false
	}
	return updated, true
}

// handleRenameGroup renames a group (admin-only).
func (s *Server) handleRenameGroup(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		Group string `json:"group"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	name := clampGroupName(req.Name)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "group name required"})
		return
	}
	s.sessMu.Lock()
	g, ok := s.groups[req.Group]
	if !ok || !groupHasMember(g, s.myAccount) {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no such group"})
		return
	}
	if !rosterHasAdmin(g, s.myAccount) {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "only an admin can rename the group"})
		return
	}
	updated, ok := s.commitAdminRosterLocked(id, req.Group, name, g.Policy, groupMembersToRoster(g.Members))
	s.sessMu.Unlock()
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not rename group"})
		return
	}
	go s.pushRosterToMembers(updated)
	writeJSON(w, http.StatusOK, map[string]string{"status": "renamed", "name": name})
}

// handleSetGroupPolicy switches the invite policy between admins-only and
// everyone (admin-only).
func (s *Server) handleSetGroupPolicy(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		Group  string `json:"group"`
		Policy string `json:"policy"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Policy != chatstore.InvitePolicyAdmins && req.Policy != chatstore.InvitePolicyEveryone {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "policy must be 'admins' or 'everyone'"})
		return
	}
	s.sessMu.Lock()
	g, ok := s.groups[req.Group]
	if !ok || !groupHasMember(g, s.myAccount) {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no such group"})
		return
	}
	if !rosterHasAdmin(g, s.myAccount) {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "only an admin can change the policy"})
		return
	}
	updated, ok := s.commitAdminRosterLocked(id, req.Group, g.Name, req.Policy, groupMembersToRoster(g.Members))
	s.sessMu.Unlock()
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not change policy"})
		return
	}
	go s.pushRosterToMembers(updated)
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated", "policy": req.Policy})
}

// pushRosterTo best-effort delivers a roster to one account (e.g. a removed
// member, who is no longer in pushRosterToMembers' loop).
func (s *Server) pushRosterTo(r protocol.SignedRoster, account string) {
	if s.onion == nil {
		return
	}
	ctx, cancel := deliveryContext(groupOpTimeout)
	defer cancel()
	if err := protocol.SendRoster(ctx, s.onion.Dialer(), r, account); err != nil {
		log.Printf("roster push to a removed member failed (they'll reconcile on next contact): %v", err)
	}
}
