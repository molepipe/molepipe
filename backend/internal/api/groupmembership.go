package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// dhPublic returns a copy of the identity's X25519 public key as a slice, for
// putting into a roster member entry.
func dhPublic(id *identity.Identity) []byte {
	p := id.Keys.DH.Public
	return append([]byte(nil), p[:]...)
}

// groupMembersToRoster converts stored members to the wire form.
func groupMembersToRoster(members []chatstore.GroupMember) []protocol.RosterMember {
	out := make([]protocol.RosterMember, 0, len(members))
	for _, m := range members {
		out = append(out, protocol.RosterMember{
			Account: m.Account, DHPub: m.DHPub, Role: m.Role, CanInvite: m.CanInvite, Name: m.Name,
		})
	}
	return out
}

// handleCreateGroup creates a new group with the caller as its sole admin. The
// genesis roster (epoch 1) is self-signed and stored via the same acceptance
// gate every other roster goes through; there is nobody else to distribute it to
// yet — that happens as members are invited.
func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	name := clampGroupName(strings.TrimSpace(req.Name))
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "group name required"})
		return
	}
	gid := randomID()
	me := protocol.RosterMember{Account: id.AccountNumber(), DHPub: dhPublic(id), Role: chatstore.GroupRoleAdmin}
	roster := protocol.NewSignedRoster(id, gid, name, chatstore.InvitePolicyAdmins, 1, []protocol.RosterMember{me})

	s.sessMu.Lock()
	ok := s.acceptRosterLocked(roster)
	s.sessMu.Unlock()
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create group"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": gid, "name": name})
}

// handleLeaveGroup removes the caller from a group they belong to. Leaving is a
// self-removal: the caller signs a new roster (epoch+1) without themselves and
// pushes it, so the rest of the group stops sealing traffic to them. A member
// may always remove themselves; the receive path accepts that even for the last
// admin (a validly-signed self-removal must not diverge across peers), but we
// refuse it LOCALLY here so the user is nudged to promote a successor first.
func (s *Server) handleLeaveGroup(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		Group string `json:"group"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.sessMu.Lock()
	g, ok := s.groups[req.Group]
	if !ok {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no such group"})
		return
	}
	if !groupHasMember(g, s.myAccount) {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{"status": "left"}) // already not a member
		return
	}
	// Solo group: nobody to tell, so just drop it locally rather than storing a
	// zero-member roster.
	if len(g.Members) == 1 {
		delete(s.groups, req.Group)
		s.persistLocked()
		s.sessMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{"status": "left"})
		return
	}
	if rosterHasAdmin(g, s.myAccount) && adminCount(g) == 1 {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "promote another admin before leaving — you are the only one"})
		return
	}

	remaining := make([]protocol.RosterMember, 0, len(g.Members)-1)
	for _, m := range g.Members {
		if m.Account == s.myAccount {
			continue
		}
		remaining = append(remaining, protocol.RosterMember{
			Account: m.Account, DHPub: m.DHPub, Role: m.Role, CanInvite: m.CanInvite, Name: m.Name,
		})
	}
	roster := protocol.NewSignedRoster(id, g.ID, g.Name, g.Policy, g.Epoch+1, remaining)
	s.acceptRosterLocked(roster)
	updated := s.groups[req.Group]
	s.sessMu.Unlock()

	go s.pushRosterToMembers(updated)
	writeJSON(w, http.StatusOK, map[string]string{"status": "left"})
}

// friendStatusLocked maps a co-member's account to our 1:1 trust relationship
// with them, for the group member list. This is DELIBERATELY separate from group
// membership: sharing a group grants no 1:1 rights, so the UI shows an "add
// friend" affordance for a co-member we haven't friended. Caller holds sessMu.
func (s *Server) friendStatusLocked(account string) string {
	if account == s.myAccount {
		return "self"
	}
	c, ok := s.contacts[account]
	if !ok {
		return "none"
	}
	switch c.Status {
	case chatstore.StatusAccepted:
		return "accepted"
	case chatstore.StatusPendingOut:
		return "pending_out"
	case chatstore.StatusPendingIn:
		return "pending_in"
	case chatstore.StatusBlocked:
		return "blocked"
	}
	return "none"
}

// handleListGroupMembers returns the roster of a group the caller belongs to,
// each entry annotated with our 1:1 friend status and whether we may DM them
// (only accepted contacts — never merely co-members). Restricted to members, so
// the membership of a group is not exposed to outsiders.
func (s *Server) handleListGroupMembers(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	gid := r.URL.Query().Get("group")
	s.sessMu.Lock()
	g, ok := s.groups[gid]
	if !ok || !groupHasMember(g, s.myAccount) {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such group"})
		return
	}
	out := make([]map[string]any, 0, len(g.Members))
	for _, m := range g.Members {
		friend := s.friendStatusLocked(m.Account)
		name := m.Name
		if c, ok := s.contacts[m.Account]; ok && c.Name != "" {
			name = c.Name // prefer the name we've saved for them
		}
		out = append(out, map[string]any{
			"account": m.Account, "name": name, "role": m.Role, "can_invite": m.CanInvite,
			"is_self": m.Account == s.myAccount, "friend_status": friend,
			// You can DM a co-member only if you've actually friended them; being in
			// the same group is not enough.
			"can_message": friend == "accepted",
		})
	}
	myRole := chatstore.GroupRoleMember
	if rosterHasAdmin(g, s.myAccount) {
		myRole = chatstore.GroupRoleAdmin
	}
	iCanInvite := canInvite(g, s.myAccount)
	s.sessMu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i]["account"].(string) < out[j]["account"].(string) })
	// Caller context alongside the roster, so a member-list screen with an invite
	// button needs only this one endpoint.
	writeJSON(w, http.StatusOK, map[string]any{
		"members": out, "my_role": myRole, "i_can_invite": iCanInvite, "policy": g.Policy, "name": g.Name,
	})
}

// handleMarkGroupRead marks a group conversation read up to now. Reuses the
// reads map keyed by the group id (see handleListGroups), so it needs no new
// storage and syncs across devices by the same MAX-merge as 1:1 reads.
func (s *Server) handleMarkGroupRead(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	var req struct {
		Group string `json:"group"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.sessMu.Lock()
	g, ok := s.groups[req.Group]
	if !ok || !groupHasMember(g, s.myAccount) {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no such group"})
		return
	}
	if s.reads == nil {
		s.reads = map[string]time.Time{}
	}
	s.reads[req.Group] = time.Now()
	s.persistLocked()
	s.sessMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "read"})
}

// handleListGroups returns the groups the caller currently belongs to. Groups we
// have left or been removed from are hidden (we may still hold the roster so a
// stale lower-epoch push can't re-add us, but they are not conversations).
func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	s.sessMu.Lock()
	out := []map[string]any{}
	for _, g := range s.groups {
		if !groupHasMember(g, s.myAccount) {
			continue
		}
		role := chatstore.GroupRoleMember
		if rosterHasAdmin(g, s.myAccount) {
			role = chatstore.GroupRoleAdmin
		}
		// Unread: inbound group messages newer than our last read of this group.
		// Group reads reuse the reads map keyed by GroupID (account ids and group
		// ids never collide — different charset/length), so multi-device sync's
		// MAX-merge covers them with no new field.
		last := s.reads[g.ID]
		unread := 0
		for _, m := range s.messages {
			if m.GroupID == g.ID && m.Direction == "in" && m.At.After(last) {
				unread++
			}
		}
		out = append(out, map[string]any{
			"id": g.ID, "name": g.Name, "policy": g.Policy, "epoch": g.Epoch,
			"member_count": len(g.Members), "role": role, "can_invite": canInvite(g, s.myAccount),
			"unread": unread,
		})
	}
	s.sessMu.Unlock()
	// Stable order so the list doesn't reshuffle between polls (map iteration is
	// randomised); the UI re-sorts for display.
	sort.Slice(out, func(i, j int) bool { return out[i]["id"].(string) < out[j]["id"].(string) })
	writeJSON(w, http.StatusOK, map[string]any{"groups": out})
}
