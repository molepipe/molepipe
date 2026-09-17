package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sort"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

const (
	maxGroupInvites = 200 // cap pending received invites (anti-spam)

	groupInviteRetryStart    = 30 * time.Second
	groupInviteRetryInterval = 60 * time.Second
	// groupInviteMaxRefusals bounds retries against a peer that keeps answering
	// "no matching invite" (the group was abandoned before we joined). A transport
	// error — the inviter merely offline — is NOT a refusal and never counts, so a
	// slow join keeps trying.
	groupInviteMaxRefusals = 10
)

func sentInviteKey(groupID, account string) string { return groupID + "|" + account }

// --- hooks (called by Peer after signature verification) ---

// hookOnGroupInvite records an inbound invitation for the user to act on. It is
// ignored if we're already a member, deduped per group, and capped.
func (s *Server) hookOnGroupInvite(groupID, groupName, inviter, inviterName, reqID string) error {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if g, ok := s.groups[groupID]; ok && groupHasMember(g, s.myAccount) {
		return nil // already in
	}
	if ex, ok := s.groupInvites[groupID]; ok && ex.Accepted {
		return nil // mid-join; keep the accepted record and its consent anchor
	}
	if _, ok := s.groupInvites[groupID]; !ok && len(s.groupInvites) >= maxGroupInvites {
		return errors.New("too many pending invites")
	}
	s.groupInvites[groupID] = chatstore.GroupInvite{
		GroupID: groupID, Name: groupName, Inviter: inviter, ReqID: reqID, At: time.Now(),
	}
	s.persistLocked()
	// Notify the Android shell so it can post a system notification.
	if fn := s.onGroupInvite; fn != nil {
		go fn(inviterName, groupName)
	}
	return nil
}

// hookOnGroupInviteAccept applies an invitee's acceptance on the inviter side:
// confirm it answers an invite we actually issued (or that they're already a
// member — a retry after we committed but before our roster reached them), add
// them to the roster, and push it. Idempotent: a second accept for an existing
// member just re-pushes, so a dropped roster is repaired without bumping the
// epoch or forking.
func (s *Server) hookOnGroupInviteAccept(groupID, from, fromName string, dhPub []byte, reqID string) error {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	g, ok := s.groups[groupID]
	if !ok || !groupHasMember(g, s.myAccount) {
		return errors.New("unknown group")
	}
	if groupHasMember(g, from) {
		go s.pushRosterToMembers(g) // already added; re-push in case the roster was lost
		return nil
	}
	key := sentInviteKey(groupID, from)
	si, ok := s.sentGroupInvites[key]
	if !ok || si.ReqID != reqID {
		return errors.New("no matching invite")
	}
	ng, ok := s.commitAddMemberLocked(s.sessID, groupID, from, fromName, dhPub)
	if !ok {
		return errors.New("could not add member")
	}
	delete(s.sentGroupInvites, key)
	s.persistLocked()
	go s.pushRosterToMembers(ng)
	return nil
}

// commitAddMemberLocked adds account (with their DHPub) to a group as a plain
// member, signing and storing a new roster. Requires that WE may invite. If the
// account is already a member it returns the current roster unchanged (for a
// re-push) rather than bumping the epoch. Caller holds sessMu.
func (s *Server) commitAddMemberLocked(id *identity.Identity, groupID, account, name string, dhPub []byte) (chatstore.Group, bool) {
	g, ok := s.groups[groupID]
	if !ok || !groupHasMember(g, s.myAccount) || !canInvite(g, s.myAccount) || id == nil {
		return chatstore.Group{}, false
	}
	if groupHasMember(g, account) {
		return g, true
	}
	members := append(groupMembersToRoster(g.Members), protocol.RosterMember{
		Account: account, DHPub: append([]byte(nil), dhPub...),
		Role: chatstore.GroupRoleMember, Name: clampGroupName(name),
	})
	roster := protocol.NewSignedRoster(id, g.ID, g.Name, g.Policy, g.Epoch+1, members)
	if !s.acceptRosterLocked(roster) {
		return chatstore.Group{}, false
	}
	return s.groups[groupID], true
}

// --- P2P handlers (onion listener) ---

func (s *Server) handleP2PGroupInvite(w http.ResponseWriter, r *http.Request) {
	peer := s.currentPeer()
	if peer == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	var gi protocol.GroupInvite
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&gi); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := peer.ReceiveGroupInvite(gi); err != nil {
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleP2PGroupInviteAccept(w http.ResponseWriter, r *http.Request) {
	peer := s.currentPeer()
	if peer == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	var a protocol.GroupInviteAccept
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&a); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := peer.ReceiveGroupInviteAccept(a); err != nil {
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// --- control API ---

// handleInviteToGroup sends a group invite to an account. Requires that the
// caller may invite in this group. The sent-invite record is stored only after
// the invite is delivered, mirroring the friend-request flow, so a failed send
// leaves no stale record for a stray accept to match.
func (s *Server) handleInviteToGroup(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		Group   string `json:"group"`
		Account string `json:"account"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if _, err := identity.AccountNumberFromString(req.Account); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid account number"})
		return
	}
	if req.Account == id.AccountNumber() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "that's your own account"})
		return
	}
	s.sessMu.Lock()
	g, ok := s.groups[req.Group]
	name := s.displayName
	if !ok || !groupHasMember(g, s.myAccount) {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no such group"})
		return
	}
	if !canInvite(g, s.myAccount) {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "you are not allowed to invite to this group"})
		return
	}
	if groupHasMember(g, req.Account) {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "already a member"})
		return
	}
	gname := g.Name
	if s.onion == nil {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Tor is disabled"})
		return
	}
	// Record the sent invite BEFORE the push, and keep it even if the push errors.
	// A "failed" POST can still have DELIVERED — the invitee may have received the
	// invite and only the 200 was lost. If we stored only on success (as an earlier
	// draft did), their accept would find no matching invite, their retries would
	// be refused, and they'd strand permanently. Same ordering lesson as
	// handleAcceptRequest.
	reqID := randomID()
	s.sentGroupInvites[sentInviteKey(req.Group, req.Account)] = chatstore.SentGroupInvite{
		GroupID: req.Group, Account: req.Account, ReqID: reqID, At: time.Now(),
	}
	s.persistLocked()
	s.sessMu.Unlock()

	ctx, cancel := deliveryContext(2 * time.Minute)
	defer cancel()
	if err := protocol.SendGroupInvite(ctx, s.onion.Dialer(), id, name, req.Group, gname, reqID, req.Account); err != nil {
		// Report the failure but leave the record: the accept-retry path can still
		// complete the join if the invite in fact landed.
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "could not confirm invite delivery: " + err.Error(), "queued": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "invited"})
}

// handleAcceptGroupInvite accepts a received invite: it arms the bootstrap
// consent anchor and pushes an acceptance carrying our DHPub to the inviter, who
// then adds us and distributes the roster. The retry loop re-sends the accept
// until we actually hold a roster listing us, so a dropped accept or a
// briefly-offline inviter doesn't strand the join.
func (s *Server) handleAcceptGroupInvite(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		Group string `json:"group"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.sessMu.Lock()
	inv, ok := s.groupInvites[req.Group]
	name := s.displayName
	if !ok {
		s.sessMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no such invite"})
		return
	}
	inv.Accepted = true
	s.groupInvites[req.Group] = inv
	s.persistLocked()
	s.sessMu.Unlock()

	notified := false
	if s.onion != nil {
		// Deliver the accept in the background so the UI returns immediately.
		// The retry loop (handleListGroupInvites) re-sends if this fails.
		go func() {
			ctx, cancel := deliveryContext(2 * time.Minute)
			defer cancel()
			if err := protocol.SendGroupInviteAccept(ctx, s.onion.Dialer(), id, name, inv.GroupID, inv.ReqID, inv.Inviter); err != nil {
				log.Printf("group invite accept to %s failed, queued for retry: %v", inv.Inviter, err)
			}
		}()
		notified = true
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "accepted", "notified": notified})
}

// handleDeclineGroupInvite drops a received invite (and its consent anchor).
func (s *Server) handleDeclineGroupInvite(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	var req struct {
		Group string `json:"group"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.sessMu.Lock()
	if _, ok := s.groupInvites[req.Group]; ok {
		delete(s.groupInvites, req.Group)
		s.persistLocked()
	}
	s.sessMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "declined"})
}

// handleListGroupInvites returns received invites for the user to act on. A
// not-yet-accepted invite is "pending"; an accepted one whose join hasn't
// completed is "joining" — the latter is shown too, so a join that stalls (an
// inviter who never committed, or retries exhausted) is visible and not a silent
// dead end.
func (s *Server) handleListGroupInvites(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	s.sessMu.Lock()
	out := []map[string]any{}
	for _, inv := range s.groupInvites {
		inviterName := inv.Inviter
		if c, ok := s.contacts[inv.Inviter]; ok && c.Name != "" {
			inviterName = c.Name
		}
		status := "pending"
		if inv.Accepted {
			status = "joining"
		}
		out = append(out, map[string]any{
			"group": inv.GroupID, "name": inv.Name, "inviter": inv.Inviter,
			"inviter_name": inviterName, "status": status,
		})
	}
	s.sessMu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i]["group"].(string) < out[j]["group"].(string) })
	writeJSON(w, http.StatusOK, map[string]any{"invites": out})
}

// --- retry loop (invitee side) ---

// groupInviteRetryLoop re-sends accepted-but-unfulfilled invite acceptances. The
// dequeue condition is "we now hold a roster that lists us", NOT "the accept
// POST succeeded" — otherwise an inviter who received the accept but died before
// committing (or whose roster push was lost) would strand us silently.
func (s *Server) groupInviteRetryLoop(ctx context.Context, id *identity.Identity) {
	t := time.NewTimer(groupInviteRetryStart)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.groupInviteRetryTick(ctx, id)
			t.Reset(groupInviteRetryInterval)
		}
	}
}

func (s *Server) groupInviteRetryTick(ctx context.Context, id *identity.Identity) {
	if s.onion == nil {
		return
	}
	type job struct{ groupID, inviter, reqID string }
	var jobs []job
	s.sessMu.Lock()
	name := s.displayName
	for gid, inv := range s.groupInvites {
		if !inv.Accepted {
			continue
		}
		if g, ok := s.groups[gid]; ok && groupHasMember(g, s.myAccount) {
			delete(s.groupInvites, gid) // joined — clean up the stale accepted record
			s.persistLocked()
			continue
		}
		if inv.Refusals >= groupInviteMaxRefusals {
			continue
		}
		jobs = append(jobs, job{gid, inv.Inviter, inv.ReqID})
	}
	s.sessMu.Unlock()

	for _, j := range jobs {
		cctx, cancel := context.WithTimeout(ctx, groupOpTimeout)
		err := protocol.SendGroupInviteAccept(cctx, s.onion.Dialer(), id, name, j.groupID, j.reqID, j.inviter)
		cancel()
		s.sessMu.Lock()
		if inv, ok := s.groupInvites[j.groupID]; ok && inv.Accepted {
			inv.LastTry = time.Now()
			var se *protocol.StatusError
			if errors.As(err, &se) {
				inv.Refusals++ // the inviter answered and refused; a transport error would not
			}
			s.groupInvites[j.groupID] = inv
			s.persistLocked()
		}
		s.sessMu.Unlock()
	}
}
