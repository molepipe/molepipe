package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

const (
	// groupMaxBodyByte caps an inbound group envelope: a max-length message plus
	// JSON + base64 + directional-crypto overhead, with headroom.
	groupMaxBodyByte = 1 << 17 // 128 KiB
	groupOpTimeout   = 60 * time.Second

	groupSyncStartDelay  = 20 * time.Second // let the onion publish before first pull
	groupSyncInterval    = 45 * time.Second
	groupSyncMaxBodyByte = 1 << 19 // 512 KiB — a have-list of ids
	groupSyncMaxMessages = 100     // per pull; the rest come next round
	// groupSyncMaxReactions bounds the reaction events re-served per pull. They ride
	// the same response as messages (read under a 32 MiB limit), re-sent wholesale
	// each tick and idempotently LWW-applied, so the cap only keeps one response
	// bounded — the rest reconcile next round like messages.
	groupSyncMaxReactions = 300
	groupSyncWorkers      = 4 // concurrent pulls, so one unreachable member can't stall a tick
	// groupSyncWindow bounds gossip to the most-recent messages on BOTH sides, so
	// the have-list can't grow without limit (which would eventually exceed
	// groupSyncMaxBodyByte and silently break sync) and the responder never
	// re-offers ancient history a member already has. Very old gaps heal slowly or
	// not at all; recent traffic — what a returning member actually missed — always
	// reconciles.
	groupSyncWindow = 500
)

// groupHasMember reports whether account is on the group's roster.
func groupHasMember(g chatstore.Group, account string) bool {
	for _, m := range g.Members {
		if m.Account == account {
			return true
		}
	}
	return false
}

// handleP2PGroupMessage receives a sealed group message from the author or from
// any forwarding member, decrypts+verifies it, gates it to the group's roster,
// and files it. Self-authenticating (inner author signature), so unlike a direct
// message there is no live challenge — the same reason any member can relay it.
func (s *Server) handleP2PGroupMessage(w http.ResponseWriter, r *http.Request) {
	peer := s.currentPeer()
	if peer == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable) // locked: retry later
		return
	}
	var req struct {
		Envelope protocol.GroupEnvelope `json:"envelope"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, groupMaxBodyByte)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Decrypt + verify the inner author signature. For a group message the author
	// signature is inside the box, so this necessarily decrypts before gating —
	// but the box only opens if it was sealed for us, and an unknown group or a
	// non-member author is refused below without anything being stored.
	gm, err := peer.OpenGroup(req.Envelope)
	if err != nil {
		groupReject(w)
		return
	}
	s.sessMu.Lock()
	g, ok := s.groups[gm.GroupID]
	// Accept only if WE still belong to the group (so leave/remove actually stops
	// delivery) AND the author is a current member. The author gate here is on
	// CURRENT membership because this is a live NEW message; gossip backfill of an
	// already-authored message deliberately does not (see groupSyncPullFrom).
	accept := ok && groupHasMember(g, s.myAccount) && groupHasMember(g, gm.Author)
	if accept && s.deliverGroupInboundLocked(gm, true) {
		s.persistLocked()
	}
	s.sessMu.Unlock()
	if !accept {
		groupReject(w) // uniform refusal: says nothing about which check failed
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "delivered"})
}

// groupReject is the single response for every group-deliver failure, so the
// endpoint reveals nothing about why (bad signature vs. unknown group vs.
// non-member author).
func groupReject(w http.ResponseWriter) {
	http.Error(w, "not accepted", http.StatusForbidden)
}

// deliverGroupInboundLocked files a group message, de-duped by its deterministic
// group id. Direction is local: "out" if we authored it (a message can return to
// us via gossip), "in" otherwise. Peer is left empty — the invariant for group
// messages. Returns true if newly added. Caller holds sessMu.
//
// notify raises the new-message notification for a freshly received inbound
// message. The live receive path passes true; the phase-3 gossip catch-up will
// pass false, so bringing a returning member up to date doesn't buzz them once
// per missed message.
func (s *Server) deliverGroupInboundLocked(gm protocol.GroupMessage, notify bool) bool {
	if gm.FullID != "" { // image message
		return s.deliverGroupImageInboundLocked(gm, notify)
	}
	id := chatstore.GroupMessageID(gm.GroupID, gm.Author, gm.Text, gm.At)
	for i := range s.messages {
		if s.messages[i].ID == id {
			return false
		}
	}
	for _, d := range s.deleted {
		if d == id {
			return false
		}
	}
	dir := "in"
	if gm.Author == s.myAccount {
		dir = "out"
	}
	s.messages = append(s.messages, chatMessage{
		Direction: dir, GroupID: gm.GroupID, Author: gm.Author, AuthorSig: gm.Sig, Text: gm.Text, At: gm.At, ID: id,
		ReplyID: gm.ReplyID, // quoted preview/author are resolved locally on render
	})
	if notify && dir == "in" && s.onInbound != nil {
		title := s.groups[gm.GroupID].Name
		if title == "" {
			title = "Group"
		}
		preview := s.groupAuthorNameLocked(gm.GroupID, gm.Author) + ": " + gm.Text
		avatarHash := ""
		if c, ok := s.contacts[gm.Author]; ok {
			avatarHash = c.AvatarHash
		}
		go s.onInbound(title, preview, gm.At.UnixMilli(), avatarHash)
	}
	return true
}

// groupAuthorNameLocked resolves a display name for a group message's author: a
// contact name if we have one, else the roster's name for them, else the raw
// account. Caller holds sessMu.
func (s *Server) groupAuthorNameLocked(groupID, author string) string {
	if c, ok := s.contacts[author]; ok && c.Name != "" {
		return c.Name
	}
	if g, ok := s.groups[groupID]; ok {
		for _, m := range g.Members {
			if m.Account == author && m.Name != "" {
				return m.Name
			}
		}
	}
	return author
}

// handleSendGroupMessage authors a group message, stores it locally, and fans it
// out to every other member best-effort. Offline members are caught up later by
// gossip (phase 3), so this deliberately does not use the 1:1 outbox/retry.
func (s *Server) handleSendGroupMessage(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		Group   string        `json:"group"`
		Text    string        `json:"text"`
		ReplyTo *replyToInput `json:"reply_to"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	replyID := req.ReplyTo.toReply().ID
	s.sessMu.Lock()
	g, ok := s.groups[req.Group]
	mine := ok && groupHasMember(g, s.myAccount)
	// Scope the reply target to THIS group. The id is signed and fanned out to every
	// member, so an id naming a 1:1 message or another group's message would relay a
	// quote pulled from an unrelated conversation (recipients resolve the preview
	// locally by id, unscoped). Unless we hold a row for this exact id in this group,
	// drop the reply and send a plain message — friendlier than a 400 and it also
	// absorbs the race where the quoted message was deleted between compose and send.
	if replyID != "" {
		found := false
		for i := range s.messages {
			if s.messages[i].ID == replyID && s.messages[i].GroupID == req.Group {
				found = true
				break
			}
		}
		if !found {
			replyID = ""
		}
	}
	s.sessMu.Unlock()
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no such group"})
		return
	}
	if !mine {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "you are not a member of this group"})
		return
	}
	if s.onion == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Tor is disabled"})
		return
	}
	// Only the reply target id is signed and fanned out (validated above to name a
	// message in THIS group); the quoted preview/author the client sent are a hint,
	// re-derived locally on each recipient (like 1:1).
	gm, err := protocol.NewGroupMessage(id, req.Group, req.Text, time.Now(), replyID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	msgID := chatstore.GroupMessageID(gm.GroupID, gm.Author, gm.Text, gm.At)
	s.sessMu.Lock()
	// Our own message: stored as "out", so notify is moot — pass false.
	if s.deliverGroupInboundLocked(gm, false) {
		s.persistLocked()
	}
	s.sessMu.Unlock()
	go s.groupFanOut(id, g, gm)
	writeJSON(w, http.StatusOK, map[string]any{"status": "queued", "id": msgID})
}

// groupFanOut seals the message for each other member (using their roster key)
// and delivers it best-effort. A member we can't reach is simply skipped; the
// gossip layer reconciles the gap when they return.
func (s *Server) groupFanOut(id *identity.Identity, g chatstore.Group, gm protocol.GroupMessage) {
	if s.onion == nil {
		return
	}
	// Snapshot our account under the lock — this runs detached and can race
	// clearSession's reset of myAccount.
	s.sessMu.Lock()
	self := s.myAccount
	s.sessMu.Unlock()
	for _, m := range g.Members {
		if m.Account == self || len(m.DHPub) != 32 {
			continue
		}
		var dh [32]byte
		copy(dh[:], m.DHPub)
		env, err := protocol.SealGroupMessage(id, gm, m.Account, dh)
		if err != nil {
			continue
		}
		ctx, cancel := deliveryContext(groupOpTimeout)
		err = protocol.SendGroupEnvelope(ctx, s.onion.Dialer(), env, m.Account)
		cancel()
		if err != nil {
			log.Printf("group send to a member failed (will reconcile via gossip): %v", err)
		}
	}
}

// recentGroupMessagesLocked returns up to n most-recent stored messages for a
// group, newest first — the gossip window. Caller holds sessMu.
func (s *Server) recentGroupMessagesLocked(groupID string, n int) []chatMessage {
	var ms []chatMessage
	for _, m := range s.messages {
		if m.GroupID == groupID {
			ms = append(ms, m)
		}
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].At.After(ms[j].At) })
	if len(ms) > n {
		ms = ms[:n]
	}
	return ms
}

// handleP2PGroupSync answers a gossip pull: verify the requester's signature,
// confirm they are a roster member, then return every message we hold for the
// group that they lack, each re-sealed for them. We forward on the author's
// behalf; the inner author signature is unchanged, so the requester still
// verifies authorship.
func (s *Server) handleP2PGroupSync(w http.ResponseWriter, r *http.Request) {
	peer := s.currentPeer()
	if peer == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	var req protocol.GroupSyncRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, groupSyncMaxBodyByte)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !req.Verify() {
		groupReject(w)
		return
	}
	s.sessMu.Lock()
	g, ok := s.groups[req.GroupID]
	// We only serve a group we ourselves still belong to: once we've left or been
	// removed we stop relaying its history.
	if !ok || !groupHasMember(g, s.myAccount) {
		s.sessMu.Unlock()
		groupReject(w)
		return
	}
	var senderDH [32]byte
	memberOK := false
	for _, m := range g.Members {
		if m.Account == req.Sender && len(m.DHPub) == 32 {
			copy(senderDH[:], m.DHPub)
			memberOK = true
			break
		}
	}
	if !memberOK {
		s.sessMu.Unlock()
		groupReject(w)
		return
	}
	// If our roster is newer than what the requester holds, hand it back so
	// membership converges over the same exchange as history.
	var newerRoster *protocol.SignedRoster
	if g.Epoch > req.HaveEpoch {
		r := groupToRoster(g)
		newerRoster = &r
	}
	have := make(map[string]bool, len(req.Have))
	for _, id := range req.Have {
		have[id] = true
	}
	// Only consider our recent window, newest first, so we never re-offer ancient
	// history the requester already holds but didn't list (which would otherwise
	// repeat every tick) and the response stays bounded.
	window := s.recentGroupMessagesLocked(req.GroupID, groupSyncWindow)
	var missing []protocol.GroupMessage
	for _, m := range window {
		if have[m.ID] {
			continue
		}
		gm, ok := s.groupMessageFromRowLocked(m)
		if !ok {
			continue
		}
		missing = append(missing, gm)
		if len(missing) >= groupSyncMaxMessages {
			break
		}
	}
	// Reactions are gathered over the WHOLE window, NOT gated on have[]: the
	// requester may already hold a message yet be missing a reaction placed on it
	// while they were offline. Each is a self-contained signed event, so we re-serve
	// it wholesale every tick (cheap, bounded) and the requester's LWW apply drops
	// the stale ones — that is what makes catch-up idempotent without touching the
	// signed request. This rides the unsigned response, so build-3 members are
	// unaffected.
	// Rotate the starting offset per group so that when the window holds more than
	// groupSyncMaxReactions events, successive pulls sweep different slices and every
	// message's reactions eventually gossip — otherwise the same first slice would be
	// re-served forever. The cursor advances by the messages actually consumed this
	// round, giving round-robin coverage across ticks.
	var reactEvents []protocol.GroupReaction
	var consumed int
	if n := len(window); n > 0 {
		if s.groupReactCursor == nil {
			s.groupReactCursor = map[string]int{}
		}
		start := s.groupReactCursor[req.GroupID] % n
		for consumed = 0; consumed < n; consumed++ {
			m := window[(start+consumed)%n]
			reactEvents = append(reactEvents, s.groupReactionsFromRowLocked(m)...)
			if len(reactEvents) >= groupSyncMaxReactions {
				reactEvents = reactEvents[:groupSyncMaxReactions]
				consumed++ // this message's slice was included
				break
			}
		}
		s.groupReactCursor[req.GroupID] = (start + consumed) % n
	}
	s.sessMu.Unlock()

	// Seal outside the lock — pure CPU, no shared state.
	out := make([]protocol.GroupEnvelope, 0, len(missing))
	for _, gm := range missing {
		env, err := peer.SealGroup(gm, req.Sender, senderDH)
		if err != nil {
			continue
		}
		out = append(out, env)
	}
	reactOut := make([]protocol.GroupReactionEnvelope, 0, len(reactEvents))
	for _, gr := range reactEvents {
		env, err := peer.SealGroupReactionAs(gr, req.Sender, senderDH)
		if err != nil {
			continue
		}
		reactOut = append(reactOut, env)
	}
	resp := map[string]any{"missing": out}
	if newerRoster != nil {
		resp["roster"] = newerRoster
	}
	if len(reactOut) > 0 {
		resp["reactions"] = reactOut
	}
	writeJSON(w, http.StatusOK, resp)
}

// groupSyncLoop periodically pulls group history from other members so that a
// member who was offline is caught up by whoever is online — the "everyone
// relays / everyone catches you up" model. Pull-based and symmetric: each member
// pulls from the others, so the union converges without push-back.
func (s *Server) groupSyncLoop(ctx context.Context, id *identity.Identity) {
	t := time.NewTimer(groupSyncStartDelay)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.groupSyncTick(ctx, id)
			t.Reset(groupSyncInterval)
		}
	}
}

func (s *Server) groupSyncTick(ctx context.Context, id *identity.Identity) {
	if s.onion == nil {
		return
	}
	// Snapshot, per group, the other members to pull from, the ids we hold, and
	// our roster epoch (so a responder can hand us a newer roster).
	type job struct {
		members []string
		have    []string
		epoch   uint64
	}
	s.sessMu.Lock()
	jobs := make(map[string]*job, len(s.groups))
	for gid, g := range s.groups {
		// Only sync groups we still belong to — once we've left or been removed we
		// stop pulling their history.
		if !groupHasMember(g, s.myAccount) {
			continue
		}
		j := &job{epoch: g.Epoch}
		for _, m := range g.Members {
			if m.Account != s.myAccount {
				j.members = append(j.members, m.Account)
			}
		}
		// Bounded have-list: only the recent window, so it can't grow past the
		// request size limit as a group's history accumulates.
		for _, cm := range s.recentGroupMessagesLocked(gid, groupSyncWindow) {
			j.have = append(j.have, cm.ID)
		}
		jobs[gid] = j
	}
	s.sessMu.Unlock()

	// Pull with bounded concurrency so one unreachable member (up to a 60s
	// timeout) can't serialize the whole tick past its interval.
	sem := make(chan struct{}, groupSyncWorkers)
	var wg sync.WaitGroup
	for gid, j := range jobs {
		for _, member := range j.members {
			select {
			case <-ctx.Done():
				wg.Wait()
				return
			case sem <- struct{}{}:
			}
			wg.Add(1)
			go func(gid, member string, have []string, epoch uint64) {
				defer wg.Done()
				defer func() { <-sem }()
				s.groupSyncPullFrom(ctx, id, gid, member, have, epoch)
			}(gid, member, j.have, j.epoch)
		}
	}
	wg.Wait()
}

func (s *Server) groupSyncPullFrom(ctx context.Context, id *identity.Identity, groupID, member string, have []string, epoch uint64) {
	req := protocol.GroupSyncRequest{GroupID: groupID, Sender: id.AccountNumber(), Have: have, HaveEpoch: epoch}
	req.Sig = protocol.SignGroupSync(id, groupID, have, epoch)
	cctx, cancel := context.WithTimeout(ctx, groupOpTimeout)
	envs, roster, reactEnvs, err := protocol.GroupSyncPull(cctx, s.onion.Dialer(), req, member)
	cancel()
	if err != nil {
		return
	}
	// A newer roster came back with the pull: adopt it through the same trust gate
	// every roster goes through, so membership converges over gossip too.
	if roster != nil {
		s.sessMu.Lock()
		s.acceptRosterLocked(*roster)
		s.sessMu.Unlock()
	}
	// Decrypt + verify outside the lock.
	var gms []protocol.GroupMessage
	for _, env := range envs {
		gm, err := protocol.OpenGroupEnvelope(id, env)
		if err == nil && gm.GroupID == groupID {
			gms = append(gms, gm)
		}
	}
	var grs []protocol.GroupReaction
	for _, env := range reactEnvs {
		gr, err := protocol.OpenGroupReactionEnvelope(id, env)
		if err == nil && gr.GroupID == groupID {
			grs = append(grs, gr)
		}
	}
	if len(gms) == 0 && len(grs) == 0 {
		return
	}
	s.sessMu.Lock()
	g, ok := s.groups[groupID]
	// Only file backfill for a group we still belong to.
	changed := false
	if ok && groupHasMember(g, s.myAccount) {
		for _, gm := range gms {
			// Backfill deliberately does NOT gate on the author being a CURRENT
			// member: the message was authored by a then-member (the author
			// signature proves it) and is served by a current member, so removing
			// someone must not make their past messages un-backfillable to a member
			// who was offline during their tenure. The live endpoint still gates NEW
			// messages on current membership. No notify — this is catch-up.
			if s.deliverGroupInboundLocked(gm, false) {
				changed = true
			}
		}
		// Reaction backfill, same reasoning: applied regardless of the reactor's
		// current membership (their signed event stands), converging via LWW so a
		// re-served stale add can't resurrect a newer un-react.
		for _, gr := range grs {
			if s.applyGroupReactionLocked(gr) {
				changed = true
			}
		}
	}
	if changed {
		s.persistLocked()
	}
	s.sessMu.Unlock()
}
