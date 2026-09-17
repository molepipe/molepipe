package api

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// Presence states, surfaced per-contact to the UI (🟢/🟡/🔴).
const (
	presenceOnline  = "online"  // reachable directly right now
	presenceMailbox = "mailbox" // not reachable, but has a known mailbox — still deliverable
	presenceOffline = "offline" // not reachable and no mailbox known
	presenceUnknown = "unknown" // not probed yet this session
)

const (
	presenceInterval = 30 * time.Second // how often to re-probe all contacts
	presenceTimeout  = 10 * time.Second // per-contact probe budget — a reachable contact responds in
	// 1-3s; an unreachable one builds a circuit that either completes in 5-10s or
	// is genuinely down. 30s was excessive and delayed the sweep.
	presenceWorkers = 8 // bounded concurrency across contacts
	// mailboxRefreshTTL bounds how often a presence sweep re-pulls a contact's
	// mailbox from their gated contact-profile endpoint. The mailbox moved out of
	// the public card (a privacy change), so it can no longer be read for free on
	// every sweep; it rarely changes, so a long TTL keeps the extra Tor traffic
	// negligible while still catching a mailbox change within the window.
	mailboxRefreshTTL = 30 * time.Minute
)

// presenceState decides a contact's status from a probe result. Pure so it can
// be tested without Tor: reachable ⇒ online; otherwise 🟡 iff we have a cached
// mailbox to fall back on, else 🔴.
func presenceState(reachable bool, cachedMailbox string) string {
	switch {
	case reachable:
		return presenceOnline
	case cachedMailbox != "":
		return presenceMailbox
	default:
		return presenceOffline
	}
}

// startSessionLoops launches the background presence prober and mailbox loop for
// this session. Caller holds sessMu (called from startSession). No-op when Tor
// is disabled (no way to probe or reach a mailbox).
func (s *Server) startSessionLoops(id *identity.Identity) {
	if s.onion == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.sessionCancel = cancel
	go s.presenceLoop(ctx, id)
	go s.mailboxLoop(ctx, id)
	go s.syncLoop(ctx, id)
	go s.groupSyncLoop(ctx, id)
	go s.groupInviteRetryLoop(ctx, id)
	go s.relayForwardLoop(ctx)
	go s.acceptRetryLoop(ctx, id)
	go s.outboxLoop(ctx, id)
}

// stopSessionLoops halts the background loops. Caller holds sessMu (clearSession).
func (s *Server) stopSessionLoops() {
	if s.sessionCancel != nil {
		s.sessionCancel()
		s.sessionCancel = nil
	}
}

func (s *Server) presenceLoop(ctx context.Context, id *identity.Identity) {
	// Wait until we can actually dial out before the first sweep. The loop used
	// to probe immediately on unlock — before Tor finished bootstrapping — so
	// every probe failed and marked online contacts "offline", a false state
	// that then stuck until the next 45s sweep (the "shows offline after unlock"
	// bug). Dialable() flips within ~0.6s of a warm relock, so this costs almost
	// nothing and the first sweep now reflects real reachability.
	if !s.waitDialable(ctx) {
		return
	}
	// Fire the first sweep immediately — some contacts may already be reachable
	// (cached circuits from a previous session, or Tor built circuits during the
	// pre-warm bootstrap). Contacts that need a fresh circuit take 5-10s but
	// still complete well within the per-contact timeout. A fixed warmup delays
	// ALL contacts by that amount even when some are already reachable, so we
	// skip it entirely: fast contacts appear quickly, slow ones take their natural
	// time.
	s.probeAllContacts(ctx, id)
	t := time.NewTimer(presenceInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.probeAllContacts(ctx, id)
			t.Reset(presenceInterval)
		}
	}
}

// waitDialable blocks until the onion can build outbound circuits, ctx ends, or
// (defensively) there is no onion. Returns true only if we became dialable.
func (s *Server) waitDialable(ctx context.Context) bool {
	if s.onion == nil {
		return false
	}
	for {
		if s.onion.Dialable() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// probeAllContacts probes every accepted contact with bounded concurrency and
// records the resulting presence state (and refreshes any cached mailbox).
func (s *Server) probeAllContacts(ctx context.Context, id *identity.Identity) {
	s.sessMu.Lock()
	accts := make([]string, 0, len(s.contacts))
	for acct, c := range s.contacts {
		if c.Status == chatstore.StatusAccepted {
			accts = append(accts, acct)
		}
	}
	s.sessMu.Unlock()
	if len(accts) == 0 {
		return
	}

	sem := make(chan struct{}, presenceWorkers)
	var wg sync.WaitGroup
	for _, acct := range accts {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(acct string) {
			defer wg.Done()
			defer func() { <-sem }()
			s.probeContact(ctx, id, acct)
		}(acct)
	}
	wg.Wait()
}

// probeContact fetches a contact's signed profile (which proves direct
// reachability and carries their name + DH key), and — at most once per
// mailboxRefreshTTL — pulls their mailbox from the gated contact-profile
// endpoint. It caches both; either way it records the derived presence state.
func (s *Server) probeContact(ctx context.Context, id *identity.Identity, acct string) {
	pctx, cancel := context.WithTimeout(ctx, presenceTimeout)
	defer cancel()
	pr, err := protocol.FetchProfile(pctx, s.onion.Dialer(), acct)
	reachable := err == nil

	// While reachable, opportunistically refresh the mailbox from the gated
	// endpoint (it left the public card, so `pr` no longer carries it). Rate-
	// limited by mailboxRefreshTTL so this extra round-trip is rare. Done outside
	// the lock, like FetchProfile above; a failure just leaves the cached mailbox
	// as-is and lets the next sweep retry (handles a peer still mid-upgrade).
	var (
		haveMailbox bool
		mailbox     string
	)
	if reachable && s.shouldRefreshMailbox(acct) {
		if cp, cerr := protocol.FetchContactProfile(pctx, s.onion.Dialer(), id, acct); cerr == nil {
			haveMailbox, mailbox = true, cp.MailboxURL
		}
	}

	// Fetch (but don't yet store) the contact's avatar bytes when the card
	// advertises a hash we don't already hold (a new contact or a changed picture).
	// The network fetch stays OFF the lock; the bytes are stored under sessMu below,
	// in the SAME critical section that records c.AvatarHash — so the orphan sweep
	// (this probe's, or a concurrent worker's) can never see the bytes on disk
	// before the keep-set reference that protects them exists. A failed fetch just
	// leaves the UI on the initials fallback and lets a later sweep retry.
	var avatarData []byte
	if reachable && pr.AvatarHash != "" {
		if store := s.avatarStoreHandle(); store != nil && !store.Has(pr.AvatarHash) {
			if data, aerr := protocol.FetchAvatar(pctx, s.onion.Dialer(), acct, pr.AvatarHash); aerr == nil {
				avatarData = data
			}
		}
	}

	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if s.presence == nil {
		s.presence = map[string]string{}
	}
	c, ok := s.contacts[acct]
	if !ok { // removed mid-probe
		delete(s.presence, acct)
		return
	}
	// A failed probe only means "offline" if OUR transport is up. If we can't
	// dial out right now (a circuit rebuild, a post-unlock blip), the failure
	// says nothing about the peer — keep the last-known state rather than
	// falsely downgrading an online contact to offline.
	if !reachable && s.onion != nil && !s.onion.Dialable() {
		return
	}
	if reachable { // refresh cached name + DH key from the live profile
		changed := false
		// The peer's signed profile is the source of truth for their display name
		// (1:1 contacts have no local alias — only the peer sets it), so a name
		// they change or set later propagates to us on the next presence sweep.
		// Guard on non-empty so an anonymous/blank profile never wipes a known name.
		if pr.DisplayName != "" && pr.DisplayName != c.Name {
			c.Name = pr.DisplayName
			changed = true
		}
		if haveMailbox && mailbox != c.MailboxURL {
			c.MailboxURL = mailbox
			changed = true
		}
		if !bytes.Equal(pr.DHPub, c.DHPub) {
			c.DHPub = pr.DHPub
			changed = true
		}
		// Record the avatar hash from the signed card even if the byte-fetch above
		// missed — the render endpoint 404s gracefully to initials, and the next
		// sweep backfills the bytes (store still lacks them).
		avatarRotated := false
		if pr.AvatarHash != "" && pr.AvatarHash != c.AvatarHash {
			c.AvatarHash = pr.AvatarHash
			changed = true
			avatarRotated = true
		}
		if changed {
			s.contacts[acct] = c
			s.persistLocked()
		}
		// Store the fetched bytes HERE, under the same lock that just recorded
		// c.AvatarHash, so the reference always exists on disk before the sweep can
		// run. Put is idempotent and verifies sha256(data)==hash; it covers both a
		// rotation and a plain backfill of missing bytes for the current hash.
		if len(avatarData) > 0 && s.avatarStore != nil {
			_ = s.avatarStore.Put(pr.AvatarHash, avatarData)
		}
		// A contact rotating their picture strands the bytes under their old hash
		// (content-addressed store never evicts); reclaim them now so a device that
		// stays unlocked for weeks can't accumulate orphans up to the store cap. Runs
		// only on the rare sweep where a hash actually changed, not every probe.
		if avatarRotated {
			s.sweepOrphanAvatarsLocked()
		}
		if haveMailbox {
			if s.mailboxCheckedAt == nil {
				s.mailboxCheckedAt = map[string]time.Time{}
			}
			s.mailboxCheckedAt[acct] = time.Now()
		}
	}
	s.presence[acct] = presenceState(reachable, c.MailboxURL)
}

// avatarStoreHandle returns the current avatar store (nil while locked) under the
// session lock, so a sweep goroutine can use it without racing clearSession.
func (s *Server) avatarStoreHandle() *chatstore.AvatarStore {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	return s.avatarStore
}

// shouldRefreshMailbox reports whether the contact's gated mailbox is due for a
// re-pull (never fetched this session, or older than mailboxRefreshTTL).
func (s *Server) shouldRefreshMailbox(acct string) bool {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if s.mailboxCheckedAt == nil {
		return true
	}
	last, ok := s.mailboxCheckedAt[acct]
	return !ok || time.Since(last) > mailboxRefreshTTL
}
