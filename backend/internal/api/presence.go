package api

import (
	"bytes"
	"context"
	"log"
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
	// helloStickiness bounds how long a verified presence hello keeps a contact
	// marked online after our OWN probe of them fails. The two facts differ while
	// reachability is asymmetric — they can reach us before their descriptor is
	// published, which is exactly the window the hello exists to cover — and
	// without this the sweep demotes the dot ~30s after every hello promotes it.
	//
	// Must exceed the gap between their hellos (they announce once per THEIR
	// sweep, observed ~38s apart on device) or the dot flickers regardless. 90s
	// tolerates one lost hello and still drops the dot within a few sweeps of a
	// contact actually going quiet.
	helloStickiness = 90 * time.Second
	// probeBackoffGrace is how many consecutive failed probes a contact keeps at
	// the full presenceInterval cadence before the sweep starts skipping them. A
	// single failure is usually ours, not theirs — a circuit that died mid-probe,
	// a relay that timed out — so the first two sweeps after a contact drops off
	// are free and the dot reaches 🔴 as fast as it always did. Only a contact
	// that is still unreachable on the third sweep is treated as actually gone.
	probeBackoffGrace = 2
	// probeBackoffMax caps the skip window for a contact that stays unreachable.
	// Each further failure doubles the wait (30s grace, then 60s, 2m, 4m, 5m), so
	// a contact who is simply offline costs one dial per 5 minutes instead of one
	// per 30s — a ~10x cut in the sweep's dial volume, which is nearly all of the
	// outbound dialing this device does when its contacts are offline. Each of
	// those dials is a hidden-service descriptor lookup, and they compete for
	// circuit capacity with our OWN descriptor upload while we are publishing.
	//
	// The cost is detection latency for a peer who comes back SILENTLY: no hello,
	// no message, nothing — just a published descriptor. They can sit green-able
	// but grey for up to this long. That is affordable now in a way it wasn't
	// before touchPeerPresenceLocked started promoting on authenticated inbound
	// traffic and successful direct sends: a peer who actually interacts with us
	// is marked online by that traffic and resets this backoff on the spot, so
	// the window only ever applies to a peer doing nothing. Shrink this number if
	// grey-but-reachable contacts become a complaint; it is the one dial worth
	// tuning.
	probeBackoffMax = 5 * time.Minute
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
	go s.rotationRetryLoop(ctx, id)
	go s.rotationRefreshLoop(ctx, id)
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

// runLoop drives one of the background maintenance loops. It blocks until the
// onion is dialable, runs the first tick immediately, then repeats on interval.
//
// The wait replaces the fixed start delays these loops used to open with. Those
// delays were guesses at how long bootstrap takes, and they were wrong in both
// directions: on a slow network the first tick still fired into a dead dialer
// and wasted a retry attempt, while on a warm start the loop sat idle for up to
// 20s after the onion was already serving traffic.
//
// One thing the old delays did provide incidentally was a stagger: they were
// 5/15/15/20/20/25s apart, so the loops did not all dial at once. Every loop
// now fires its first tick together. For the retry loops that is free: an idle
// tick is a no-op — nothing queued in the outbox, no pending accepts, no
// groups, no held relay blobs — so on a primary the only first ticks doing real
// work are the mailbox check-in and the presence sweep.
//
// syncLoop is the exception, and only on a secondary device: its tick dials the
// primary for a state exchange plus an image backfill unconditionally, with no
// "is there anything to sync" gate (the only gate is !IsPrimary). A secondary
// therefore opens with three concurrent dials where it used to get a 20s head
// start on the third. That is a deliberate trade — the dial is the work the
// loop exists to do and waiting for dialable already means circuits are up —
// but if it proves costly, give this helper a per-loop offset rather than
// putting the blind delays back.
func (s *Server) runLoop(ctx context.Context, interval time.Duration, tick func()) {
	if !s.waitDialable(ctx) {
		return
	}
	tick()
	t := time.NewTimer(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
			t.Reset(interval)
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
	// Resolved once, up front: it gates both the skip below and the log line, so
	// the two cannot drift, and it keeps devMu (which announcing takes through
	// currentDevice) from ever being acquired inside sessMu.
	announcing := s.announcing()

	s.sessMu.Lock()
	accts := make([]string, 0, len(s.contacts))
	for acct, c := range s.contacts {
		if c.Status != chatstore.StatusAccepted {
			continue
		}
		// While unpublished, probe everyone every sweep regardless of how long
		// they have been unreachable: the probe is carrying our presence hello,
		// which is the only way a contact learns we are up before our descriptor
		// reaches the HSDir ring. Backing off here would throttle our own
		// announcements during exactly the window the hello exists to cover —
		// and on a slow publish (minutes, not seconds) that is the window that
		// matters most.
		if !announcing && !s.probeDueLocked(acct) {
			continue
		}
		accts = append(accts, acct)
	}
	s.sessMu.Unlock()
	// Can now be empty in the steady state, not just when we have no contacts:
	// every contact being backed off is the normal resting state of a device
	// whose peers are all offline.
	if len(accts) == 0 {
		return
	}

	// One line per sweep, not per contact, and only while we are announcing — so
	// this is silent in the steady state and the lines that do appear bracket
	// exactly the window in which a hello could have been sent. Counts only; the
	// contacts are not named.
	if announcing {
		log.Printf("presence hello: announcing to %d contacts (our own service is not published yet)", len(accts))
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
	pr, err := s.fetchProfileAnnouncing(pctx, id, acct)
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
		// Present the account this contact knows us by (their MyAccountKnown), not the
		// primary: post-rotation their gate keys us by the alias, so a primary-stamped
		// probe would fail their accepted-contact check. On any resolve error, skip the
		// refresh (the cached mailbox stays; the next sweep retries), same as a fetch miss.
		if from, signPriv, ierr := s.outboundIdentity(id, acct); ierr == nil {
			if cp, cerr := protocol.FetchContactProfile(pctx, s.onion.Dialer(), from, signPriv, acct); cerr == nil {
				haveMailbox, mailbox = true, cp.MailboxURL
			}
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
		delete(s.probeBackoff, acct)
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
	state := presenceState(reachable, c.MailboxURL)
	// Our probe failing does not mean they are gone: while their descriptor is
	// still publishing they can reach US but we cannot reach THEM. A recent
	// verified hello is direct evidence of the first, so it holds the dot rather
	// than letting this sweep overwrite it. Promotion only — a stale hello leaves
	// the probe's own verdict untouched.
	if state != presenceOnline && s.helloFreshLocked(acct) {
		state = presenceOnline
	}
	s.presence[acct] = state
	// Accounted AFTER the state is final, so the hello promotion above counts as
	// evidence of reachability and resets the backoff: a contact we cannot dial
	// but who keeps reaching us is the one contact we most want to keep re-testing.
	s.recordProbeOutcomeLocked(acct, state)
}

// probeBackoffEntry tracks one contact's consecutive-failure streak and the time
// the next probe of them is due. Session-local, never persisted.
type probeBackoffEntry struct {
	fails  int       // consecutive failed probes (reset by any evidence of reachability)
	nextAt time.Time // zero until the streak passes probeBackoffGrace
	capped bool      // the cap-reached line has been logged for this streak
}

// probeDueLocked reports whether the sweep should spend a dial on acct this time
// round. Caller holds sessMu.
func (s *Server) probeDueLocked(acct string) bool {
	// A contact recorded online while failing our probes is being held there by a
	// fresh hello — they can reach us, we cannot yet reach them. Never back that
	// off: it is the asymmetric case resolving, and skipping sweeps would also
	// leave the dot green for up to one backoff window past helloStickiness with
	// nothing left to demote it. Self-limiting — once the hello goes stale the
	// state flips and the backoff accrues normally.
	if s.presence[acct] == presenceOnline {
		return true
	}
	b, ok := s.probeBackoff[acct]
	return !ok || !time.Now().Before(b.nextAt)
}

// recordProbeOutcomeLocked folds one probe's result into acct's backoff streak.
// Only presenceOnline clears it — that is the one state meaning somebody crossed
// the gap, whether our dial landed or their hello did. Otherwise the streak
// grows and the next probe is pushed out with a doubling, capped delay.
//
// presenceMailbox backs off alongside presenceOffline, deliberately: a contact
// we cannot dial but can leave mail for is still a contact we cannot dial, and
// the outbox reaches their mailbox on its own schedule without needing the sweep
// to keep re-testing a direct path that has failed every time so far.
//
// Caller holds sessMu.
func (s *Server) recordProbeOutcomeLocked(acct, state string) {
	if state == presenceOnline {
		delete(s.probeBackoff, acct)
		return
	}
	if s.probeBackoff == nil {
		s.probeBackoff = map[string]probeBackoffEntry{}
	}
	b := s.probeBackoff[acct]
	b.fails++
	if b.fails > probeBackoffGrace {
		// Doubling from presenceInterval, by iteration rather than a shift: the
		// loop stops at the cap, which also means fails can grow for the whole
		// session without the delay ever overflowing.
		d := presenceInterval
		for i := probeBackoffGrace; i < b.fails && d < probeBackoffMax; i++ {
			d *= 2
		}
		if d > probeBackoffMax {
			d = probeBackoffMax
		}
		b.nextAt = time.Now().Add(d)
		// Once per contact per streak, and the contact is not named: the fact
		// worth having in the field is that the sweep has stopped dialing someone
		// hard, which is otherwise only visible as an absence of lines.
		if d == probeBackoffMax && !b.capped {
			b.capped = true
			log.Printf("presence sweep: a contact has failed %d consecutive probes — backing off to one probe per %s", b.fails, probeBackoffMax)
		}
	}
	s.probeBackoff[acct] = b
}

// helloFreshLocked reports whether a verified presence hello from acct arrived
// recently enough to outweigh a failed outbound probe. Caller holds sessMu.
func (s *Server) helloFreshLocked(acct string) bool {
	at, ok := s.helloAt[acct]
	return ok && time.Since(at) < helloStickiness
}

// fetchProfileAnnouncing fetches a contact's card, stamping the request with a
// signed presence hello while our own onion is not yet published.
//
// The stamp is what lets a contact see us come online without waiting for our
// descriptor to reach the HSDir ring. Dialing out needs only Dialable, which goes
// true well before Ready (see tor.OnionService), and publishing is the slow half
// — so while we are unpublished we are invisible to every probe and the hello is
// the only way anyone learns we are here.
//
// announcing reports whether outbound profile fetches should carry a presence
// hello right now. Factored out of fetchProfileAnnouncing so the per-sweep log
// line and the per-contact decision read the same gate and cannot drift: a log
// that disagreed with the behaviour would be worse than no log.
//
// device.Config.IsPrimary dereferences its receiver, and currentDevice can be
// nil (no device config loaded). Treat that as "not announcing": a stamp is an
// optimisation, so the uncertain case loses latency, never correctness.
//
// "Not yet published" is a latched question, not a live one — hence
// publishedOnce() rather than Ready() directly. Ready() dips every time the
// service re-establishes an intro point, and reading it live treats each dip as
// a fresh unpublished state: that resumes announcing, and with it the
// full-cadence probe sweep this gate unlocks, on a service that never left the
// HSDirs. Measured: 24 dips in 12 minutes on one device.
func (s *Server) announcing() bool {
	dev := s.currentDevice()
	return dev != nil && dev.IsPrimary() && s.onion != nil && !s.publishedOnce()
}

// Stamped ONLY while unpublished, so the steady state costs nothing: once the
// publish is confirmed, a contact's own sweep finds us within presenceInterval
// and a hello would only tell them what they can already see for themselves.
//
// Only a primary announces. The hello claims the ACCOUNT is reachable, and only
// the primary publishes the account onion — a secondary that announced would show
// itself online to contacts whose messages still go to a primary they cannot
// reach. Ready() happens to report true in client-only mode, so gating on it
// alone would get this right by accident; the role check says so on purpose.
func (s *Server) fetchProfileAnnouncing(ctx context.Context, id *identity.Identity, acct string) (protocol.Profile, error) {
	if s.announcing() {
		// outboundIdentity resolves the account this contact knows us by, so a
		// post-rotation hello is signed by the alias key they can verify — the same
		// resolution the gated mailbox refresh below does. On an error we fall
		// through to the anonymous fetch rather than stamping with the primary,
		// which would leak it.
		if from, signPriv, err := s.outboundIdentity(id, acct); err == nil {
			return protocol.FetchProfileAs(ctx, s.onion.Dialer(), from, signPriv, acct)
		}
	}
	return protocol.FetchProfile(ctx, s.onion.Dialer(), acct)
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
