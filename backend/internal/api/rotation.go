package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/crypto"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
	"github.com/molepipe/molepipe/backend/internal/tor"
)

const (
	// rotationGraceWindow is how long an alias onion stays live and republished
	// after it stops being the current account, so a contact who has not yet
	// applied the rotation can still reach us there. User-locked at 7 days.
	rotationGraceWindow = 7 * 24 * time.Hour
	// rotationRefreshInterval is the cadence of time-based auto-refresh (a fresh
	// alias is minted this long after the last rotation). User-locked at weekly.
	rotationRefreshInterval = 7 * 24 * time.Hour
	// rotationRetryStartDelay / rotationRetryInterval pace the resend of pending
	// rotations over the ratchet session. There is deliberately NO give-up TTL
	// (unlike acceptRetryTTL): a rotation is not a one-shot social debt that goes
	// moot — a contact who never acks keeps dialing an alias we are retiring, so
	// abandoning delivery would manufacture the very orphan the grace window exists
	// to avoid. Entries leave pendingRotations only on ack, on being superseded by a
	// newer rotation, or when the grace sweeper retires the alias the contact still
	// knows us by (slice 3). The cadence mirrors accept retry.
	rotationRetryStartDelay = 20 * time.Second
	rotationRetryInterval   = 60 * time.Second
	// rotationSendTimeout bounds one rotation/ack delivery attempt over Tor.
	rotationSendTimeout = 90 * time.Second
	// rotationRefreshCheck is how often the auto-refresh loop wakes to see whether
	// the current alias has reached NextRefreshAt. Far finer than the weekly
	// interval so a rotation fires within an hour of coming due, without a per-tick
	// cost that matters.
	rotationRefreshCheck = time.Hour
)

// extraOnionHost is the optional capability a tor.OnionService may implement to
// run additional concurrent onion services (rotation aliases) alongside the
// primary account onion, for the rotating-identity feature. artihost (mobile)
// implements it; torsidecar (desktop) will; the no-tor path and iOS stub do not.
// The api layer reaches it via an optional upcast so a host that lacks it
// degrades to "rotation unavailable" rather than breaking the build.
type extraOnionHost interface {
	// StartExtraService publishes an additional onion at the given alias key,
	// forwarding inbound streams to localAddr, under a nickname unique across the
	// primary and every live alias. Returns the .onion address and an id to pass
	// to StopExtraService.
	StartExtraService(key tor.OnionKey, localAddr, nickname string) (onion string, id uint64, err error)
	// StopExtraService tears down one alias by id (no-op for an unknown id).
	StopExtraService(id uint64)
}

// asExtraOnionHost returns the onion service as an extraOnionHost if it supports
// concurrent alias services, else nil, false.
func (s *Server) asExtraOnionHost() (extraOnionHost, bool) {
	h, ok := s.onion.(extraOnionHost)
	return h, ok
}

// lookupContactByDHPubLocked resolves an address rotation's channel identity on
// the mailbox path: given the SenderDHPub of a static-DH mailbox seal, it finds
// the one accepted contact whose cached DHPub matches. This is the reverse of the
// account-keyed contacts map (the DHPub is the non-rotating continuity anchor,
// the account rotates), so it scans.
//
// It FAILS CLOSED on ambiguity: if two contacts somehow carry the same DHPub it
// returns ok=false rather than guessing which one a rotation is meant to migrate.
// Only accepted contacts are eligible — a rotation is meaningful only from someone
// we already trust at a current alias. Caller holds sessMu.
// hookOnAddressRotation applies a channel-authenticated AddressRotation from a
// contact (protocol.Hooks.OnAddressRotation). contactAccount is the identity the
// CHANNEL proved — the account we currently know the contact by (the ratchet
// session's account, or the DHPub-matched contact on the mailbox path) — NEVER an
// account carried in the payload. newOnion and aliasIndex are the announcement.
//
// It enforces the two receive-side invariants: the contact must be a known,
// accepted contact, and aliasIndex must EXCEED the highest index already accepted
// (Contact.AliasIndex) — the monotonic rollback-replay guard (a replayed older
// announcement can't walk the contact back to a dead onion). On success it
// re-keys every per-peer structure to the new onion atomically, advances the
// stored index, and persists once.
func (s *Server) hookOnAddressRotation(contactAccount, newOnion string, aliasIndex uint32) error {
	s.sessMu.Lock()
	id := s.sessID
	err := s.applyAddressRotationLocked(contactAccount, newOnion, aliasIndex)
	s.sessMu.Unlock()
	if err != nil {
		return err
	}
	// The rotation applied (or was already applied — applyAddressRotationLocked
	// returns nil for BOTH). Ack it back to the rotator, best-effort, on a
	// goroutine so the receive handler never dials under the (now released) lock.
	// The ack MUST be re-sent on the idempotent path too: a resend means our
	// earlier ack was lost, and this re-ack is what finally lets the rotator stop.
	// Liveness rests entirely on the rotator's resend loop, so a dropped ack here
	// simply triggers another resend that we ack again — no receiver-side queue.
	// The ack rides the session to the rotator's NEW address (newOnion), which the
	// migration above made the contact's current account.
	if id != nil {
		go s.deliverRotationAck(id, newOnion, aliasIndex)
	}
	return nil
}

// deliverRotationAck sends a best-effort rotation ack for `ackedIndex` to `to`
// (the rotator, now at its new onion) over the established session. Errors are
// logged, not retried — the rotator's resend drives liveness (see
// hookOnAddressRotation).
func (s *Server) deliverRotationAck(idn *identity.Identity, to string, ackedIndex uint32) {
	if s.onion == nil {
		return
	}
	ctx, cancel := deliveryContext(rotationSendTimeout)
	defer cancel()
	if err := s.sendSealedOverSessionV2(ctx, s.onion.Dialer(), idn, to, protocol.EncodeRotationAckPayload(ackedIndex)); err != nil {
		log.Printf("rotation ack to %s (index %d) failed (will re-ack on next resend): %v", to, ackedIndex, err)
	}
}

// resolvePeerAccountLocked maps an inbound sender account to the account we
// currently know that contact by. It returns account unchanged for a current
// contact (or a stranger); only a retired ALIAS a contact rotated away from
// resolves — to the account we migrated that contact to. This is what makes an
// ack-lost resend of a rotation (still addressed from the old alias, because the
// sender resends over the old-alias channel until we ack) recognisable rather
// than an unknown sender with no session. Onion addresses are public keys, so a
// retired alias can never collide with a different identity's current account;
// the map is single-hop (collapsed on record) so no chasing is needed. Caller
// holds sessMu.
func (s *Server) resolvePeerAccountLocked(account string) string {
	if cur, ok := s.peerAliases[account]; ok {
		return cur
	}
	return account
}

// resolvePeerAccount is the lock-acquiring form for callers that don't already
// hold sessMu (the ratchet session-manager adapter). It takes sessMu only briefly
// and never holds a manager lock, so it is safe to call before manager operations.
func (s *Server) resolvePeerAccount(account string) string {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	return s.resolvePeerAccountLocked(account)
}

// recordPeerAliasLocked notes that a contact's old account is now a retired alias
// of new (its current account) after a rotation, so a later resend from old
// resolves forward. It collapses any existing chain (entries that pointed at old
// now point at new) so resolution stays single-hop, and clears any entry keyed by
// new, since new is now a live account rather than an alias of anything. Caller
// holds sessMu; the caller persists. No-op when old==new or either is empty.
func (s *Server) recordPeerAliasLocked(old, new string) {
	if old == "" || new == "" || old == new {
		return
	}
	if s.peerAliases == nil {
		s.peerAliases = map[string]string{}
	}
	for k, v := range s.peerAliases {
		if v == old {
			s.peerAliases[k] = new
		}
	}
	s.peerAliases[old] = new
	delete(s.peerAliases, new)
}

// setLiveAliasAccountsLocked records the alias onion accounts we are currently
// publishing beyond the primary and pushes them to the receive path, so a contact
// who hasn't applied our rotation and still dials an alias-of-us is recognised as
// addressing a valid recipient identity. The rotation orchestrator calls this when
// an alias service starts (add) or is torn down after its grace window (remove).
// Caller holds sessMu.
func (s *Server) setLiveAliasAccountsLocked(accounts []string) {
	s.localAliasAccounts = append([]string(nil), accounts...)
	if s.peer != nil {
		s.peer.SetLocalAliasAccounts(s.localAliasAccounts)
	}
}

// recipientCandidates returns the account identities a sender may have addressed a
// v2 INIT to: our primary account first, then any live alias. It is the api-layer
// counterpart of Peer.recipientCandidates for the established-message path; the
// init handler retries the signature against each so a handshake dialed at an
// alias-of-us during a grace window is accepted. Takes sessMu.
func (s *Server) recipientCandidates(idn *identity.Identity) []string {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	out := make([]string, 0, 1+len(s.localAliasAccounts))
	out = append(out, idn.AccountNumber())
	out = append(out, s.localAliasAccounts...)
	return out
}

// deriveAliasOnionKey derives the Tor onion-service key for our own rotation
// alias `index` (m/0'/2'/index'). It reads zeroable key material (the mnemonic),
// so — exactly like onionKeyFor for the primary — it MUST run while the identity
// is guaranteed live, never on a goroutine that could race a lock zeroing the
// mnemonic. The returned key carries secret material; the caller zeroes it once
// published.
func (s *Server) deriveAliasOnionKey(idn *identity.Identity, index uint32) (tor.OnionKey, error) {
	kp, err := idn.AliasSigningKey(index)
	if err != nil {
		return tor.OnionKey{}, fmt.Errorf("derive alias %d signing key: %w", index, err)
	}
	defer crypto.Zero(kp.Private)
	return tor.DeriveOnionKey(kp.Private.Seed())
}

// cacheAliasSigningKeyLocked derives alias `index`'s Ed25519 signing key and
// keeps it resident under `account` so the send path can stamp AND sign an
// outbound message as that alias without re-deriving from the mnemonic (a
// PBKDF2) per message. Unlike deriveAliasOnionKey the private key is NOT zeroed
// here — it lives for the unlocked session and is zeroed in clearSession. It
// reads the mnemonic, so like deriveAliasOnionKey it MUST run while the identity
// is guaranteed live. Caller holds sessMu.
func (s *Server) cacheAliasSigningKeyLocked(idn *identity.Identity, index uint32, account string) error {
	kp, err := idn.AliasSigningKey(index)
	if err != nil {
		return fmt.Errorf("cache alias %d signing key: %w", index, err)
	}
	if s.aliasSigningKeys == nil {
		s.aliasSigningKeys = map[string]crypto.SigningKeyPair{}
	}
	s.aliasSigningKeys[account] = kp
	return nil
}

// refreshLiveAliasesLocked recomputes the set of alias accounts we are currently
// publishing beyond the primary — the current alias plus every history alias still
// within its grace window — and pushes it to the recipient-identity receive path
// (setLiveAliasAccountsLocked). Expired history entries are excluded (the grace
// sweeper tears their services down separately); a nil rotation clears the set.
// Caller holds sessMu.
func (s *Server) refreshLiveAliasesLocked() {
	if s.rotation == nil {
		s.setLiveAliasAccountsLocked(nil)
		return
	}
	now := time.Now()
	live := make([]string, 0, 1+len(s.rotation.History))
	live = append(live, s.rotation.CurrentAccount)
	for _, h := range s.rotation.History {
		if now.Before(h.RetireAt) {
			live = append(live, h.Account)
		}
	}
	s.setLiveAliasAccountsLocked(live)
}

// performRotationLocked mints the next rotation alias, publishes it as a concurrent
// onion service, makes it our current advertised account, and enqueues an
// ack-driven AddressRotation to every accepted contact. The previous current alias
// (if any) moves into History with a 7-day grace deadline and stays live (still in
// localAliasAccounts, its service still up) so a contact who has not yet applied
// the rotation can still reach us there; the grace sweeper tears it down later.
//
// The FIRST rotation runs from a nil RotationState — this is the existing-identity
// migration: index 0 is a FRESH alias (m/0'/2'/0'), NEVER the primary m/0'/0'
// onion, which has no StopExtraService and stays live as unadvertised
// infrastructure (a retired address that still answers but gates every verb on
// contact status — the plan's "leaked alias self-heals" property, not a leak).
//
// idn must be live (caller passes the unlocked identity from a request or timer).
// Requires an extraOnionHost; returns the new onion. Caller holds sessMu; persists
// once.
func (s *Server) performRotationLocked(idn *identity.Identity) (string, error) {
	host, ok := s.asExtraOnionHost()
	if !ok {
		return "", fmt.Errorf("rotation unavailable: onion host has no concurrent-service support")
	}
	var nextIndex uint32
	if s.rotation != nil {
		nextIndex = s.rotation.CurrentIndex + 1
	}
	key, err := s.deriveAliasOnionKey(idn, nextIndex)
	if err != nil {
		return "", err
	}
	nick := fmt.Sprintf("alias-%d", nextIndex)
	onion, id, err := host.StartExtraService(key, s.publicAddr(), nick)
	key.Zeroize()
	if err != nil {
		return "", fmt.Errorf("publish alias %d: %w", nextIndex, err)
	}

	// Make the new alias's signing key resident BEFORE committing s.rotation to it.
	// Once a contact acks this rotation (advancing their MyAccountKnown to `onion`),
	// the send path signs their messages with this key; advertisedAccountLocked also
	// starts handing `onion` out the instant s.rotation flips. Both would be broken
	// by an alias whose key never became resident, so this fallible step runs while
	// nothing is committed yet: on failure we tear the just-published service back
	// down and leave s.rotation untouched, so handleRotate's 503 is truthful (nothing
	// changed) rather than half-applied. Derived here while idn is live; zeroed in
	// clearSession.
	if err := s.cacheAliasSigningKeyLocked(idn, nextIndex, onion); err != nil {
		host.StopExtraService(id)
		return "", fmt.Errorf("cache alias %d signing key: %w", nextIndex, err)
	}

	now := time.Now()
	var history []chatstore.AliasRecord
	if s.rotation != nil {
		history = append(history, s.rotation.History...)
		history = append(history, chatstore.AliasRecord{
			Index:    s.rotation.CurrentIndex,
			Account:  s.rotation.CurrentAccount,
			RetireAt: now.Add(rotationGraceWindow),
		})
	}
	s.rotation = &chatstore.RotationState{
		CurrentIndex:   nextIndex,
		CurrentAccount: onion,
		NextRefreshAt:  now.Add(rotationRefreshInterval),
		History:        history,
	}
	if s.aliasServiceIDs == nil {
		s.aliasServiceIDs = map[string]uint64{}
	}
	s.aliasServiceIDs[onion] = id
	s.refreshLiveAliasesLocked()

	// Enqueue ack-driven, resend-until-acked delivery to every accepted contact,
	// keyed by the account we currently know them by (s.contacts keys). A newer
	// rotation supersedes any still-pending older one for the same contact.
	if s.pendingRotations == nil {
		s.pendingRotations = map[string]chatstore.RotationPending{}
	}
	for acct, c := range s.contacts {
		if c.Status != chatstore.StatusAccepted {
			continue
		}
		s.pendingRotations[acct] = chatstore.RotationPending{
			NewOnion:   onion,
			AliasIndex: nextIndex,
			QueuedAt:   now,
		}
	}
	s.persistLocked()
	return onion, nil
}

// handleRotate (POST /api/rotate) manually rotates our advertised address: it mints
// the next alias onion, publishes it as a concurrent service, makes it current, and
// enqueues an ack-driven announcement to every accepted contact (the retry loop
// delivers). This is a DISTINCT operation from the invite-code "refresh" action,
// which only mints a new token on the SAME address — rotation publishes a new
// hidden-service descriptor and retires the old alias after the grace window, so the
// permanent onion is never handed out again. Returns the refreshed friend-code card
// so the UI updates in one round-trip. Fails 503 when the onion host has no
// concurrent-service support (rotation is unavailable rather than silently no-op).
func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	s.sessMu.Lock()
	_, err := s.performRotationLocked(id)
	var resp inviteCodeResponse
	if err == nil {
		resp = s.inviteCodeResponseLocked(id)
	}
	s.sessMu.Unlock()
	if err != nil {
		log.Printf("rotate: %v", err)
		http.Error(w, "rotation unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// rotationRefreshLoop drives time-based auto-refresh: it wakes every
// rotationRefreshCheck and rotates once the current alias reaches NextRefreshAt
// (user-locked at weekly). A never-rotated account (s.rotation == nil) has no
// NextRefreshAt and is left untouched — the weekly cadence begins only after the
// first rotation establishes it, so this loop never spontaneously rotates an
// account that has not opted in by rotating once. Mirrors the other session loops;
// stops with the session context.
func (s *Server) rotationRefreshLoop(ctx context.Context, id *identity.Identity) {
	t := time.NewTicker(rotationRefreshCheck)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Sweep expired aliases first (tear down what's past grace), then
			// consider minting a fresh one — the same hourly rotation-maintenance
			// wake serves both, and grace is measured in days so hourly is ample.
			s.sweepExpiredAliases()
			s.maybeAutoRotate(id)
		}
	}
}

// sweepExpiredAliases retires every history alias past its grace deadline: it
// evicts the alias's resident signing key, forgets its service id, drops the
// history record, and gives up any pending rotation the retirement orphaned —
// then tears the onion services down OUTSIDE sessMu (a teardown must never block
// inbound message handling on the lock). Runs on the hourly refresh loop.
func (s *Server) sweepExpiredAliases() {
	s.sessMu.Lock()
	stop, changed := s.sweepExpiredAliasesLocked(time.Now())
	if changed {
		s.persistLocked()
	}
	s.sessMu.Unlock()
	if len(stop) == 0 {
		return
	}
	host, ok := s.asExtraOnionHost()
	if !ok {
		return
	}
	for _, id := range stop {
		host.StopExtraService(id)
	}
}

// sweepExpiredAliasesLocked mutates the rotation state to drop aliases past their
// RetireAt and returns (a) the extra-service ids the caller must StopExtraService
// off-lock and (b) whether anything changed (so the caller persists). Caller
// holds sessMu.
//
// It replaces s.rotation with a fresh struct rather than mutating History in
// place: snapshotLocked hands the live *RotationState pointer straight to the
// persister, so an in-place slice edit could race a concurrent marshal.
func (s *Server) sweepExpiredAliasesLocked(now time.Time) ([]uint64, bool) {
	if s.rotation == nil || len(s.rotation.History) == 0 {
		return nil, false
	}
	kept := make([]chatstore.AliasRecord, 0, len(s.rotation.History))
	swept := map[string]bool{}
	var stop []uint64
	for _, h := range s.rotation.History {
		if now.Before(h.RetireAt) {
			kept = append(kept, h)
			continue
		}
		if id, ok := s.aliasServiceIDs[h.Account]; ok {
			stop = append(stop, id)
			delete(s.aliasServiceIDs, h.Account)
		}
		delete(s.aliasSigningKeys, h.Account)
		swept[h.Account] = true
	}
	if len(swept) == 0 {
		return nil, false
	}
	s.rotation = &chatstore.RotationState{
		CurrentIndex:   s.rotation.CurrentIndex,
		CurrentAccount: s.rotation.CurrentAccount,
		NextRefreshAt:  s.rotation.NextRefreshAt,
		History:        kept,
	}
	s.refreshLiveAliasesLocked()
	// Give up pending rotations the sweep orphaned: a contact whose MyAccountKnown
	// alias we just retired can no longer be reached at all — outboundIdentity
	// fails loud once that alias's signing key is evicted (it never falls back to
	// primary) — so retrying forever would only spin. Gate strictly on the set we
	// actually retired this pass, never on aliasSigningKeys membership: a live
	// alias whose republish failed is absent from that map yet still perfectly
	// reachable, and giving its contacts up would be wrong. peerAliases is left
	// alone — it tracks a PEER's own grace (no RetireAt of ours to key off).
	for to := range s.pendingRotations {
		c, ok := s.contacts[to]
		if !ok {
			delete(s.pendingRotations, to)
			continue
		}
		if c.MyAccountKnown != "" && swept[c.MyAccountKnown] {
			delete(s.pendingRotations, to)
		}
	}
	return stop, true
}

// maybeAutoRotate rotates iff the current alias has come due. It ACQUIRES sessMu
// itself (no -Locked suffix, unlike performRotationLocked): the check-and-rotate is
// one critical section so NextRefreshAt can't be read against a concurrently mutated
// rotation state.
func (s *Server) maybeAutoRotate(id *identity.Identity) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if s.rotation == nil || time.Now().Before(s.rotation.NextRefreshAt) {
		return
	}
	if _, err := s.performRotationLocked(id); err != nil {
		log.Printf("auto-rotate: %v", err)
	}
}

// sendRotationV2 pushes one pending AddressRotation to `to` over the established
// ratchet session, announcing our newOnion. It rides the session the contact
// already holds — outboundIdentity stamps the (OLD) alias they currently know us
// by, so the message lands on that session and their receive gate accepts it.
// Returns an error so the retry tick can try again; the entry is cleared only on
// ack.
func (s *Server) sendRotationV2(ctx context.Context, idn *identity.Identity, to, newOnion string, aliasIndex uint32) error {
	pt := protocol.EncodeRotationPayload(protocol.AddressRotation{NewOnion: newOnion, AliasIndex: aliasIndex})
	return s.sendSealedOverSessionV2(ctx, s.onion.Dialer(), idn, to, pt)
}

// rotationRetryLoop resends every pending rotation over its contact's session
// until acked. Mirrors acceptRetryLoop's shape but deliberately has NO give-up
// TTL: abandoning a rotation would leave the contact dialing an alias we are
// retiring (see rotationRetryStartDelay). Entries leave pendingRotations only via
// the ack handler, a superseding rotation, or the grace sweeper.
func (s *Server) rotationRetryLoop(ctx context.Context, id *identity.Identity) {
	t := time.NewTimer(rotationRetryStartDelay)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.rotationRetryTick(ctx, id)
			t.Reset(rotationRetryInterval)
		}
	}
}

// rotationRetryTick attempts one delivery of each pending rotation. It carries
// the live MAP KEY as the destination, never an account captured in the value:
// migratePeerAccountLocked re-keys pendingRotations when a contact rotates, so
// the key is always the contact's current address, while a copied value has no
// address field to rewrite. Best-effort — an entry is never removed here (only by
// ack / supersede / sweep); a contact who is simply offline is retried next tick.
func (s *Server) rotationRetryTick(ctx context.Context, id *identity.Identity) {
	if s.onion == nil {
		return
	}
	type due struct {
		to         string
		newOnion   string
		aliasIndex uint32
	}
	s.sessMu.Lock()
	pending := make([]due, 0, len(s.pendingRotations))
	for to, pr := range s.pendingRotations {
		pending = append(pending, due{to: to, newOnion: pr.NewOnion, aliasIndex: pr.AliasIndex})
	}
	s.sessMu.Unlock()

	for _, d := range pending {
		select {
		case <-ctx.Done():
			return
		default:
		}
		cctx, cancel := deliveryContext(rotationSendTimeout)
		err := s.sendRotationV2(cctx, id, d.to, d.newOnion, d.aliasIndex)
		cancel()
		if err != nil {
			// No session yet / offline / wire error — retry next tick. Not logged per
			// attempt: a contact being offline is the normal case, not an error.
			continue
		}
	}
}

// advertisedAccountLocked is the account we currently hand out and answer as: the
// rotation alias once we have rotated at least once, else the primary m/0'/0'
// onion. This is the seam that hides the permanent address — the friend code and
// its QR carry THIS, not id.AccountNumber(), so a redeemer only ever learns a
// rotating alias. It differs from the primary only after the first rotation, so a
// never-rotated account still shares its primary onion (nothing to hide yet).
// Caller holds sessMu.
func (s *Server) advertisedAccountLocked(id *identity.Identity) string {
	if s.rotation != nil {
		return s.rotation.CurrentAccount
	}
	return id.AccountNumber()
}

// onionAccountFromHost extracts the bare account (56-char base32 label) an inbound
// P2P request was dialed at, from its Host header: strip an optional :port, strip
// the ".onion" suffix, lowercase. An honest onionClient always sends the dialed
// account as Host (client.go dials "<account>.onion:80"). Host is client-controlled,
// so responderForRequest constrains the result to our live set before trusting it.
func onionAccountFromHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(host, ".onion"))
}

// signingKeyForAccountLocked returns the Ed25519 private key that signs responses
// AS `acct`: the primary key for our primary account, else the resident alias key.
// It FAILS LOUD for a live alias whose signing key is not resident — never falling
// back to the primary key, which would re-leak the permanent address on an alias a
// caller dialed. Caller holds sessMu.
func (s *Server) signingKeyForAccountLocked(idn *identity.Identity, acct string) (ed25519.PrivateKey, error) {
	if acct == idn.AccountNumber() {
		return idn.Keys.Signing.Private, nil
	}
	kp, ok := s.aliasSigningKeys[acct]
	if !ok {
		return nil, fmt.Errorf("no resident signing key for account %s", acct)
	}
	return kp.Private, nil
}

// responderForRequest resolves which account an inbound ungated P2P request (a
// challenge or a public profile card) must be answered AS, plus that account's
// signing key. The client derives our verifying key from the account IT dialed, so
// a response signed as anything else fails verification — during a rotation grace
// window a request arriving on an alias-of-us MUST answer as that alias, or it both
// breaks the un-updated contact and leaks our primary account string.
//
// The dialed account comes from the Host header, constrained to our live set:
//   - primary (checked explicitly — post-rotation the primary onion stays live as
//     unadvertised infrastructure, and pre-rotation contacts still dial it), or
//   - a currently-published alias (localAliasAccounts).
//
// Anything else — an empty, garbage, or stale Host — resolves to the account we
// currently advertise (advertisedAccountLocked), never the primary post-rotation,
// so a malformed Host can never coax the permanent address back out. A live alias
// whose signing key is not resident fails loud (see signingKeyForAccountLocked);
// the handler then emits its generic reject rather than answering as the primary.
// Takes sessMu.
func (s *Server) responderForRequest(idn *identity.Identity, r *http.Request) (string, ed25519.PrivateKey, error) {
	dialed := onionAccountFromHost(r.Host)
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	acct := dialed
	if acct != idn.AccountNumber() && !slices.Contains(s.localAliasAccounts, acct) {
		acct = s.advertisedAccountLocked(idn)
	}
	priv, err := s.signingKeyForAccountLocked(idn, acct)
	if err != nil {
		return "", nil, err
	}
	return acct, priv, nil
}

// aliasAccountForIndexLocked maps one of OUR alias indexes to its account (onion
// label) from the live rotation state (current + non-pruned history). ok is false
// for an index we no longer hold (never rotated to it, or pruned past its grace
// window). Caller holds sessMu.
func (s *Server) aliasAccountForIndexLocked(index uint32) (string, bool) {
	if s.rotation == nil {
		return "", false
	}
	if s.rotation.CurrentIndex == index {
		return s.rotation.CurrentAccount, true
	}
	for _, h := range s.rotation.History {
		if h.Index == index {
			return h.Account, true
		}
	}
	return "", false
}

// aliasIndexForAccountLocked is the inverse of aliasAccountForIndexLocked: it maps
// one of OUR live alias accounts (current + non-pruned history) back to its index.
// ok is false for an account we do not currently hold as an alias (the primary, or
// one pruned past grace) — callers must gate on ok, never on the index, because
// index 0 is a real alias (Contact.MyAccountKnown == "" is the primary sentinel,
// not a zero index). Caller holds sessMu.
func (s *Server) aliasIndexForAccountLocked(account string) (uint32, bool) {
	if s.rotation == nil {
		return 0, false
	}
	if s.rotation.CurrentAccount == account {
		return s.rotation.CurrentIndex, true
	}
	for _, h := range s.rotation.History {
		if h.Account == account {
			return h.Index, true
		}
	}
	return 0, false
}

// advertisedOutboundIdentityLocked resolves the account + signing key we present
// when we INITIATE a brand-new relationship (an outbound friend request): the
// currently advertised account (the alias if rotated, else the primary) and the
// key that account is an Ed25519 public key OF, so the request's From and its
// signature agree and never leak the primary once a rotation is live. isAlias
// reports whether the advertised account is a rotation alias (index valid) rather
// than the primary — the caller records MyAccountKnown only when it is. Caller
// holds sessMu.
func (s *Server) advertisedOutboundIdentityLocked(idn *identity.Identity) (account string, signPriv ed25519.PrivateKey, aliasIndex uint32, isAlias bool, err error) {
	account = s.advertisedAccountLocked(idn)
	signPriv, err = s.signingKeyForAccountLocked(idn, account)
	if err != nil {
		return "", nil, 0, false, err
	}
	if account == idn.AccountNumber() {
		return account, signPriv, 0, false, nil
	}
	idx, ok := s.aliasIndexForAccountLocked(account)
	if !ok {
		// Advertised account is neither the primary nor a known live alias — refuse
		// rather than stamp an unresolvable identity onto a new contact.
		return "", nil, 0, false, fmt.Errorf("advertised account %s is not a known live alias", account)
	}
	return account, signPriv, idx, true, nil
}

// hookOnAddressRotationAck records that `contactAccount` (the identity the ratchet
// channel authenticated) has applied our rotation to alias `ackedIndex`
// (protocol.Hooks.OnAddressRotationAck). It clears the contact's pending rotation
// once they have caught up to at least the index we are delivering (ackedIndex >=
// the pending index — NOT ==, so an ack for a newer, superseding rotation also
// settles an older still-pending one), and advances MyAccountKnown /
// MyAliasIndexKnown to the alias they now know us by, strictly forward so a late
// or duplicate ack never walks it back.
func (s *Server) hookOnAddressRotationAck(contactAccount string, ackedIndex uint32) error {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	contactAccount = s.resolvePeerAccountLocked(contactAccount)
	c, ok := s.contacts[contactAccount]
	if !ok || c.Status != chatstore.StatusAccepted {
		return fmt.Errorf("rotation ack from a non-accepted contact")
	}
	changed := false
	if pr, ok := s.pendingRotations[contactAccount]; ok && ackedIndex >= pr.AliasIndex {
		delete(s.pendingRotations, contactAccount)
		changed = true
	}
	// Advance the account this contact knows us by. MyAccountKnown == "" is the
	// "no alias acked yet" sentinel (index 0 is itself a real alias, so the empty
	// string — not a zero index — is what distinguishes the primary default).
	if c.MyAccountKnown == "" || ackedIndex > c.MyAliasIndexKnown {
		if acct, ok := s.aliasAccountForIndexLocked(ackedIndex); ok {
			c.MyAccountKnown = acct
			c.MyAliasIndexKnown = ackedIndex
			c.UpdatedAt = time.Now()
			s.contacts[contactAccount] = c
			changed = true
		}
	}
	if changed {
		s.persistLocked()
	}
	return nil
}

// aliasToPublish is a rotation alias whose onion key has been derived synchronously
// (while the identity is live) and is ready to publish once the Tor client is up.
type aliasToPublish struct {
	index   uint32
	account string
	key     tor.OnionKey
}

// zeroPreparedAliases scrubs the secret onion-key material of a prepared set. It
// is idempotent (double-zeroing is harmless), so a caller can defer it to cover
// early-return paths that never reach publishPreparedAliases (which zeroes too).
func zeroPreparedAliases(prepared []aliasToPublish) {
	for i := range prepared {
		prepared[i].key.Zeroize()
	}
}

// prepareLiveAliasesLocked derives the onion keys for the whole live alias set
// (current + every history alias still within its grace window) so they can be
// republished after a restart. It reads zeroable key material, so it MUST run
// synchronously while the identity is live (the finishUnlock caller derives it
// before handing back the session token, like onionKeyFor). Returns nil when
// rotation has not started. The returned keys carry secret material; the publisher
// zeroes each once used. Caller holds sessMu.
func (s *Server) prepareLiveAliasesLocked(idn *identity.Identity) ([]aliasToPublish, error) {
	if s.rotation == nil {
		return nil, nil
	}
	now := time.Now()
	type want struct {
		index   uint32
		account string
	}
	wants := []want{{s.rotation.CurrentIndex, s.rotation.CurrentAccount}}
	for _, h := range s.rotation.History {
		if now.Before(h.RetireAt) {
			wants = append(wants, want{h.Index, h.Account})
		}
	}
	out := make([]aliasToPublish, 0, len(wants))
	for _, w := range wants {
		key, err := s.deriveAliasOnionKey(idn, w.index)
		if err != nil {
			for i := range out {
				out[i].key.Zeroize()
			}
			return nil, err
		}
		// Keep the signing key resident too (the onion key above is a separate,
		// zeroed-after-publish derivation): the send path signs messages to any
		// contact whose MyAccountKnown is this alias with it. Rebuilds the cache to
		// mirror the live set after a restart, exactly as the onion services are
		// republished. Zeroed in clearSession.
		if err := s.cacheAliasSigningKeyLocked(idn, w.index, w.account); err != nil {
			for i := range out {
				out[i].key.Zeroize()
			}
			return nil, err
		}
		out = append(out, aliasToPublish{index: w.index, account: w.account, key: key})
	}
	return out, nil
}

// publishPreparedAliases restarts the extra onion services for a pre-derived live
// alias set now that the Tor client is up (extra-service ids do not survive a
// restart, and an un-updated contact's next message must still reach a live alias).
// It records each runtime service id and refreshes the recipient-identity set. Safe
// on a background goroutine — it touches no zeroable key material (keys were derived
// synchronously by prepareLiveAliasesLocked). It always zeroes every prepared key,
// even on early return. Skips any alias already published; a host without
// concurrent-service support leaves rotation simply unavailable until rebuilt.
func (s *Server) publishPreparedAliases(prepared []aliasToPublish) {
	defer zeroPreparedAliases(prepared)
	if len(prepared) == 0 {
		return
	}
	host, ok := s.asExtraOnionHost()
	if !ok {
		return
	}
	for _, a := range prepared {
		s.sessMu.Lock()
		_, live := s.aliasServiceIDs[a.account]
		s.sessMu.Unlock()
		if live {
			continue
		}
		onion, id, err := host.StartExtraService(a.key, s.publicAddr(), fmt.Sprintf("alias-%d", a.index))
		if err != nil {
			log.Printf("rotation: republish alias %d failed: %v", a.index, err)
			continue
		}
		if onion != a.account {
			// Onion is deterministic from the index, so a mismatch is a derivation
			// bug; refuse to publish under an address the rotation state doesn't know.
			log.Printf("rotation: republished alias %d onion mismatch (got %s, want %s); stopping", a.index, onion, a.account)
			host.StopExtraService(id)
			continue
		}
		s.sessMu.Lock()
		if s.aliasServiceIDs == nil {
			s.aliasServiceIDs = map[string]uint64{}
		}
		s.aliasServiceIDs[onion] = id
		s.sessMu.Unlock()
	}
	s.sessMu.Lock()
	s.refreshLiveAliasesLocked()
	s.sessMu.Unlock()
}

// applyAddressRotationLocked is the locked core of hookOnAddressRotation. The
// ratchet receive path reaches it through the locking wrapper above; the mailbox
// loop, which already holds sessMu, calls it directly. Caller holds sessMu.
func (s *Server) applyAddressRotationLocked(contactAccount, newOnion string, aliasIndex uint32) error {
	// A resend of an already-applied rotation still arrives addressed from the old
	// alias; resolve it to the contact we migrated to so the idempotency check below
	// can recognise it (and so a genuine new rotation from a contact who has rotated
	// before is keyed by their current account, not a stale one).
	contactAccount = s.resolvePeerAccountLocked(contactAccount)
	c, ok := s.contacts[contactAccount]
	if !ok || c.Status != chatstore.StatusAccepted {
		return fmt.Errorf("rotation from a non-accepted contact")
	}
	// Idempotent duplicate: the exact rotation we already applied (same target
	// onion AND same index). Delivery is ack-driven resend-until-acked, so a
	// resend of an already-applied rotation MUST succeed (return nil) so the peer
	// gets its ack and stops resending — the same idempotency processedInits gives
	// the X3DH path. This check comes first so an ack-lost resend never trips the
	// monotonic guard below.
	if aliasIndex == c.AliasIndex && newOnion == c.Account {
		return nil
	}
	// Monotonic guard: a genuinely new rotation must strictly exceed the highest
	// index we've accepted. Anything else — a strictly lower index, or the same
	// index pointing at a DIFFERENT onion — is a stale replay or a conflict and is
	// rejected, so a captured old announcement can't walk us back to a dead onion.
	if aliasIndex <= c.AliasIndex {
		return fmt.Errorf("rotation index %d not newer than %d", aliasIndex, c.AliasIndex)
	}
	// The target must be a free slot: if newOnion already names ANY contact record
	// (accepted, pending or otherwise), refuse rather than migrate — the migration
	// is collision-safe about not clobbering, but merging a rotating contact onto an
	// existing one, or dropping its session to a squatting record, is never right.
	// A fresh alias never collides in practice; a collision is pathological.
	if newOnion != contactAccount {
		if _, exists := s.contacts[newOnion]; exists {
			return fmt.Errorf("rotation target already names another contact")
		}
	}

	s.migratePeerAccountLocked(contactAccount, newOnion)

	// Advance the index and stamp the update on the (possibly re-keyed) contact.
	moved := s.contacts[newOnion]
	moved.Account = newOnion
	moved.AliasIndex = aliasIndex
	moved.UpdatedAt = time.Now()
	s.contacts[newOnion] = moved

	// Remember the account we just migrated away from as a retired alias of the new
	// one, so an ack-lost resend from the old alias still resolves to this contact.
	s.recordPeerAliasLocked(contactAccount, newOnion)

	s.persistLocked()
	return nil
}

// migratePeerAccountLocked atomically re-keys every per-peer structure from a
// contact's old account (onion) to its new one when that contact rotates its
// address. It is the receive-side counterpart of a peer's AddressRotation: the
// contact's durable identity (DHPub) is unchanged, only the transport account
// moves, so every account-keyed entry must follow.
//
// EXHAUSTIVE against the server's account-keyed state (server.go:163–236):
// contacts, messages(.Peer), reads, pendingAccepts(+.Account), outbox(.To),
// ratchetSessions, pendingInits, processedInits, pendingRotations, presence,
// mailboxCheckedAt. Group structures are deliberately NOT touched — groups are
// excluded from rotation in v1 (a rotating member is re-added; the signed roster
// epoch is an admin's to bump), so groups, groupReactCursor, groupInvites and
// sentGroupInvites keep their existing keys.
//
// Idempotent and collision-safe: an entry moves to `new` only when `new` has no
// entry of its own; on a collision BOTH keys are left in place (old is NOT
// dropped) so a peer's session/reads/etc. are never silently destroyed, and a
// re-applied migration (old already gone) is a no-op. `.Peer`/`.To` field
// rewrites always run (they carry no key collision). The rotation hook refuses
// any target collision upstream, so `new` is free in the normal path.
// It does NOT persist — the caller persists once after any accompanying updates
// (e.g. advancing Contact.AliasIndex). Caller holds sessMu. Returns whether
// anything moved. No-op when old==new or either is empty.
func (s *Server) migratePeerAccountLocked(old, new string) bool {
	if old == "" || new == "" || old == new {
		return false
	}
	moved := false

	// contacts: move the record and rewrite its embedded Account. On collision,
	// leave old in place rather than dropping it into a squatting record.
	if c, ok := s.contacts[old]; ok {
		if _, exists := s.contacts[new]; !exists {
			c.Account = new
			s.contacts[new] = c
			delete(s.contacts, old)
			moved = true
		}
	}
	// messages is a slice keyed by the Peer field, not a map.
	for i := range s.messages {
		if s.messages[i].Peer == old {
			s.messages[i].Peer = new
			moved = true
		}
	}
	// outbox is keyed by message id; the peer lives in the To field.
	for id, it := range s.outbox {
		if it.To == old {
			it.To = new
			s.outbox[id] = it
			moved = true
		}
	}
	// pendingAccepts: move the record and rewrite its embedded Account. On
	// collision, leave old in place rather than dropping it.
	if p, ok := s.pendingAccepts[old]; ok {
		if _, exists := s.pendingAccepts[new]; !exists {
			p.Account = new
			s.pendingAccepts[new] = p
			delete(s.pendingAccepts, old)
			moved = true
		}
	}
	// Plain account->value maps: move the key, keep the value, never clobber new.
	moved = migrateMapKey(s.reads, old, new) || moved
	moved = migrateMapKey(s.ratchetSessions, old, new) || moved
	moved = migrateMapKey(s.pendingInits, old, new) || moved
	moved = migrateMapKey(s.processedInits, old, new) || moved
	moved = migrateMapKey(s.pendingRotations, old, new) || moved
	moved = migrateMapKey(s.presence, old, new) || moved
	moved = migrateMapKey(s.mailboxCheckedAt, old, new) || moved
	moved = migrateMapKey(s.helloAt, old, new) || moved
	moved = migrateMapKey(s.probeBackoff, old, new) || moved

	return moved
}

// migrateMapKey moves m[old] to m[new] and reports whether it moved. It moves
// only when new is FREE: if new is already occupied it leaves BOTH entries in
// place (returns false) rather than clobbering new or dropping old — a collision
// must never silently destroy a peer's session/reads/etc. A generic helper so
// migratePeerAccount stays exhaustive without repeating the move per map type.
// (The rotation hook refuses any target collision upstream, so in practice new is
// always free; this is the belt-and-suspenders for every caller.)
func migrateMapKey[V any](m map[string]V, old, new string) bool {
	v, ok := m[old]
	if !ok {
		return false
	}
	if _, exists := m[new]; exists {
		return false // collision: preserve old, never clobber new or drop state
	}
	m[new] = v
	delete(m, old)
	return true
}

func (s *Server) lookupContactByDHPubLocked(dh []byte) (account string, ok bool) {
	if len(dh) != 32 {
		return "", false
	}
	found := false
	for acct, c := range s.contacts {
		if c.Status != chatstore.StatusAccepted || len(c.DHPub) != 32 {
			continue
		}
		if bytes.Equal(c.DHPub, dh) {
			if found {
				return "", false // ambiguous: two contacts share a DHPub — fail closed
			}
			account, found = acct, true
		}
	}
	return account, found
}
