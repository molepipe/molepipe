// Package api is the localhost HTTP layer between the UI and the backend. It
// has an explicit start/stop lifecycle (not tied to a desktop process) so the
// same server can later be started/stopped by Android gomobile hooks, and it
// serves the embedded UI over loopback — the identical pattern that works
// inside an Android WebView.
package api

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/device"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/mailbox"
	"github.com/molepipe/molepipe/backend/internal/pin"
	"github.com/molepipe/molepipe/backend/internal/protocol"
	"github.com/molepipe/molepipe/backend/internal/tor"
	"github.com/molepipe/molepipe/backend/internal/unlockguard"
	"github.com/molepipe/molepipe/backend/internal/version"
)

//go:embed public
var publicFS embed.FS

// loopbackHosts are the hostnames we accept in the Host header. Anything else
// (e.g. a DNS-rebinding attacker's domain) is rejected. Ports are ignored.
var loopbackHosts = map[string]bool{
	"127.0.0.1": true,
	"localhost": true,
	"::1":       true,
}

// Server is the local HTTP server. Create with New, run with Start, stop with
// Shutdown. It binds to loopback only.
type Server struct {
	store   *identity.Store
	vault   *vault
	httpSrv *http.Server
	ln      net.Listener
	port    string

	// controlToken is a per-process capability secret that gates the /api
	// surface on the loopback CONTROL listener. On desktop, loopback is a
	// single-user boundary; on Android it is NOT — every co-installed app shares
	// 127.0.0.1 and can forge Host/Origin like a native client, so the host
	// allowlist and origin guard (which only bind a browser) do not separate
	// apps. Only a secret the other app cannot read does. The first-party UI
	// receives this token out-of-band (in its bootstrap URL, delivered in-process
	// to the WebView / opened browser) and echoes it on every /api call; another
	// app on the device never sees it. Static assets stay tokenless so the page
	// can load — they carry nothing sensitive (they ship in the APK).
	controlToken string

	// exchangeToken is a single-use bootstrap secret for the cmd/server entry
	// point, which opens the UI in the user's DEFAULT BROWSER — where a token in
	// the launch URL lands in history, the address-bar autocomplete DB, and any
	// extension watching navigations. So that URL carries this throwaway instead
	// of the durable controlToken: the UI trades it once (POST /control-token) for
	// the real token, then it is spent, so the history entry is inert. The
	// embedded-webview entry points (Wails, Android) keep using URLWithToken —
	// their URL is never exposed to a browser, and a single-use token would break
	// their reload/recreate paths. Guarded by exchangeMu; spent flips true on use.
	exchangeToken string
	exchangeSpent bool
	exchangeMu    sync.Mutex

	// pub* is the public, onion-facing listener. It is SEPARATE from the
	// loopback control server above: the control server hosts the private unlock
	// UI/API for the local browser only, while the onion forwards here. Nothing
	// sensitive is exposed on this listener.
	pubSrv  *http.Server
	pubLn   net.Listener
	pubPort string

	onion     tor.OnionService // may be nil (Tor disabled)
	onionMu   sync.Mutex
	onionAddr string

	// runningVersionCode is the build number the update check compares against
	// the signed manifest. -1 means "not injected": on desktop the handler then
	// falls back to version.Code() (the ldflags stamp is authoritative there); on
	// Android it must be set via SetRunningVersionCode from PackageInfo at
	// startup, and until it is the check refuses to compare (fail closed) rather
	// than trust a possibly-stale stamp. Atomic, not comment-guarded "set once":
	// the setter is exported and the reader runs on an HTTP goroutine, so the two
	// genuinely cross goroutines once the Android layer wires the setter.
	runningVersionCode atomic.Int64

	// Lock-grace: after a normal Log out, keep the onion running for graceWindow
	// so a quick re-unlock reuses the still-published service instead of paying a
	// ~9s re-publish. An account with erase-after-failed-unlocks enabled (a
	// higher-threat posture) skips the grace and tears down immediately, and a
	// wipe (duress / forget) always cancels a pending grace. graceGen invalidates
	// an already-fired-but-waiting timer callback that a cancel raced.
	graceMu    sync.Mutex
	graceTimer *time.Timer
	graceGen   uint64

	// onInbound, if set, is called asynchronously with the sender's display
	// name, the message text and its time whenever a NEW inbound message is
	// delivered — direct, mailbox or relay alike. The Android shell uses it to
	// post a system notification while the window is closed; desktop leaves it
	// nil and the web UI raises its own notifications. Set once at construction
	// (before any delivery can run), so it needs no lock.
	onInbound func(fromName, preview string, atMillis int64, avatarHash string)

	// onFriendRequest, if set, is called asynchronously when a new inbound
	// friend request arrives. The Android shell uses it to post a system
	// notification. Set once at construction, needs no lock.
	onFriendRequest func(fromName string)

	// onGroupInvite, if set, is called asynchronously when a new inbound group
	// invite arrives. The Android shell uses it to post a system notification.
	// Set once at construction, needs no lock.
	onGroupInvite func(inviterName, groupName string)

	// desktop is the desktop shell (window + tray + start-at-login), registered
	// by cmd/desktop. Nil for cmd/server and every test: the settings it backs
	// then report themselves unavailable rather than half-working. Guarded by
	// sessMu, along with the one-time notice it posts.
	desktop Desktop
	notice  string
	// devMu guards the three per-device pointers below. A wipe (forget / duress /
	// failed-attempts erase) swaps all three via reloadDeviceState, concurrently
	// with request handlers that read them — handleUnlock in particular, the one
	// field-reading endpoint still reachable after vault.lock() invalidates the
	// session token. Read them only through currentDevice/currentPin/currentGuard.
	// It is NOT sessMu: reloadDeviceState is reached via haltForWipe→clearSession,
	// which already holds sessMu, so sharing it would deadlock.
	devMu  sync.RWMutex
	device *device.Config     // local per-device state (role + device key)
	pin    *pin.Store         // device-bound PIN unlock shortcut (nil = unavailable)
	guard  *unlockguard.Store // password-unlock backoff + optional erase-after-N (nil = unavailable)
	relay     *mailbox.Store     // blobs we hold-and-forward for friends (friend-relay)
	relayQuota *relaySenderQuota // per-sender relay drop-off quota (abuse prevention)

	// Messaging session state, live only while unlocked.
	sessMu       sync.Mutex
	sessID       *identity.Identity           // the unlocked identity, for signing group rosters off the request path
	myAccount    string                       // our own account number (for the sync gate)
	displayName  string                       // our own display name
	mailboxURL   string                       // our own mailbox address (disclosed to accepted contacts, not in the public card)
	avatarHash   string                       // sha256 hex of our own avatar image, "" = none (advertised in the public card)
	profileAt    time.Time                    // profile last-updated time (for sync LWW)
	backupBudget int64                        // byte budget for group-image backup to our own mailbox (0 = off)
	contacts     map[string]chatstore.Contact // account number -> contact (with status)
	messages     []chatMessage
	groups       map[string]chatstore.Group // group id -> group (roster + policy); group chat
	// groupReactCursor rotates the starting offset of the reaction re-serve window
	// per group across successive sync pulls, so a group with more than
	// groupSyncMaxReactions reaction events in its window doesn't re-serve the same
	// first slice forever (which would leave older messages' reactions un-gossiped).
	// Lazy-initialized in handleP2PGroupSync; never read while locked out.
	groupReactCursor map[string]int
	// groupInvites are invitations we've received, keyed by group id; once
	// accepted, one arms the bootstrap consent anchor + drives the accept-retry.
	// sentGroupInvites are invites we've issued, keyed by "group|account", so we
	// only ever commit an accept that matches one we sent.
	groupInvites     map[string]chatstore.GroupInvite
	sentGroupInvites map[string]chatstore.SentGroupInvite
	reads            map[string]time.Time // account -> last-read time (unread tracking)
	devices          []chatstore.Device   // enrolled devices authorized to sync
	// pendingAccepts are friend-accepts we owe a requester whose push hasn't
	// landed yet, keyed by their account. Retried by acceptRetryLoop.
	pendingAccepts map[string]chatstore.PendingAccept
	// deleted are tombstones for messages removed by "delete for everyone".
	deleted []string
	// outbox holds messages accepted but not yet delivered, keyed by message ID.
	// Drained by outboxLoop.
	outbox      map[string]chatstore.OutboxItem
	peer        *protocol.Peer
	chat        *chatstore.Store           // encrypted persistence, nil while locked
	attach      *chatstore.AttachmentStore // encrypted image blobs, nil while locked
	avatarStore *chatstore.AvatarStore     // encrypted avatar blobs (own + cached contacts), nil while locked
	// avatarBytesOwn is our own avatar image held in memory so snapshotLocked can
	// place it on the synced Profile (for our other devices) without a disk-decrypt
	// on every persist. It mirrors the bytes in avatarStore under s.avatarHash.
	avatarBytesOwn []byte
	// avatarLimiter globally rate-limits the ungated AvatarPath. Over Tor an
	// ungated GET carries no per-caller identity, so the bucket bounds aggregate
	// bandwidth, not per-peer fairness. Process-lifetime (not per-session).
	avatarLimiter *tokenBucket

	presence map[string]string // account -> last-known presence state (online/mailbox/offline)
	// mailboxCheckedAt is session-local (NOT synced/persisted): the last time we
	// pulled a contact's mailbox from their gated contact-profile endpoint. Bounds
	// how often the presence sweep re-fetches it, since the mailbox rarely changes
	// and each fetch is an extra Tor round-trip.
	mailboxCheckedAt map[string]time.Time
	sessionCancel    context.CancelFunc // stops the background presence + mailbox loops on lock
	syncNonces       *syncNonceJar      // single-use nonces for the /sync + /pair gates
	pairSecrets      *syncNonceJar      // short-lived single-use device-pairing secrets
	// attachNeed carries, across attachment-sync ticks, the image ids the primary
	// last told this (secondary) device it is missing, so the next tick pushes
	// their blobs. Written only by the sync loop goroutine but read/reset under
	// sessMu on lock. Empty on a primary (it runs no sync loop).
	attachNeed []string
	// backupRestoreRunning guards the group-image backup restore so only one runs at
	// a time (the auto-restore in mailboxTick and a manual /group/images/restore must
	// not overlap and double-fetch). Guarded by sessMu.
	backupRestoreRunning bool
	// lastBackupRestore throttles the auto-restore's mailbox List. Under on-demand
	// full fetch, most group-image rows have no local blob (the user never tapped
	// them), so the missing-set is almost never empty and can't gate the List by
	// itself. We List at most once per backupRestoreEvery on the auto path; a manual
	// restore (force) bypasses this. Guarded by sessMu.
	lastBackupRestore time.Time

	// ready signals when finishUnlock's background work (the Tor bring-up in
	// startOnion) has completed. Tests wait on this to avoid racing with the
	// async startup.
	ready sync.WaitGroup

	// publishWatchdogCancel cancels the stuck-publishing watchdog launched by
	// finishUnlock. Nil when no watchdog is running (locked, or Tor disabled).
	publishWatchdogCancel context.CancelFunc
	publishWatchdogMu     sync.Mutex
}

// New creates a server backed by the given identity store. onion is the Tor
// integration (an Arti sidecar on desktop); pass nil to run without Tor.
func New(store *identity.Store, onion tor.OnionService) *Server {
	dev, err := device.Load(store.Dir)
	if err != nil {
		log.Printf("device config: %v (defaulting to primary in memory)", err)
		dev = &device.Config{Role: device.RolePrimary}
	}
	// Friend-relay hold-and-forward store: opaque E2E blobs we carry for friends,
	// keyed by their recipient. Open drop-off (recipients never check in with us);
	// access is gated by the relay handler. Caps protect our own resources.
	relay, err := mailbox.New(mailbox.Config{
		Dir:         filepath.Join(store.Dir, "relay"),
		OpenDropOff: true,
		Defaults:    mailbox.Caps{MaxMessages: 100, MaxBytes: 5 << 20, MaxMessage: 32 << 10, BlobTTL: 3 * 24 * time.Hour},
		// An approved relay sender chooses the recipient, so per-account caps alone
		// let it fill the disk by inventing endless recipients. Cap the tenancy
		// count so total relay storage is bounded (64 × 5 MiB ≈ 320 MiB).
		GlobalMaxTenants: 64,
	})
	if err != nil {
		log.Printf("relay store: %v (friend-relay disabled)", err)
	}
	// PIN unlock is bound to the device's local secret. If the device config
	// couldn't be loaded above we fell back to an in-memory one with no seed —
	// binding to that would be binding to a constant, so the shortcut is simply
	// unavailable and unlock stays password-only.
	var pinStore *pin.Store
	var guard *unlockguard.Store
	if len(dev.Seed) > 0 {
		pinStore = pin.New(store.Dir, dev.LocalSecret())
		// The password-unlock guard binds its counter to the same device secret.
		// Without one, unlock stays exactly as before: no backoff, no erase policy.
		guard = unlockguard.New(store.Dir, dev.LocalSecret())
	} else {
		log.Printf("no device key; pin unlock and unlock guard unavailable")
	}
	// A fresh capability secret per process. crypto/rand can't realistically
	// fail here; if it ever did, an empty token would leave /api open, so fall
	// back to refusing every /api request (controlGuard rejects an empty token).
	ctok, err := newToken()
	if err != nil {
		log.Printf("control token: %v (the /api surface will refuse all requests until restart)", err)
	}
	srv := &Server{store: store, vault: newVault(), onion: onion, device: dev, pin: pinStore, guard: guard, relay: relay, relayQuota: newRelaySenderQuota(), syncNonces: newSyncNonceJar(), pairSecrets: newSyncNonceJar(), controlToken: ctok, avatarLimiter: newTokenBucket(avatarServeRate, avatarServeBurst)}
	srv.runningVersionCode.Store(-1) // "not injected"; the handler falls back to version.Code() on desktop, fails closed on Android
	return srv
}

// Start binds a loopback listener on addr (use "127.0.0.1:0" for an
// OS-assigned port) and begins serving in the background. It returns the base
// URL to open. Start is explicit — nothing happens at import/init time.
func (s *Server) Start(addr string) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("listen on %s: %w", addr, err)
	}
	tcp, ok := ln.Addr().(*net.TCPAddr)
	if !ok || !tcp.IP.IsLoopback() {
		ln.Close()
		return "", fmt.Errorf("refusing to serve on non-loopback address %s", ln.Addr())
	}
	s.ln = ln
	s.port = fmt.Sprintf("%d", tcp.Port)

	// Startup is a locked state, so no onion key should be on disk. Sweep any
	// key material a previous run left behind (crash / kill before Stop).
	if s.onion != nil {
		if err := s.onion.Sweep(); err != nil {
			log.Printf("onion keystore sweep at startup: %v", err)
		}
	}

	s.httpSrv = &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go s.httpSrv.Serve(ln)

	// Public onion-facing listener (also loopback; the onion service forwards
	// to it over Tor). Kept separate so the control UI/API is never reachable
	// over the network.
	pubLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		ln.Close()
		return "", fmt.Errorf("listen public: %w", err)
	}
	s.pubLn = pubLn
	s.pubPort = fmt.Sprintf("%d", pubLn.Addr().(*net.TCPAddr).Port)
	pubMux := http.NewServeMux()
	pubMux.HandleFunc("/", s.handlePublicRoot)
	pubMux.HandleFunc(protocol.ChallengePath, s.handleP2PChallenge)
	pubMux.HandleFunc(protocol.MessagePath, s.handleP2PMessage)
	pubMux.HandleFunc(protocol.ProfilePath, s.handleP2PProfile)
	pubMux.HandleFunc(protocol.FriendRequestPath, s.handleP2PFriendRequest)
	pubMux.HandleFunc(protocol.FriendAcceptPath, s.handleP2PFriendAccept)
	pubMux.HandleFunc(protocol.DeleteMessagePath, s.handleP2PDeleteMessage)
	pubMux.HandleFunc(protocol.ReactMessagePath, s.handleP2PReactMessage)
	pubMux.HandleFunc(protocol.GroupMessagePath, s.handleP2PGroupMessage)
	pubMux.HandleFunc(protocol.GroupReactPath, s.handleP2PGroupReact)
	pubMux.HandleFunc(protocol.GroupImagePath, s.handleP2PGroupImage)
	pubMux.HandleFunc(protocol.GroupSyncPath, s.handleP2PGroupSync)
	pubMux.HandleFunc(protocol.GroupRosterPath, s.handleP2PGroupRoster)
	pubMux.HandleFunc(protocol.AttachmentPath, s.handleP2PAttachment)
	pubMux.HandleFunc(protocol.ContactProfilePath, s.handleP2PContactProfile)
	pubMux.HandleFunc(protocol.AvatarPath, s.handleP2PAvatar)
	pubMux.HandleFunc(protocol.GroupInvitePath, s.handleP2PGroupInvite)
	pubMux.HandleFunc(protocol.GroupInviteAcceptPath, s.handleP2PGroupInviteAccept)
	// Multi-device sync (gated by SyncVerify: identity key + enrolled device).
	pubMux.HandleFunc("GET /sync/challenge", s.handleSyncChallenge)
	pubMux.HandleFunc("POST /sync", s.handleSyncExchange)
	// Attachment blob backfill between a user's own devices (same enrolled-device
	// gate as /sync; the message rows sync via /sync but the image bytes do not).
	pubMux.HandleFunc("POST /sync/attachment", s.handleAttachmentSync)
	// Device pairing enrollment (gated by identity key + pairing secret).
	pubMux.HandleFunc("GET /pair/challenge", s.handlePairChallenge)
	pubMux.HandleFunc("POST /pair/enroll", s.handlePairEnroll)
	// Friend-relay: accept blobs to hold for approved friends, and receive
	// relayed blobs pushed by untrusted couriers (gated by inner signature).
	pubMux.HandleFunc("POST /relay/dropoff", s.handleRelayDropOff)
	pubMux.HandleFunc("POST /relay/deliver", s.handleRelayDeliver)
	pubMux.HandleFunc(protocol.RelayRequestPath, s.handleP2PRelayRequest)
	pubMux.HandleFunc(protocol.RelayAcceptPath, s.handleP2PRelayAccept)
	s.pubSrv = &http.Server{
		Handler:           recoverPanic(logRequests(limitInFlight(maxPublicInFlight, pubMux))),
		ReadHeaderTimeout: 5 * time.Second,
		// The onion-facing listener is reachable by anyone on Tor, and several of
		// its handlers must read (and allocate) a request body before they can
		// authenticate — the auth nonce lives INSIDE the body. Bound how long a
		// body read and a response may take so a slow or stalled peer cannot pin a
		// worker; /sync is the only large body and it is capped at maxSyncBody. The
		// peer is Arti on loopback (it terminates the circuit and forwards locally),
		// so these are generous even for a slow Tor client on the far end.
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	go s.pubSrv.Serve(pubLn)

	return s.URL(), nil
}

// handlePublicRoot serves the peer-facing onion endpoint. Phase 4 implements the
// messaging protocol here; for now it only confirms reachability and logs the
// request. It exposes nothing about the identity beyond that it is online.
func (s *Server) handlePublicRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("molepipe onion service reachable\n"))
}

// publicAddr is the loopback address of the onion-facing listener.
func (s *Server) publicAddr() string { return "127.0.0.1:" + s.pubPort }

// PublicAddr is the exported loopback address of the onion-facing listener
// (for logging/diagnostics).
func (s *Server) PublicAddr() string { return s.publicAddr() }

// URL is the base URL to open in a browser. We always advertise 127.0.0.1 (not
// "localhost") so the browser can't resolve to ::1 while we listen on IPv4.
func (s *Server) URL() string { return "http://127.0.0.1:" + s.port }

// TorServing reports whether the onion service is unlocked and reachable — i.e.
// actively hosting, so peers can reach us. The Android foreground service polls
// this to hold a CPU wakelock ONLY while Tor genuinely needs to run (unlocked +
// published), rather than for the whole service lifetime — a locked app hosts no
// onion, so a wakelock then would be pure battery waste.
func (s *Server) TorServing() bool {
	return s.vault.unlocked() && s.onion != nil && s.onion.Ready()
}

// OnionHost returns the underlying Tor service, allowing the mobile layer to
// call Android-specific methods (like SetDormant) via type assertion. Returns
// nil if Tor is disabled.
func (s *Server) OnionHost() tor.OnionService {
	return s.onion
}

// Shutdown gracefully stops the server, tears down the onion service, and locks
// the vault.
func (s *Server) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.cancelGrace() // don't let a deferred teardown fire during/after shutdown
	s.stopOnion()
	s.clearSession()
	s.vault.lock()
	if s.pubSrv != nil {
		_ = s.pubSrv.Shutdown(ctx)
	}
	if s.httpSrv == nil {
		return nil
	}
	return s.httpSrv.Shutdown(ctx)
}

// onionKeyFor derives id's onion key from its signing seed. It reads zeroable
// key material, so any caller that backgrounds startOnion (finishUnlock) must
// call this synchronously — before handing out the session token — while the
// identity is still guaranteed live and cannot be zeroed by a concurrent lock.
// It cannot fail at runtime for an unlocked identity (the seed is always 32
// bytes); the error is defensive against a derivation bug.
func onionKeyFor(id *identity.Identity) (tor.OnionKey, error) {
	return tor.DeriveOnionKey(id.Keys.Signing.Private.Seed())
}

// startOnion (re)starts the sidecar forwarding to this server, publishing the
// account onion on the primary. onionKey is the identity's onion key, which the
// caller derives synchronously while the identity is guaranteed live: startOnion
// may run on a background goroutine (finishUnlock), where reading zeroable key
// material off the vault's identity would race a concurrent lock zeroing it.
// The key is used only on the primary publish path; a secondary ignores it. Tor
// failures are returned but must not fail unlock — the local identity still
// works without Tor.
func (s *Server) startOnion(onionKey tor.OnionKey) error {
	if s.onion == nil {
		return nil
	}
	// If a lock-grace kept the onion running, reuse it: cancel the pending
	// teardown and skip re-publishing entirely. The service is still on the
	// HSDirs under the same address, so a quick re-unlock is reachable at once
	// instead of after a ~9s republish. (Single account per device, so the
	// running onion is always for this identity.)
	if s.cancelGrace() {
		return nil
	}
	// Only the primary device publishes the account onion — a secondary
	// publishing the same key would collide with it on the Tor HSDir hashring.
	// But it must still run Tor: the SOCKS proxy Arti provides is what carries
	// outbound messages and sync pulls, so returning early here left a
	// secondary with no transport at all and no way to reach anything.
	if !s.currentDevice().IsPrimary() {
		// Fast path: if the TorClient is alive (from pre-warm or a previous
		// session), only stop the service — the bootstrapped client is reused.
		type stopServicer interface{ StopService() error }
		type aliver interface{ IsAlive() bool }
		if alive, ok := s.onion.(aliver); ok && alive.IsAlive() {
			if sc, ok := s.onion.(stopServicer); ok {
				sc.StopService()
			}
		} else {
			s.onion.Stop()
		}
		if err := s.onion.StartClient(context.Background()); err != nil {
			return fmt.Errorf("start tor client: %w", err)
		}
		s.onionMu.Lock()
		s.onionAddr = ""
		s.onionMu.Unlock()
		return nil
	}
	// Fast path: if the TorClient is already alive and bootstrapped (pre-warm
	// or previous session), only stop the onion service — Start() reuses the
	// existing client and just launches a new service (~1-8s vs ~15-23s cold).
	type stopServicer interface{ StopService() error }
	type aliver interface{ IsAlive() bool }
	if alive, ok := s.onion.(aliver); ok && alive.IsAlive() {
		if sc, ok := s.onion.(stopServicer); ok {
			sc.StopService()
		}
	} else {
		s.onion.Stop() // idempotent; clears any prior session
	}
	addr, err := s.onion.Start(context.Background(), onionKey, s.publicAddr())
	if err != nil {
		return err
	}
	s.onionMu.Lock()
	s.onionAddr = addr
	s.onionMu.Unlock()
	return nil
}

func (s *Server) stopOnion() {
	if s.onion == nil {
		return
	}
	s.onion.Stop()
	s.onionMu.Lock()
	s.onionAddr = ""
	s.onionMu.Unlock()
}

// startPublishWatchdog monitors the onion service after startOnion. If the
// service stays in "publishing" (Dialable but not Ready) for longer than
// publishTimeout, it restarts the onion service. This recovers from a stuck
// descriptor publication where Arti's service state never reaches
// Running/DegradedReachable. Cancelled automatically on lock via
// cancelPublishWatchdog.
func (s *Server) startPublishWatchdog() {
	if s.onion == nil {
		return
	}
	// Cancel any previous watchdog.
	s.cancelPublishWatchdog()

	ctx, cancel := context.WithCancel(context.Background())
	s.publishWatchdogMu.Lock()
	s.publishWatchdogCancel = cancel
	s.publishWatchdogMu.Unlock()

	const (
		pollInterval    = 5 * time.Second
		publishTimeout  = 90 * time.Second
		dialWaitTimeout = 120 * time.Second
		maxRetries      = 2
	)

	go func() {
		defer cancel()
		// Wait for bootstrap to finish (Dialable) — no point checking Ready
		// before we can even send.
		dialWaited := time.Duration(0)
		for !s.onion.Dialable() {
			select {
			case <-ctx.Done():
				return
			case <-time.After(pollInterval):
			}
			dialWaited += pollInterval
			if dialWaited > dialWaitTimeout {
				log.Printf("publish watchdog: gave up waiting for dialable after %v", dialWaitTimeout)
				return
			}
		}
		// Now poll Ready(). If it doesn't go true within publishTimeout,
		// restart the onion service (up to maxRetries times).
		for attempt := 0; attempt <= maxRetries; attempt++ {
			publishStart := time.Now()
			for {
				if s.onion.Ready() {
					return // descriptor published — we're good
				}
				elapsed := time.Since(publishStart)
				if elapsed >= publishTimeout {
					break // stuck — try restarting
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(pollInterval):
				}
			}
			log.Printf("publish watchdog: onion service stuck (not ready after %v), restart attempt %d/%d", publishTimeout, attempt+1, maxRetries)
			// Restart: stop service only (keep the bootstrapped client).
			type stopServicer interface{ StopService() error }
			type aliver interface{ IsAlive() bool }
			if alive, ok := s.onion.(aliver); ok && alive.IsAlive() {
				if sc, ok := s.onion.(stopServicer); ok {
					sc.StopService()
				}
			}
			s.onionMu.Lock()
			addr := s.onionAddr
			s.onionMu.Unlock()
			if addr == "" {
				return
			}
			// Re-derive the onion key from the live session and re-start.
			s.sessMu.Lock()
			id := s.sessID
			s.sessMu.Unlock()
			if id == nil {
				return
			}
			onionKey, err := onionKeyFor(id)
			if err != nil {
				log.Printf("publish watchdog: re-derive key: %v", err)
				return
			}
			if _, err := s.onion.Start(context.Background(), onionKey, s.publicAddr()); err != nil {
				log.Printf("publish watchdog: restart failed: %v", err)
				return
			}
		}
		log.Printf("publish watchdog: service still not ready after %d restart attempts", maxRetries)
	}()
}

// cancelPublishWatchdog stops the running publish watchdog, if any. Safe to
// call when no watchdog is running.
func (s *Server) cancelPublishWatchdog() {
	s.publishWatchdogMu.Lock()
	fn := s.publishWatchdogCancel
	s.publishWatchdogCancel = nil
	s.publishWatchdogMu.Unlock()
	if fn != nil {
		fn()
	}
}

// graceWindow is how long the onion keeps running after a normal Log out, so a
// quick re-unlock reuses it instead of re-publishing (~9s). See lockOnion. A var
// (not const) only so tests can shrink it.
var graceWindow = 5 * time.Minute

// lockOnion tears the onion down on lock — immediately for a higher-threat
// account (erase-after-failed-unlocks on), or deferred by graceWindow otherwise
// so a quick re-unlock reuses the still-published service. Called from LockNow
// in place of a bare stopOnion.
func (s *Server) lockOnion() {
	if s.onion == nil {
		return
	}
	if !s.graceEligible() {
		s.cancelGrace() // no grace for this posture; drop any stale one too
		s.stopOnion()
		return
	}
	s.startGrace()
}

// graceEligible reports whether a lock should defer the onion teardown. It does
// NOT for an account with erase-after-failed-unlocks enabled: that user wants a
// locked device to be inert, so the key is wiped immediately on lock. (Whether a
// duress code is set is deliberately unknowable — see internal/duress — so the
// visible erase policy stands in as the "treat a locked device as hostile" signal.)
func (s *Server) graceEligible() bool {
	g := s.currentGuard()
	if g == nil {
		return false // can't confirm the erase policy → fail closed, don't hold the key open
	}
	return !g.Status().WipeEnabled
}

// startGrace schedules the deferred onion teardown. Idempotent: a second lock
// while a grace is pending keeps the original window.
func (s *Server) startGrace() {
	s.graceMu.Lock()
	defer s.graceMu.Unlock()
	if s.graceTimer != nil {
		return
	}
	gen := s.graceGen
	s.graceTimer = time.AfterFunc(graceWindow, func() {
		s.graceMu.Lock()
		if s.graceGen != gen { // cancelled/superseded by a re-unlock or wipe
			s.graceMu.Unlock()
			return
		}
		s.graceGen++
		s.graceTimer = nil
		s.graceMu.Unlock()
		s.stopOnion() // outside graceMu: onion.Stop may block
	})
}

// cancelGrace stops a pending grace teardown. It returns true only if it
// cancelled in time — meaning the onion is still running and can be reused. A
// false return means there was no grace, or the teardown already fired (so the
// caller must start the onion normally).
func (s *Server) cancelGrace() bool {
	s.graceMu.Lock()
	defer s.graceMu.Unlock()
	if s.graceTimer == nil {
		return false
	}
	stopped := s.graceTimer.Stop()
	s.graceTimer = nil
	s.graceGen++ // invalidate a callback that already fired and is waiting on graceMu
	return stopped
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// Static UI (embedded). Longest-prefix matching lets /api/ win below.
	sub, _ := fs.Sub(publicFS, "public")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	// Tokenless by necessity: trades a single-use exchange token for the control
	// token (cmd/server browser bootstrap). NOT under /api/ so controlGuard — which
	// would require the very token being handed out — lets it through; origin-guarded.
	mux.HandleFunc("POST /control-token", s.originGuard(s.handleControlToken))

	// No session required: safe to call before unlocking (still control-token
	// gated, like every /api route). Must never expose the account.
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/version", s.handleVersion)
	// No session required, but origin-guarded: takes the password, returns a
	// session token. (Control-token gated by controlGuard like all of /api.)
	mux.HandleFunc("/api/unlock", s.originGuard(s.handleUnlock))
	// Same, via the device-bound PIN shortcut (security doc §1).
	mux.HandleFunc("POST /api/pin/unlock", s.originGuard(s.handlePINUnlock))
	// PIN and duress changes share ONE path. The request logger records paths,
	// so a dedicated /api/duress/enable line would tell anyone reading the log
	// that a panic code exists — the fact §2 exists to hide. The action is in
	// the body, which is never logged. Neither is there any duress unlock
	// endpoint: the code is entered at the ordinary unlock prompts.
	mux.HandleFunc("POST /api/security", s.originGuard(s.auth(s.handleSecurity)))
	// Read-only companion to the POST above: reports PIN state and the
	// erase-after-failed-unlocks policy so the You tab can render them. Authed
	// (a session token) but not origin-guarded, mirroring GET/POST /api/desktop.
	mux.HandleFunc("GET /api/security", s.auth(s.handleSecurityStatus))
	// Pre-identity, origin-guarded: create or recover an identity from the UI.
	mux.HandleFunc("POST /api/create", s.originGuard(s.handleCreate))
	mux.HandleFunc("POST /api/recover", s.originGuard(s.handleRecover))
	// Last resort for a user who has lost both their password and their recovery
	// phrase: remove the account without a credential they no longer have.
	mux.HandleFunc("POST /api/forget-identity", s.originGuard(s.handleForgetIdentity))
	// Authenticated: require a valid session token.
	mux.HandleFunc("/api/identity", s.auth(s.handleIdentity))
	// Notify-only update check: dials the pinned release onion over Tor on behalf
	// of the unlocked identity, so it requires a session. Returns {"state":...}
	// (see handleUpdateCheck); reports "disabled" when no release pins are built in.
	mux.HandleFunc("GET /api/update-check", s.auth(s.handleUpdateCheck))
	mux.HandleFunc("/api/tor-log", s.auth(s.handleTorLog))
	mux.HandleFunc("GET /api/qr", s.auth(s.handleQR))
	mux.HandleFunc("/api/lock", s.originGuard(s.auth(s.handleLock)))
	// Desktop shell settings (start-at-login, one-time notices). Reports
	// "available: false" when no shell is registered.
	mux.HandleFunc("GET /api/desktop", s.auth(s.handleDesktopGet))
	mux.HandleFunc("POST /api/desktop", s.originGuard(s.auth(s.handleDesktopSet)))
	// Open an external link (Donate, Report a bug) in the system browser via the
	// desktop shell. Unavailable — and a no-op the frontend falls back from —
	// when no desktop shell is registered.
	mux.HandleFunc("POST /api/open-external", s.originGuard(s.auth(s.handleOpenExternal)))

	// Messaging + contacts. Method-routed; POSTs are origin-guarded.
	mux.HandleFunc("GET /api/contacts", s.auth(s.handleListContacts))
	mux.HandleFunc("POST /api/contacts", s.originGuard(s.auth(s.handleAddContact)))
	mux.HandleFunc("POST /api/contacts/delete", s.originGuard(s.auth(s.handleDeleteContact)))
	mux.HandleFunc("POST /api/contacts/block", s.originGuard(s.auth(s.handleBlockContact)))
	mux.HandleFunc("GET /api/messages", s.auth(s.handleListMessages))
	mux.HandleFunc("POST /api/messages", s.originGuard(s.auth(s.handleSendMessage)))
	mux.HandleFunc("POST /api/messages/image", s.originGuard(s.auth(s.handleSendImage)))
	mux.HandleFunc("GET /api/attachment", s.auth(s.handleGetAttachment))
	mux.HandleFunc("POST /api/read", s.originGuard(s.auth(s.handleMarkRead)))
	mux.HandleFunc("POST /api/messages/delete", s.originGuard(s.auth(s.handleDeleteMessage)))
	mux.HandleFunc("POST /api/messages/react", s.originGuard(s.auth(s.handleReactMessage)))
	mux.HandleFunc("POST /api/messages/retry", s.originGuard(s.auth(s.handleRetryMessage)))
	mux.HandleFunc("POST /api/delete-identity", s.originGuard(s.auth(s.handleDeleteIdentity)))

	// Multi-device (Phase 5.1 §0).
	mux.HandleFunc("POST /api/pair/start", s.originGuard(s.auth(s.handlePairStart)))
	mux.HandleFunc("POST /api/pair/link", s.originGuard(s.auth(s.handlePairLink)))
	mux.HandleFunc("POST /api/pair/link-setup", s.originGuard(s.handlePairLinkSetup))
	mux.HandleFunc("GET /api/devices", s.auth(s.handleListDevices))
	mux.HandleFunc("POST /api/device/make-primary", s.originGuard(s.auth(s.handleMakePrimary)))
	mux.HandleFunc("POST /api/relay/request", s.originGuard(s.auth(s.handleRequestRelay)))
	mux.HandleFunc("POST /api/relay/approve", s.originGuard(s.auth(s.handleApproveRelay)))
	mux.HandleFunc("POST /api/relay/decline", s.originGuard(s.auth(s.handleDeclineRelay)))
	mux.HandleFunc("POST /api/relay/send", s.originGuard(s.auth(s.handleRelayMessage)))

	mux.HandleFunc("GET /api/groups", s.auth(s.handleListGroups))
	mux.HandleFunc("GET /api/groups/members", s.auth(s.handleListGroupMembers))
	mux.HandleFunc("POST /api/groups/read", s.originGuard(s.auth(s.handleMarkGroupRead)))
	mux.HandleFunc("POST /api/groups/create", s.originGuard(s.auth(s.handleCreateGroup)))
	mux.HandleFunc("POST /api/groups/leave", s.originGuard(s.auth(s.handleLeaveGroup)))
	mux.HandleFunc("POST /api/groups/invite", s.originGuard(s.auth(s.handleInviteToGroup)))
	mux.HandleFunc("GET /api/groups/invites", s.auth(s.handleListGroupInvites))
	mux.HandleFunc("POST /api/groups/invites/accept", s.originGuard(s.auth(s.handleAcceptGroupInvite)))
	mux.HandleFunc("POST /api/groups/invites/decline", s.originGuard(s.auth(s.handleDeclineGroupInvite)))
	mux.HandleFunc("POST /api/groups/remove", s.originGuard(s.auth(s.handleRemoveFromGroup)))
	mux.HandleFunc("POST /api/groups/promote", s.originGuard(s.auth(s.handlePromoteInGroup)))
	mux.HandleFunc("POST /api/groups/can-invite", s.originGuard(s.auth(s.handleSetCanInvite)))
	mux.HandleFunc("POST /api/groups/rename", s.originGuard(s.auth(s.handleRenameGroup)))
	mux.HandleFunc("POST /api/groups/policy", s.originGuard(s.auth(s.handleSetGroupPolicy)))
	mux.HandleFunc("POST /api/groups/send", s.originGuard(s.auth(s.handleSendGroupMessage)))
	mux.HandleFunc("POST /api/groups/react", s.originGuard(s.auth(s.handleGroupReact)))
	mux.HandleFunc("POST /api/groups/image", s.originGuard(s.auth(s.handleSendGroupImage)))
	mux.HandleFunc("POST /api/groups/image/download", s.originGuard(s.auth(s.handleDownloadGroupImage)))
	mux.HandleFunc("POST /api/groups/image/restore", s.originGuard(s.auth(s.handleRestoreGroupImages)))

	// Profile + friend requests (Phase 5).
	mux.HandleFunc("GET /api/profile", s.auth(s.handleGetProfile))
	mux.HandleFunc("GET /api/avatar", s.auth(s.handleGetAvatar))
	mux.HandleFunc("POST /api/profile", s.originGuard(s.auth(s.handleSetProfile)))
	mux.HandleFunc("POST /api/lookup", s.originGuard(s.auth(s.handleLookup)))
	mux.HandleFunc("GET /api/friend-requests", s.auth(s.handleListRequests))
	mux.HandleFunc("POST /api/friend-requests/send", s.originGuard(s.auth(s.handleSendRequest)))
	mux.HandleFunc("POST /api/friend-requests/accept", s.originGuard(s.auth(s.handleAcceptRequest)))
	mux.HandleFunc("POST /api/friend-requests/decline", s.originGuard(s.auth(s.handleDeclineRequest)))

	// Host allowlist wraps everything (anti-DNS-rebinding); the control-token
	// guard sits just inside it so /api is gated against a same-device app that
	// forges Host/Origin; request logging is outermost so every request —
	// including onion-routed ones — is logged. recoverPanic is outermost of all
	// so it catches panics in any middleware or handler without crashing.
	return recoverPanic(logRequests(s.hostGuard(s.controlGuard(securityHeaders(mux)))))
}

// csp is a strict Content-Security-Policy that ENFORCES the app's no-external-
// calls requirement at the browser level: default-src 'none' denies everything
// not listed, and connect-src 'self' blocks any fetch/XHR/WebSocket to another
// host. So even a regressed or tampered vendored script physically cannot
// exfiltrate — the guarantee no longer rests only on auditing the bundle.
// style-src allows 'unsafe-inline' because the Material web components inject
// their own styles; script has no such allowance (only same-origin files).
const csp = "default-src 'none'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	// blob: lets the UI show received images: they're fetched with the auth token
	// (an <img src> can't send one), turned into a same-origin blob: URL and
	// rendered. Still no remote origin — blob:/data: are page-created and local.
	"img-src 'self' data: blob:; " +
	"font-src 'self'; " +
	// blob: additionally lets the UI fetch a page-created image blob back out — for
	// saving a viewed photo to the gallery and for forwarding it to another chat.
	// Like img-src's blob:, a blob: URL is page-local (an in-memory Blob in this
	// origin) and can't be a remote/WebSocket/beacon target, so no remote origin is
	// added and the "physically cannot exfiltrate" guarantee is unchanged.
	"connect-src 'self' blob:; " +
	"base-uri 'none'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'"

// securityHeaders applies the CSP and a few standard hardening headers to the
// control UI/API. (The onion-facing public listener serves no HTML and is not
// wrapped here.)
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// maxPublicInFlight bounds concurrent requests on the onion-facing listener.
// That listener is reachable by anyone on Tor and several handlers allocate a
// request body before they can authenticate (the auth nonce is inside the
// body), so without a ceiling a flood of large unauthenticated POSTs — /sync
// accepts up to maxSyncBody each — is a memory-exhaustion vector. Normal use
// keeps one or two requests in flight; anything past the cap is told to retry.
const maxPublicInFlight = 32

// limitInFlight rejects requests over a concurrency cap with 503 rather than
// queueing them, so a connection flood cannot pile up goroutines or bodies.
// Every public caller (sync, pairing, relay, messaging) already retries, so a
// 503 costs a later attempt, not a lost message. It wraps only the onion-facing
// listener; the loopback control server is single-user and not wrapped.
func limitInFlight(n int, next http.Handler) http.Handler {
	sem := make(chan struct{}, n)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			next.ServeHTTP(w, r)
		default:
			http.Error(w, "busy", http.StatusServiceUnavailable)
		}
	})
}

// logRequests logs method, path, status and duration for each request. This is
// what surfaces an onion request hitting the server (the Phase 3 milestone).
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Printf("%s %s -> %d (%s)", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
	})
}

// recoverPanic catches any panic in an HTTP handler, logs it, and returns 500
// instead of crashing the process. Without this, a single nil-pointer dereference
// or index-out-of-bounds in any handler brings down the entire server. The
// recovery runs outside the handler so it catches panics in middleware too.
func recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic recovered: %v", rec)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// hostGuard rejects requests whose Host header is not a loopback name. A
// rebinding attacker's request carries Host: evil.com and is refused here.
func (s *Server) hostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if !loopbackHosts[host] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// controlGuard gates the /api surface of the control listener on the process's
// capability token. Static assets (everything not under /api/) pass through so
// the page can bootstrap; they carry nothing an on-device app can't already
// read from the APK. The token is compared constant-time and an empty stored
// token rejects everything (fail closed). This is the defense that actually
// separates apps on Android, where 127.0.0.1 is shared and a native caller can
// forge the Host/Origin headers the other guards rely on.
func (s *Server) controlGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			tok := r.Header.Get("X-Control-Token")
			if s.controlToken == "" ||
				subtle.ConstantTimeCompare([]byte(tok), []byte(s.controlToken)) != 1 {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ControlToken is the per-process capability secret the first-party UI must
// echo on every /api call (see controlGuard). Entry points hand it to the UI
// out-of-band via URLWithToken.
func (s *Server) ControlToken() string { return s.controlToken }

// URLWithToken is the bootstrap URL to load in the WebView / browser: the base
// URL plus the control token as a query parameter. The UI reads it once, then
// scrubs it from its address bar. Kept out of URL() so callers that need a
// clean base (tests, address derivation) are unaffected. The token appears only
// in this in-process handoff and never in the request log (logRequests records
// the path, not the query). Used by the embedded-webview shells (Wails, Android)
// where the URL never reaches a browser; cmd/server uses BootstrapExchangeURL.
func (s *Server) URLWithToken() string { return s.URL() + "/?ct=" + s.controlToken }

// BootstrapExchangeURL returns a launch URL carrying a FRESH single-use exchange
// token instead of the durable control token, for the cmd/server entry point
// that opens the UI in the user's default browser. The UI POSTs the token to
// /control-token once to obtain the real token; the exchange is then spent, so
// the copy left in browser history / autocomplete / an extension's log cannot be
// replayed. Each call mints a new token (and re-arms it), so a re-open always
// works. Falls back to the plain tokened URL if the RNG fails (same posture as
// newToken in New: an empty token just means the UI shows the recovery message).
func (s *Server) BootstrapExchangeURL() string {
	tok, err := newToken()
	if err != nil {
		log.Printf("bootstrap exchange token: %v (falling back to direct token URL)", err)
		return s.URLWithToken()
	}
	s.exchangeMu.Lock()
	s.exchangeToken = tok
	s.exchangeSpent = false
	s.exchangeMu.Unlock()
	return s.URL() + "/?x=" + tok
}

// handleControlToken trades a valid, unspent exchange token for the durable
// control token, exactly once. It is intentionally NOT under /api/ (controlGuard
// would demand the very token we are handing out) and is origin-guarded like the
// other state-changing routes. Constant-time compare; an empty stored token or a
// spent one is refused.
func (s *Server) handleControlToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		X string `json:"x"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.exchangeMu.Lock()
	ok := !s.exchangeSpent && s.exchangeToken != "" &&
		subtle.ConstantTimeCompare([]byte(req.X), []byte(s.exchangeToken)) == 1
	if ok {
		s.exchangeSpent = true
	}
	s.exchangeMu.Unlock()
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": s.controlToken})
}

// originGuard enforces same-origin on state-changing requests. It fails CLOSED:
// a missing Origin header is rejected, not treated as same-origin. This is what
// stops a malicious website from CSRF-ing /unlock or /lock. No CORS headers are
// ever sent, so cross-origin reads fail too.
func (s *Server) originGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" || !s.originAllowed(origin) {
			http.Error(w, "bad origin", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// originAllowed accepts only http(s) loopback origins on our own port.
func (s *Server) originAllowed(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if u.Port() != s.port {
		return false
	}
	return loopbackHosts[u.Hostname()]
}

// auth requires a valid Bearer session token and injects the unlocked identity.
func (s *Server) auth(next func(http.ResponseWriter, *http.Request, *identity.Identity)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		id, ok := s.vault.get(tok)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r, id)
	}
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(h, "Bearer "); ok {
		return after
	}
	return ""
}

// --- handlers ---

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"has_identity": s.store.Exists(),
		"unlocked":     s.vault.unlocked(),
		"pin_enabled":  s.pinEnabled(),
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, version.BuildInfo())
}

// handleCreate generates a new identity from the UI (replacing the CLI). It
// returns the recovery phrase once for the user to write down. Refuses to
// overwrite an existing identity.
// validatePassword checks that a password meets minimum strength requirements.
// It requires at least 8 characters (max 256), an uppercase letter, a lowercase
// letter, a digit, and a special character. Unicode letters and digits from all
// scripts (Latin, Cyrillic, CJK, Arabic, etc.) are accepted.
func validatePassword(pw string) error {
	if len(pw) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if len(pw) > 256 {
		return fmt.Errorf("password must be at most 256 characters")
	}
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range pw {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSymbol = true
		}
	}
	if !hasUpper {
		return fmt.Errorf("password must include an uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must include a lowercase letter")
	}
	if !hasDigit {
		return fmt.Errorf("password must include a number")
	}
	if !hasSymbol {
		return fmt.Errorf("password must include a symbol")
	}
	return nil
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	if s.store.Exists() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "an identity already exists on this device"})
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must not be empty"})
		return
	}
	if err := validatePassword(req.Password); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	id, err := identity.New()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.store.Save(id, []byte(req.Password)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"account_number":  id.AccountNumber(),
		"recovery_phrase": id.MnemonicString(),
	})
}

// handleRecover rebuilds an identity from a recovery phrase and a new password.
func (s *Server) handleRecover(w http.ResponseWriter, r *http.Request) {
	if s.store.Exists() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "an identity already exists on this device"})
		return
	}
	var req struct {
		Mnemonic string `json:"mnemonic"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must not be empty"})
		return
	}
	if err := validatePassword(req.Password); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	id, err := identity.FromMnemonic(strings.TrimSpace(req.Mnemonic), "")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid recovery phrase"})
		return
	}
	if err := s.store.Save(id, []byte(req.Password)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// A recovered account may already be live on another device. Defaulting to
	// primary would publish a second descriptor for the same address and
	// collide with it — both devices then become intermittently unreachable,
	// and pairing (which has to dial that address) cannot complete either. So
	// a recovered device starts as a secondary and does not publish. If it is
	// now the only device, the user promotes it explicitly.
	if d := s.currentDevice(); d != nil {
		d.Role = device.RoleSecondary
		if err := device.Save(s.store.Dir, d); err != nil {
			log.Printf("save device role after recover: %v", err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"account_number": id.AccountNumber(),
		"role":           string(device.RoleSecondary),
	})
}

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.store.Exists() {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "no identity on this device — run `tormsg create` first",
		})
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, err := s.guardedLoad(req.Password)
	if err != nil {
		// Not the password. It may be the duress code — the prompt is the same
		// field either way, which is the point: an observer forcing entry gets
		// no signal about which one was typed. Checked on EVERY failure, including
		// a backoff refusal (a coerced user may type the panic code while
		// throttled) and before any counter is touched, so entering it never
		// advances the erase counter.
		if decoy, ok := s.checkDuress(req.Password); ok {
			s.triggerDuress(w, decoy, req.Password)
			return
		}
		var throttled *unlockguard.ThrottleError
		if errors.As(err, &throttled) {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error":       "Too many attempts. Try again in a moment.",
				"retry_after": int(throttled.RetryAfter.Round(time.Second).Seconds()),
			})
			return
		}
		if errors.Is(err, identity.ErrNewerVersion) {
			// The identity file was written by a NEWER build. This is decided at the
			// version check, before decryption, so it is NOT a wrong password and must
			// NOT feed finishFailedUnlock — that path can erase the account on the Nth
			// failure, and a genuine downgrade (or a single corrupt version byte) must
			// never wipe intact data. Tell the user to update; the account is safe.
			writeJSON(w, http.StatusConflict, map[string]string{
				"error": "this app is older than your saved data — update to the latest version to unlock",
			})
			return
		}
		// A genuine wrong password (indistinguishable from a corrupt file — AES-GCM
		// fails auth either way). Record it; the optional policy may erase the
		// account on the Nth consecutive failure.
		s.finishFailedUnlock(w)
		return
	}
	if g := s.currentGuard(); g != nil {
		_ = g.RecordSuccess()
	}
	s.ensureDuressBlob()
	s.finishUnlock(w, id)
}

// guardedLoad refuses a password attempt during an active backoff window and
// otherwise tries to open the identity. Refusing WITHOUT calling store.Load is
// what makes the backoff a real rate limit rather than a delay in front of an
// attempt that still runs.
func (s *Server) guardedLoad(password string) (*identity.Identity, error) {
	if g := s.currentGuard(); g != nil {
		if wait := g.Backoff(); wait > 0 {
			return nil, &unlockguard.ThrottleError{RetryAfter: wait}
		}
	}
	return s.store.Load([]byte(password))
}

// finishFailedUnlock records a wrong password and writes the response. When the
// erase-after-N policy is armed and this failure hit the threshold, it erases
// the account like the lock-screen removal does. NOTHING here may log: this is
// also the duress trigger path (handleUnlock routes both), and a line reading
// "account erased" would be exactly the tell the duress wipe truncates the log
// to avoid.
func (s *Server) finishFailedUnlock(w http.ResponseWriter) {
	g := s.currentGuard()
	if g == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unlock failed"})
		return
	}
	out, _ := g.RecordFailure()
	if out.Wipe {
		s.removeAccountFromDevice()
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "Too many failed attempts — this account has been erased from the device. " +
				"You can restore it with your recovery phrase.",
			"wiped": true,
		})
		return
	}
	resp := map[string]any{"error": "unlock failed"}
	if out.AttemptsLeft >= 0 {
		resp["attempts_left"] = out.AttemptsLeft
	}
	if out.RetryAfter > 0 {
		resp["retry_after"] = int(out.RetryAfter.Round(time.Second).Seconds())
	}
	writeJSON(w, http.StatusUnauthorized, resp)
}

func (s *Server) handleIdentity(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	torEnabled := s.onion != nil
	torReady := torEnabled && s.onion.Ready()
	// tor_sendable: outbound circuits are up, so we can dial peers to SEND even
	// before our own descriptor is published (tor_ready). Sending completes over
	// a single outbound stream and never needs our inbound reachability, so the
	// UI gates the send button on this — not on tor_ready, which would block
	// sending for the whole descriptor-publish window for no reason.
	torSendable := torEnabled && s.onion.Dialable()

	var bootstrapFrac float32
	var hsState string
	if torEnabled {
		bootstrapFrac = s.onion.BootstrapFrac()
		switch {
		case !torSendable && bootstrapFrac < 1.0:
			hsState = "bootstrapping"
		case torSendable && !torReady:
			hsState = "publishing"
		case torReady:
			hsState = "running"
		default:
			hsState = "unknown"
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"account_number":     id.AccountNumber(),
		"onion_address":      id.OnionAddress(),
		"tor_enabled":        torEnabled,
		"tor_ready":          torReady,
		"tor_sendable":       torSendable,
		"tor_bootstrap_frac": bootstrapFrac,
		"tor_hs_state":       hsState,
	})
}

func (s *Server) handleTorLog(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	var lines []string
	if s.onion != nil {
		lines = s.onion.LogLines()
	}
	if lines == nil {
		lines = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"lines": lines,
	})
}

func (s *Server) handleLock(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.LockNow()
	writeJSON(w, http.StatusOK, map[string]string{"status": "locked"})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// WaitReady blocks until the background work spawned by finishUnlock (startOnion
// + startSession) has completed. Used by tests to avoid racing with the async
// startup path; production code never needs this.
func (s *Server) WaitReady() { s.ready.Wait() }
