// Package mobile is the gomobile binding surface for the Android build. It
// wraps the same api.Server that the desktop entrypoint drives, exposing an
// explicit Start/Stop lifecycle that Android can call from its foreground
// service instead of a main().
//
// gomobile bind only understands a narrow set of exported types (numeric,
// string, bool, []byte, and types defined in THIS package; at most two return
// values, the second an error; no maps, no context.Context). Every exported
// function here obeys those rules so `gomobile bind ./mobile` produces a usable
// .aar. The heavy lifting stays in the portable core — this file is glue, the
// mobile counterpart of cmd/server/main.go, and it is the single place the
// Android build wires Tor in (see newOnionService).
package mobile

import (
	"context"
	"errors"
	"io"
	"log"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/molepipe/molepipe/backend/internal/api"
	"github.com/molepipe/molepipe/backend/internal/datalock"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/porthint"
	"github.com/molepipe/molepipe/backend/internal/runlog"
)

// A single running instance per process. Android recreates activities and may
// call Start more than once for one running service; the mutex plus the running
// check make Start and Stop idempotent rather than letting a second Start fail
// inside api.Server.Start (which errors once its listener is bound).
var (
	mu      sync.Mutex
	srv     *api.Server
	release func() error // datalock release; nil when not held
	logFile *runlog.File // in-dataDir log, size-bounded; nil when not open
)

// MessageListener receives callbacks for newly delivered inbound messages,
// friend requests, and group invites. The Android shell implements it — gomobile
// turns this Go interface into a Java interface a Kotlin class can implement and
// pass back via SetMessageListener — and posts system notifications so events
// can surface while the WebView is closed.
type MessageListener interface {
	// OnMessage reports a newly delivered inbound message. convKey identifies
	// the conversation and is stable for its lifetime (the peer's account, or
	// the group id); fromName is what to display and can change whenever the
	// user renames the contact or group. The shell must key its per-
	// conversation notification on convKey, never on fromName — keyed on the
	// name, a rename while a notification from that conversation was still in
	// the shade posted a second notification instead of replacing the first.
	OnMessage(convKey, fromName, preview string, atMillis int64, avatarBytes []byte)
	OnFriendRequest(fromName string)
	OnFriendAccept(fromName string)
	OnGroupInvite(inviterName, groupName string)
}

var (
	listenerMu  sync.Mutex
	msgListener MessageListener
)

// SetMessageListener registers (or clears, with nil) the listener notified for
// each newly delivered inbound message. Order-independent with Start: the hook
// wired in Start reads this live, so Android may set it before or after Start.
func SetMessageListener(l MessageListener) {
	listenerMu.Lock()
	msgListener = l
	listenerMu.Unlock()
}

func currentListener() MessageListener {
	listenerMu.Lock()
	defer listenerMu.Unlock()
	return msgListener
}

// Start brings the backend up on a loopback port and returns the base URL for
// the Android WebView to load (e.g. "http://127.0.0.1:54321"). It is safe to
// call again while already running: it returns the existing URL and does
// nothing else.
//
// dataDir MUST be an explicit, app-private, writable directory — on Android
// this is Context.getFilesDir(). An empty dataDir is rejected rather than
// falling back to a desktop OS config directory (identity.NewStore's default),
// which does not exist or is not writable under Android's per-app storage.
func Start(dataDir string) (string, error) {
	mu.Lock()
	defer mu.Unlock()

	if srv != nil {
		return srv.URLWithToken(), nil // already running; idempotent
	}
	if dataDir == "" {
		return "", errors.New("dataDir is required (pass Context.getFilesDir())")
	}

	// Refuse to share a data directory with another live process. On Android
	// this is belt-and-suspenders — the OS runs one instance — but datalock uses
	// flock, which the kernel drops on process death (task-swipe, OOM kill), so
	// a hard kill never leaves a stale lock that bricks the next launch.
	rel, err := datalock.Acquire(dataDir)
	if err != nil {
		return "", err
	}

	// Route the run log into the data directory, NOT to stderr. On Android the
	// Go runtime sends stderr to logcat, which survives an account wipe and
	// which the duress / account-removal wipe cannot reach — and the log names
	// the accounts you talked to. Writing only to the in-dataDir file (which the
	// wipe empties, and whose rotated generation the wipe removes — see
	// api.LogFileName and runlog) keeps a wiped directory indistinguishable from
	// a fresh install, the same guarantee desktop has.
	if lf, err := runlog.Open(filepath.Join(dataDir, api.LogFileName),
		runlog.MaxBytes); err == nil {
		// gomobile's mobileinit zeroes the log flags because logcat stamps its
		// own timestamps; our file output inherits that and lands timestampless,
		// which makes the log nearly useless for working out the order and gap
		// between two events. localStamp puts the date and time back, in the
		// device's own zone rather than the UTC the Go runtime reports here —
		// see SetTimeZone. Flags stay at zero because localStamp writes the
		// prefix itself.
		log.SetOutput(localStamp{w: lf})
		log.SetFlags(0)
		logFile = lf
	} else {
		log.Printf("could not open the log file (continuing without one): %v", err)
	}

	store, err := identity.NewStore(dataDir)
	if err != nil {
		_ = rel()
		closeLog()
		return "", err
	}

	// Tor is wired in here and nowhere else, mirroring how cmd/server is the one
	// place the desktop Arti sidecar is constructed. Until the Arti-on-Android
	// binding is proven (Phase 7 §0 spike), this returns nil, and api.Server
	// runs Tor-disabled exactly like the desktop -no-tor flag: the UI and local
	// features come up, the onion service simply is not published yet.
	onion := newOnionService(dataDir)

	// Pre-warm one-time Rust globals (logger + rustls crypto provider) in the
	// background while the WebView loads, so the first Start call on the unlock
	// path does not pay the ~20-100ms init cost. The goroutine is fire-and-forget;
	// the Once guard inside the Rust shim makes repeated calls no-ops.
	if h, ok := onion.(interface{ Prewarm() }); ok {
		go h.Prewarm()
	}

	// Pre-warm Tor bootstrap: start a client-only TorClient in the background
	// so it fetches and caches the consensus directory while the user types
	// their password. When unlock happens, startOnion creates a new TorClient
	// that finds the cached consensus and bootstraps in ~1-2s instead of 5-15s.
	// The client does not publish an onion service — it just warms the cache.
	if h, ok := onion.(interface{ StartClient(context.Context) error }); ok {
		go h.StartClient(context.Background())
	}

	s := api.New(store, onion)
	// Forward newly delivered inbound messages to whatever listener Android has
	// registered, so the shell can post a system notification. Reads the listener
	// live, so registration order relative to Start does not matter.
	s.SetInboundHook(func(convKey, name, preview string, atMillis int64, avatarHash string) {
		if l := currentListener(); l != nil {
			var avatarBytes []byte
			if avatarHash != "" {
				avatarBytes = s.GetAvatarBytes(avatarHash)
			}
			l.OnMessage(convKey, name, preview, atMillis, avatarBytes)
		}
	})
	s.SetFriendRequestHook(func(fromName string) {
		if l := currentListener(); l != nil {
			l.OnFriendRequest(fromName)
		}
	})
	s.SetFriendAcceptHook(func(fromName string) {
		if l := currentListener(); l != nil {
			l.OnFriendAccept(fromName)
		}
	})
	s.SetGroupInviteHook(func(inviterName, groupName string) {
		if l := currentListener(); l != nil {
			l.OnGroupInvite(inviterName, groupName)
		}
	})
	// Ask for the SAME loopback port we used last time, so the WebView keeps
	// its origin and therefore its localStorage. See the porthint package for
	// why that matters and why pinning it costs nothing in security.
	addr, hinted := porthint.Addr(dataDir)
	url, err := s.Start(addr)
	if err != nil && hinted {
		// Something else grabbed it while we were away. Take any port — the
		// settings reset this once, which beats refusing to start.
		url, err = s.Start("127.0.0.1:0")
	}
	if err != nil {
		_ = rel()
		closeLog()
		return "", err
	}
	porthint.Write(dataDir, s.Port())

	srv = s
	release = rel
	_ = url
	// Hand back the token-carrying bootstrap URL, not the bare base: the WebView
	// must load ?ct=<token> so the UI can authenticate to the control listener.
	// On Android 127.0.0.1 is shared across apps, so this capability token — not
	// the (forgeable) Host/Origin headers — is what keeps another app off /api.
	return srv.URLWithToken(), nil
}

// URL returns the bootstrap URL (base + control token) of the running backend,
// or "" if it is not running. It matches what Start returned so the WebView can
// (re)load an authenticated page.
func URL() string {
	mu.Lock()
	defer mu.Unlock()
	if srv == nil {
		return ""
	}
	return srv.URLWithToken()
}

// PublicAddr returns the loopback address of the onion-facing listener (for
// diagnostics), or "" if the backend is not running.
func PublicAddr() string {
	mu.Lock()
	defer mu.Unlock()
	if srv == nil {
		return ""
	}
	return srv.PublicAddr()
}

// IsRunning reports whether the backend is up.
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return srv != nil
}

// TorServing reports whether the onion service is unlocked and reachable, i.e.
// actively hosting. Latched across Arti's descriptor-reupload dips; see
// api.Server.TorServing.
//
// Exported for the shells, though none calls it today. The CPU wakelock this
// was written for is held for BackendService's whole lifetime instead
// (BackendService.kt), so nothing polls this from Kotlin. Its in-process use is
// SetDormant's gate below.
func TorServing() bool {
	mu.Lock()
	defer mu.Unlock()
	return srv != nil && srv.TorServing()
}

// SetDormant toggles arti-client's dormant mode on the underlying Tor host.
// When dormant, proactive background tasks (preemptive circuit building,
// directory fetches) are suspended, conserving CPU and battery. Existing
// connections stay alive. Called from Android when the app transitions between
// foreground and background. No-op if the backend is not running, the host
// does not support dormant mode, or Tor has not finished bootstrapping yet
// (going dormant during bootstrap would slow startup).
//
// That last gate used to read a package-level torReadyOnce flag whose ONLY
// writer was TorServing() above — which no shell has ever called. The flag was
// therefore always false and this function was a permanent no-op: dormant mode
// never engaged on Android at all, despite MainActivity calling it on every
// foreground/background transition. It now asks the server, via a gate that is
// latched (so a descriptor-reupload dip cannot make a backgrounding silently
// fail to go dormant) and that ignores peer traffic (so a peer reaching us off
// a previous session's descriptor cannot let us go dormant while this session's
// publish is still retrying). See api.Server.DormantAllowed.
func SetDormant(dormant bool) {
	mu.Lock()
	defer mu.Unlock()
	if srv == nil || !srv.DormantAllowed() {
		return
	}
	if h, ok := srv.OnionHost().(interface{ SetDormant(bool) }); ok {
		h.SetDormant(dormant)
	}
}

// SetTraceFilter configures Arti's internal tracing filter on the underlying
// Tor host (e.g. "tor_hsservice=debug,tor_circmgr=debug"). "" or "off" disables it.
func SetTraceFilter(spec string) {
	mu.Lock()
	defer mu.Unlock()
	if srv == nil {
		return
	}
	if h, ok := srv.OnionHost().(interface{ SetTraceFilter(string) }); ok {
		h.SetTraceFilter(spec)
	}
}

// Stop shuts the backend down, tears down Tor, locks the vault, and releases the
// data-directory lock. timeoutMillis bounds the graceful shutdown (<= 0 uses a
// 5s default). It is safe to call when not running. context.Context is built
// internally because gomobile cannot pass one across the binding.
func Stop(timeoutMillis int) error {
	mu.Lock()
	defer mu.Unlock()
	if srv == nil {
		return nil // idempotent
	}
	d := time.Duration(timeoutMillis) * time.Millisecond
	if d <= 0 {
		d = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()

	err := srv.Shutdown(ctx)
	srv = nil
	if release != nil {
		if relErr := release(); err == nil {
			err = relErr
		}
		release = nil
	}
	closeLog()
	return err
}

// closeLog detaches the log from the file and closes it. Caller holds mu.
// logLoc is the zone the run log is stamped in, set by SetTimeZone. nil means
// we were never told, and lines fall back to UTC.
var logLoc atomic.Pointer[time.Location]

// SetTimeZone tells the backend which zone to stamp its run log in. The shell
// has to supply this: on Android the Go runtime reports time.Local as UTC
// unconditionally — zoneinfo_android.go's initLocal hard-codes it and the TODO
// to read persist.sys.timezone is still open — so a log stamped from
// time.Local reads hours off the device clock, which sends you looking for an
// event in the wrong window. id is an IANA name (Kotlin:
// TimeZone.getDefault().id, Swift: TimeZone.current.identifier);
// offsetSeconds is that zone's current offset from UTC, used only when the
// zone can't be loaded from the device's tzdata. Idempotent, safe to call
// before or after Start, and takes effect on the next line logged.
func SetTimeZone(id string, offsetSeconds int) {
	// LoadLocation gets DST transitions right, and the Go runtime finds the
	// tzdata it needs at /system/usr/share/zoneinfo/tzdata. It can still miss:
	// Android 10 moved the maintained copy into an APEX module the runtime
	// doesn't look in, so a device without the legacy copy falls back to a
	// fixed offset — correct now, and stale only if the log outlives a DST
	// transition without the app restarting.
	if loc, err := time.LoadLocation(id); err == nil {
		logLoc.Store(loc)
		return
	}
	name := id
	if name == "" {
		name = "local"
	}
	logLoc.Store(time.FixedZone(name, offsetSeconds))
}

// localStamp prefixes every log line with the local date, time and UTC offset.
// It stamps rather than reassigning time.Local because the rest of the backend
// reads that concurrently; this writer is only ever installed before the
// server starts.
type localStamp struct{ w io.Writer }

func (s localStamp) Write(p []byte) (int, error) {
	loc := logLoc.Load()
	if loc == nil {
		loc = time.UTC
	}
	// One Write for the whole line: log.Logger serialises its own output, so a
	// separate prefix write would be safe too, but a single buffer keeps the
	// file readable if anything else ever writes to it. The offset is included
	// so a log pulled onto a machine in another zone still reads unambiguously.
	buf := time.Now().In(loc).AppendFormat(make([]byte, 0, len(p)+32), "2006/01/02 15:04:05 -0700 ")
	prefix := len(buf)
	buf = append(buf, p...)
	n, err := s.w.Write(buf)
	// io.Writer must not report more than it was handed.
	if n -= prefix; n < 0 {
		n = 0
	}
	return n, err
}

func closeLog() {
	if logFile != nil {
		log.SetOutput(io.Discard)
		_ = logFile.Close()
		logFile = nil
	}
}

// newOnionService returns the Tor implementation for this build. It is the
// single Android Tor-wiring seam, split by build tag: onion_android.go returns
// the Arti-backed host (cgo -> torhost), and onion_stub.go returns nil on every
// other platform so the host build and mobile_test.go carry no cgo/Arti
// dependency. api.Server nil-guards every onion call, so the nil path runs the
// backend Tor-disabled (parity with `cmd/server -no-tor`).
