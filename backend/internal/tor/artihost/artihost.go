//go:build android || ios

// Package artihost implements tor.OnionService for Android and iOS over the
// torhost Rust shim (arti-client), linked via cgo. It is the mobile counterpart
// of the desktop torsidecar package: same interface, but the onion service runs
// in-process through Arti's library instead of a child `arti` process. The
// onion secret key is handed to native code as raw bytes and never enters the
// JVM (Android) or the Swift runtime (iOS).
//
// This file is compiled only for android/ios and only by the gomobile build,
// which links torhost/target/<abi>/libtorhost.a. On Android the per-ABI
// ldflags_*.go files supply -ltorhost (see android/build-aar.sh); on iOS the
// static library is linked at the Xcode layer (per-SDK LIBRARY_SEARCH_PATHS in
// ios/project.yml), because device and simulator share one Go build tag
// (ios && arm64) and so cannot be told apart by cgo. It has never been compiled
// on the host — the host build uses the nil stub in ../../../mobile/onion_stub.go.
package artihost

/*
#include <stdlib.h>
#include "torhost.h"
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/molepipe/molepipe/backend/internal/crypto"
	"github.com/molepipe/molepipe/backend/internal/tor"
	"github.com/molepipe/molepipe/backend/internal/wipe"
)

// nickname is the Arti keystore/service nickname; it must be stable across runs
// so the keystore path resolves to the same slot (matches the desktop sidecar).
const nickname = "molepipe"

// Dial-budget bounds handed to torhost_dial. Every caller wraps DialOnion in a
// context with a deadline (deliveryContext / WithTimeout), so the budget is
// normally the remaining time on that deadline; these only clamp it. The floor
// keeps a nearly-expired ctx from asking the native side for a sub-second
// connect it can't make; the ceiling and the no-deadline default keep an
// unbounded dial from pinning a native thread forever.
const (
	minDialTimeout     = 1 * time.Second
	maxDialTimeout     = 3 * time.Minute
	defaultDialTimeout = 90 * time.Second
)

// Host implements tor.OnionService (and tor.Dialer) over the torhost shim.
type Host struct {
	dataDir string

	mu             sync.Mutex
	handle         C.torhost_handle // nil unless running
	serviceRunning bool             // true when the onion service is live

	// Which service is live, so a caller about to publish can find out it is
	// already published and skip the teardown — see ServingKey. Both are
	// meaningful only while serviceRunning; they are cleared on every teardown
	// so a stale pair can never vouch for a service that is gone.
	servingPub  [32]byte // Ed25519 public key the live service publishes under
	servingAddr string   // the live service's .onion address

	lastReady   bool             // last observed torhost_ready value
	lastState   tor.ServiceState // last observed torhost_service_state value
	stateLogged bool             // whether lastState has been logged at least once

	// Guards the log-mirroring goroutine so it is started at most once per
	// process. It is deliberately never stopped: it must keep running across a
	// lock and an onion-service restart, and the lines it mirrors (including the
	// teardown ones) are exactly what a post-mortem needs.
	drainOnce sync.Once
}

// How often the Rust log ring is polled for new lines. The ring holds 400, and
// the loudest producer is the dial-retry path, so a few seconds is far short of
// a window in which the ring could turn over and lose lines.
const logDrainInterval = 5 * time.Second

// New returns a Host rooted at dataDir (the app's files dir); Arti state lives
// under dataDir/arti.
func New(dataDir string) *Host { return &Host{dataDir: dataDir} }

// Prewarm triggers one-time global init (logger + rustls crypto provider) at
// app startup so the first Start call does not pay the cost on the unlock path.
func (h *Host) Prewarm() {
	C.torhost_prewarm()
	h.startLogDrain()
}

// startLogDrain mirrors the Rust log ring into the Go run log, once per process.
//
// The ring is 400 lines of process memory read through an authenticated HTTP
// endpoint, so on a phone the native side's diagnostics — onion-service status
// transitions, descriptor-upload failures, start errors — exist only while the
// app is running and only for whoever can open the UI. That made a real failure
// (a service with live intro points whose descriptor never published) impossible
// to investigate from a log pulled off the device. Mirrored into the run log
// they sit alongside the Go lines that give them context, in the one file that
// already carries this history.
//
// The desktop sidecar needs none of this: its LogLines reads arti.log, which is
// already a file on disk.
//
// Note the destination. tormsg.log lives in the app's data dir, so it is erased
// by an account removal and by a duress wipe — which is why mirroring there is
// safe, and why these lines must never be sent to logcat instead: logcat
// survives both, and dial failures name the peers this account talks to.
func (h *Host) startLogDrain() {
	h.drainOnce.Do(func() { go h.drainLogRing() })
}

func (h *Host) drainLogRing() {
	ticker := time.NewTicker(logDrainInterval)
	defer ticker.Stop()

	var prev []string
	// Base text and already-mirrored count of the newest line, so a message that
	// keeps repeating can be re-reported as it grows (see below).
	var lastBase string
	var lastCount int

	for range ticker.C {
		cur := h.LogLines()
		if len(cur) == 0 {
			continue
		}
		for _, line := range newRingLines(prev, cur) {
			log.Printf("tor: %s", line)
			lastBase, lastCount = ringBase(line)
		}
		// A retry loop re-logging one failure does not append to the ring, it
		// bumps the newest line's count in place — so a storm would otherwise
		// appear in the log as a single line. Re-report it each time the count
		// doubles: enough to show a storm and to date its growth, while staying
		// logarithmic in the number of retries rather than one line per retry.
		if base, n := ringBase(cur[len(cur)-1]); base == lastBase && n >= lastCount*2 {
			log.Printf("tor: %s (x%d)", base, n)
			lastCount = n
		}
		prev = cur
	}
}

// Start publishes the onion service under key, forwarding the virtual port to
// localAddr ("127.0.0.1:PORT"), and returns the .onion address. If the TorClient
// is already alive (from a pre-warm or previous session), it only launches a new
// service on the existing client — avoiding the 3s shutdown + full re-bootstrap.
func (h *Host) Start(ctx context.Context, key tor.OnionKey, localAddr string) (string, error) {
	_, portStr, err := net.SplitHostPort(localAddr)
	if err != nil {
		return "", fmt.Errorf("parse local addr %q: %w", localAddr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", fmt.Errorf("parse local port %q: %w", portStr, err)
	}

	// Prewarm normally starts this at app launch; do it here too so a caller
	// that skips Prewarm still gets the native diagnostics in the run log.
	h.startLogDrain()

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.serviceRunning {
		// Already publishing this very key: hand back the address it is already
		// published under instead of failing. The caller wants a published
		// service and there is one, so there is nothing to do. A DIFFERENT key
		// means two identities in one process (a duress decoy, a restore, a
		// pairing) and must still be refused — publishing it here would leave
		// the previous account's descriptor on the HSDirs under a service the
		// caller believes it replaced.
		if h.servingPub == key.Public && h.servingAddr != "" {
			return h.servingAddr, nil
		}
		return "", errors.New("onion host already started")
	}

	// Fast path: TorClient is alive but service was stopped (re-unlock).
	// Launch a new onion service on the existing bootstrapped client.
	if h.handle != nil {
		return h.startServiceLocked(key, port)
	}

	// Slow path: full start — create runtime + client + service.
	cData := C.CString(h.dataDir)
	defer C.free(unsafe.Pointer(cData))
	cNick := C.CString(nickname)
	defer C.free(unsafe.Pointer(cNick))

	// &key.ExpandedSecret[0] is passed to C for the duration of the call only;
	// the Rust side copies the 64 bytes immediately and does not retain the
	// pointer, satisfying the cgo pointer-passing rules.
	var cOnion *C.char
	handle := C.torhost_start(
		cData, cNick,
		(*C.uint8_t)(unsafe.Pointer(&key.ExpandedSecret[0])), C.size_t(len(key.ExpandedSecret)),
		C.uint16_t(port), &cOnion,
	)
	if handle == nil {
		return "", errors.New("torhost failed to start the onion service")
	}
	// Zero the expanded secret from the Go heap now that Rust has copied it.
	crypto.Zero(key.ExpandedSecret[:])
	onion := C.GoString(cOnion)
	C.torhost_free_string(cOnion)

	h.handle = handle
	h.serviceRunning = true
	h.servingPub = key.Public
	h.servingAddr = onion
	return onion, nil
}

// startServiceLocked launches a new onion service on an existing bootstrapped
// TorClient. Caller holds h.mu. Used for the fast re-unlock path.
func (h *Host) startServiceLocked(key tor.OnionKey, port uint64) (string, error) {
	cNick := C.CString(nickname)
	defer C.free(unsafe.Pointer(cNick))

	var cOnion *C.char
	ok := C.torhost_start_service(
		h.handle, cNick,
		(*C.uint8_t)(unsafe.Pointer(&key.ExpandedSecret[0])), C.size_t(len(key.ExpandedSecret)),
		C.uint16_t(port), &cOnion,
	)
	if ok == 0 {
		return "", errors.New("torhost failed to restart the onion service")
	}
	// Zero the expanded secret from the Go heap now that Rust has copied it.
	crypto.Zero(key.ExpandedSecret[:])
	onion := C.GoString(cOnion)
	C.torhost_free_string(cOnion)
	h.serviceRunning = true
	h.servingPub = key.Public
	h.servingAddr = onion
	return onion, nil
}

// StartExtraService launches an additional onion service (a rotation alias)
// alongside the primary account service, on the existing bootstrapped client,
// forwarding its inbound streams to localAddr. nickname MUST be unique across
// the primary and every live alias (arti keys hidden-service state by nickname).
// Returns the alias's .onion address and an opaque id to pass to
// StopExtraService. Requires the client to be up (Start or StartClient first).
//
// This is not part of the tor.OnionService interface; the api layer reaches it
// via an optional upcast, so hosts that don't implement it (torsidecar, the
// no-tor path) simply don't offer rotation.
func (h *Host) StartExtraService(key tor.OnionKey, localAddr, nickname string) (string, uint64, error) {
	_, portStr, err := net.SplitHostPort(localAddr)
	if err != nil {
		return "", 0, fmt.Errorf("parse local addr %q: %w", localAddr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("parse local port %q: %w", portStr, err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.handle == nil {
		return "", 0, errors.New("torhost not started")
	}

	cNick := C.CString(nickname)
	defer C.free(unsafe.Pointer(cNick))

	var cOnion *C.char
	id := C.torhost_start_extra_service(
		h.handle, cNick,
		(*C.uint8_t)(unsafe.Pointer(&key.ExpandedSecret[0])), C.size_t(len(key.ExpandedSecret)),
		C.uint16_t(port), &cOnion,
	)
	if id == 0 {
		return "", 0, errors.New("torhost failed to start the alias onion service")
	}
	// Zero the expanded secret from the Go heap now that Rust has copied it.
	crypto.Zero(key.ExpandedSecret[:])
	onion := C.GoString(cOnion)
	C.torhost_free_string(cOnion)
	return onion, uint64(id), nil
}

// StopExtraService tears down a single rotation alias by the id returned from
// StartExtraService (aborts its forwarder and unpublishes it). It does not
// disturb the primary service or any other alias. A no-op for an unknown id.
func (h *Host) StopExtraService(id uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.handle == nil {
		return
	}
	C.torhost_stop_service_by_id(h.handle, C.uint64_t(id))
}

// StartClient brings Tor up in dial-out-only mode for a secondary device: it
// bootstraps a client that can reach peer onions and pull sync, without
// publishing the account onion (which would collide with the primary on the
// HSDir hashring). Idempotent: returns nil if the client is already alive.
func (h *Host) StartClient(ctx context.Context) error {
	h.startLogDrain()

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.handle != nil {
		return nil // already running
	}
	cData := C.CString(h.dataDir)
	defer C.free(unsafe.Pointer(cData))

	handle := C.torhost_start_client(cData)
	if handle == nil {
		return errors.New("torhost failed to start the tor client")
	}
	h.handle = handle
	return nil
}

// Ready reports whether the descriptor has been published (inbound reachable).
func (h *Host) Ready() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.handle == nil {
		return false
	}
	ready := C.torhost_ready(h.handle) != 0
	if ready != h.lastReady {
		h.lastReady = ready
		st := tor.ServiceState(C.torhost_service_state(h.handle))
		log.Printf("tor: ready transitioned to %v (service state: %v)", ready, st)
	}
	return ready
}

// ServiceState reports arti's own view of the onion service's publication
// state, for the publish watchdog's restart decision. It is deliberately not
// part of tor.OnionService — the desktop sidecar cannot answer — so callers
// reach it through an interface assertion and fall back when it is absent.
// Returns tor.StateUnknown when no handle is live or in client-only mode.
func (h *Host) ServiceState() tor.ServiceState {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.handle == nil {
		return tor.StateUnknown
	}
	st := tor.ServiceState(C.torhost_service_state(h.handle))
	if !h.stateLogged || st != h.lastState {
		h.stateLogged = true
		h.lastState = st
		log.Printf("tor: service state transitioned to %v", st)
	}
	return st
}

// SetTraceFilter configures Arti's internal tracing filter dynamically at runtime.
// An empty spec or "off" disables the bridge.
func (h *Host) SetTraceFilter(spec string) {
	cs := C.CString(spec)
	defer C.free(unsafe.Pointer(cs))
	C.torhost_set_trace_filter(cs)
}

// Dialable reports whether outbound circuits can be built yet (send-ready). See
// the tor.OnionService.Dialable contract: this goes true before Ready, and
// sending is gated on it rather than on descriptor publication.
func (h *Host) Dialable() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.handle == nil {
		return false
	}
	return C.torhost_dialable(h.handle) != 0
}

// SetDormant toggles arti-client's dormant mode. When dormant is true,
// proactive background tasks (preemptive circuit building, directory fetches)
// are suspended, conserving CPU and battery. Existing circuits and TCP
// connections stay alive. The client wakes automatically on next use.
// Called from Android when the app transitions between foreground and background.
func (h *Host) SetDormant(dormant bool) {
	h.mu.Lock()
	handle := h.handle
	h.mu.Unlock()
	if handle == nil {
		return
	}
	var d C.int
	if dormant {
		d = 1
	}
	C.torhost_set_dormant(handle, d)
}

// Dialer returns a dialer for reaching peer onion services (Host itself).
func (h *Host) Dialer() tor.Dialer { return h }

// DialOnion connects to onionHostPort ("abcd….onion:80") over Tor. The shim
// bridges Arti's circuit stream to a real socket fd, which we wrap as a
// net.Conn.
//
// torhost_dial is a blocking cgo call, so it is run on its own goroutine and
// raced against ctx: the caller's deadline (or an explicit cancel) returns
// control at once instead of waiting out a hung circuit build. The native
// connect is bounded by the same deadline (passed as timeout_ms), and if it
// still lands after we have given up, a cleanup goroutine closes the orphaned
// fd so a slow dial cannot leak a socket.
func (h *Host) DialOnion(ctx context.Context, onionHostPort string) (net.Conn, error) {
	h.mu.Lock()
	handle := h.handle
	h.mu.Unlock()
	if handle == nil {
		return nil, errors.New("onion host not running")
	}

	// Derive the native connect budget from the ctx deadline. If it has already
	// passed, never enter the blocking C call.
	timeoutMs := uint64(defaultDialTimeout / time.Millisecond)
	if dl, ok := ctx.Deadline(); ok {
		remaining := time.Until(dl)
		if remaining <= 0 {
			return nil, ctx.Err()
		}
		if remaining < minDialTimeout {
			remaining = minDialTimeout
		} else if remaining > maxDialTimeout {
			remaining = maxDialTimeout
		}
		timeoutMs = uint64(remaining / time.Millisecond)
	}

	cTarget := C.CString(onionHostPort)
	// Buffered so the dial goroutine can always send its result and exit even
	// after we have stopped listening (ctx cancelled) — an unbuffered channel
	// here would leak the goroutine AND its OS thread on every cancelled dial.
	ch := make(chan C.int, 1)
	go func() {
		ch <- C.torhost_dial(handle, cTarget, C.uint64_t(timeoutMs))
		C.free(unsafe.Pointer(cTarget)) // must outlive the C call
	}()

	select {
	case <-ctx.Done():
		// Gave up before the dial returned. Reclaim the fd if it still lands.
		go func() {
			if fd := <-ch; fd >= 0 {
				_ = syscall.Close(int(fd))
			}
		}()
		return nil, ctx.Err()
	case fd := <-ch:
		if fd < 0 {
			return nil, fmt.Errorf("torhost could not dial %s", onionHostPort)
		}
		f := os.NewFile(uintptr(fd), "onion:"+onionHostPort)
		if f == nil {
			_ = syscall.Close(int(fd))
			return nil, fmt.Errorf("invalid fd %d from torhost for %s", int(fd), onionHostPort)
		}
		conn, err := net.FileConn(f) // dups the fd
		_ = f.Close()                // drop our copy; conn owns its own dup
		if err != nil {
			return nil, fmt.Errorf("wrap onion fd: %w", err)
		}
		return conn, nil
	}
}

// Sweep removes any key material a previous run left in the keystore before a
// fresh start, mirroring the desktop sidecar's startup sweep. Pure Go, so it
// needs no handle and works while stopped. Uses wipe.Dir to scrub files before
// unlink, defeating forensic recovery on flash/SSD.
func (h *Host) Sweep() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.handle != nil {
		return nil // running; not safe to sweep
	}
	base := filepath.Join(h.dataDir, "arti")
	for _, sub := range []string{"keystore", "hss"} {
		p := filepath.Join(base, sub)
		if err := wipe.Dir(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// Stop tears the service down, frees the handle, and wipes the keystore.
func (h *Host) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.handle == nil {
		return nil
	}
	C.torhost_stop(h.handle)
	h.handle = nil
	h.serviceRunning = false
	h.servingPub = [32]byte{}
	h.servingAddr = ""
	return nil
}

// StopService stops only the onion service while keeping the TorClient and
// runtime alive. This enables a fast restart on re-unlock: the bootstrapped
// client stays warm, and only a new onion service needs to be launched.
// Wipes the keystore so the onion key does not outlive the session.
func (h *Host) StopService() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.handle == nil {
		return nil
	}
	C.torhost_stop_service(h.handle)
	h.serviceRunning = false
	h.servingPub = [32]byte{}
	h.servingAddr = ""
	return nil
}

// ServingKey reports the public key and .onion address of the live onion
// service. running is false when nothing is published, in which case the other
// two values are zero and must not be used.
//
// It exists so the api layer can tell "this service is already published under
// exactly the key I was about to publish" from "this is a different service",
// and skip a teardown-and-republish in the first case. Comparing the key
// matters: re-unlocking the same account is not the only way back into
// startOnion, and a duress decoy or a restore arrives with a different
// identity in the same process.
//
// Not part of the tor.OnionService interface; the api layer reaches it via an
// optional upcast, so a host that does not implement it (torsidecar) simply
// keeps the old teardown-and-republish behaviour.
func (h *Host) ServingKey() (pub [32]byte, onion string, running bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.serviceRunning {
		return [32]byte{}, "", false
	}
	return h.servingPub, h.servingAddr, true
}

// IsAlive reports whether the underlying TorClient is running (the handle is
// valid). When true, a subsequent Start call can reuse the bootstrapped client
// for a fast restart instead of creating a new one from scratch.
func (h *Host) IsAlive() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.handle != nil
}

// BootstrapFrac returns a rough fraction (0.0–1.0) of Tor bootstrap progress.
func (h *Host) BootstrapFrac() float32 {
	h.mu.Lock()
	handle := h.handle
	h.mu.Unlock()
	if handle == nil {
		return 0
	}
	return float32(C.torhost_bootstrap_frac(handle))
}

// LogLines returns the recent torhost log lines from the Rust ring buffer.
func (h *Host) LogLines() []string {
	count := int(C.torhost_log_count())
	if count == 0 {
		return nil
	}
	lines := make([]string, 0, count)
	for i := 0; i < count; i++ {
		cline := C.torhost_log_line(C.int(i))
		if cline == nil {
			continue
		}
		lines = append(lines, C.GoString(cline))
		C.torhost_free_string(cline)
	}
	return lines
}

var (
	_ tor.OnionService = (*Host)(nil)
	_ tor.Dialer       = (*Host)(nil)
)
