//go:build android

// Package artihost implements tor.OnionService for Android over the torhost
// Rust shim (arti-client), linked via cgo. It is the Android counterpart of the
// desktop torsidecar package: same interface, but the onion service runs
// in-process through Arti's library instead of a child `arti` process. The
// onion secret key is handed to native code as raw bytes and never enters the
// JVM.
//
// This file is compiled only for android and only by the gomobile build, which
// links torhost/target/<abi>/libtorhost.a (see android/build-aar.sh and the
// per-ABI ldflags_*.go files). It has never been compiled on the host — the
// host build uses the nil stub in ../../../mobile/onion_stub.go.
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
}

// New returns a Host rooted at dataDir (the app's files dir); Arti state lives
// under dataDir/arti.
func New(dataDir string) *Host { return &Host{dataDir: dataDir} }

// Prewarm triggers one-time global init (logger + rustls crypto provider) at
// app startup so the first Start call does not pay the cost on the unlock path.
func (h *Host) Prewarm() { C.torhost_prewarm() }

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

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.serviceRunning {
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
	return onion, nil
}

// StartClient brings Tor up in dial-out-only mode for a secondary device: it
// bootstraps a client that can reach peer onions and pull sync, without
// publishing the account onion (which would collide with the primary on the
// HSDir hashring). Idempotent: returns nil if the client is already alive.
func (h *Host) StartClient(ctx context.Context) error {
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
	return C.torhost_ready(h.handle) != 0
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
	return nil
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
