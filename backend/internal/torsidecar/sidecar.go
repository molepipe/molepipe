// Package torsidecar runs Arti as a child process to host the identity's onion
// service. It is desktop-only glue: it uses os/exec and must NOT be imported by
// the portable core (only cmd/server imports it). On Android the same
// tor.OnionService interface is implemented over Arti's mobile library instead.
package torsidecar

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/tor"
	"github.com/molepipe/molepipe/backend/internal/wipe"
)

// readyMarker is the Arti log line that appears only after the onion service
// descriptor has been successfully uploaded (and it schedules the next upload).
const readyMarker = "reuploading descriptor"

// clientReadyMarker is the line Arti prints once its SOCKS proxy can carry
// traffic. A client-mode sidecar never publishes a descriptor, so readiness
// cannot key off readyMarker.
const clientReadyMarker = "Sufficiently bootstrapped"

// Sidecar hosts one onion service via a child `arti proxy` process.
type Sidecar struct {
	bin      string // path to the arti binary
	workDir  string // holds arti.toml, state/, cache/
	nickname string

	mu        sync.Mutex
	cmd       *exec.Cmd
	keyPath   string
	socksPort string
	ready     atomic.Bool // descriptor published (inbound reachable)
	dialable  atomic.Bool // bootstrap done (outbound circuits available — send-ready)
	logfile   *os.File
}

// New returns a sidecar. bin is the arti binary (e.g. "arti"); workDir is a
// private directory (created 0700) for Arti's config and state.
func New(bin, workDir, nickname string) *Sidecar {
	if bin == "" {
		bin = "arti"
	}
	if nickname == "" {
		nickname = "molepipe"
	}
	return &Sidecar{bin: bin, workDir: workDir, nickname: nickname}
}

// resolveBin finds the Arti executable. The order matters for packaging: an
// explicit path wins, then a copy sitting next to our own executable (how the
// release tarball ships it), then PATH (how a developer machine has it). One
// helper rather than a lookup at each call site, so client mode cannot drift
// from server mode. If an arti-sha256.txt file sits next to the binary, its
// hash is verified to detect tampering.
func (s *Sidecar) resolveBin() (string, error) {
	// An explicit path or anything with a separator is used as given.
	if strings.ContainsRune(s.bin, os.PathSeparator) {
		if _, err := os.Stat(s.bin); err != nil {
			return "", fmt.Errorf("arti not found at %s: %w", s.bin, err)
		}
		s.verifyBinIntegrity(s.bin)
		return s.bin, nil
	}
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), s.bin)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			s.verifyBinIntegrity(candidate)
			return candidate, nil
		}
	}
	path, err := exec.LookPath(s.bin)
	if err != nil {
		return "", fmt.Errorf("could not find the %q program: it should sit next to this "+
			"application or be installed on your PATH (on Arch: pacman -S arti)", s.bin)
	}
	s.verifyBinIntegrity(path)
	return path, nil
}

// verifyBinIntegrity checks the arti binary's SHA-256 against arti-sha256.txt
// if that file exists next to the binary. A mismatch is logged as a warning
// (not a hard failure) because the check file is optional and developer
// builds won't have it.
func (s *Sidecar) verifyBinIntegrity(binPath string) {
	hashFile := binPath + "-sha256.txt"
	expected, err := os.ReadFile(hashFile)
	if err != nil {
		return // no hash file — skip check
	}
	expected = bytes.TrimSpace(expected)
	// Expected format: "arti sha256: <hex>" or just "<hex>"
	if i := bytes.IndexByte(expected, ':'); i >= 0 {
		expected = bytes.TrimSpace(expected[i+1:])
	}
	f, err := os.Open(binPath)
	if err != nil {
		return
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if !bytes.Equal([]byte(actual), expected) {
		log.Printf("WARNING: arti binary integrity check failed — expected %s, got %s", expected, actual)
	}
}

// Start writes the key into Arti's keystore, writes a config forwarding the
// onion virtual port to localAddr, and launches `arti proxy`. It returns the
// .onion address immediately (we know it locally); reachability follows once
// Ready() reports true. The key file is written on Start and removed on Stop,
// so the plaintext onion key is on disk only while the service runs.
func (s *Sidecar) Start(ctx context.Context, key tor.OnionKey, localAddr string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil {
		return "", errors.New("sidecar already started")
	}
	bin, err := s.resolveBin()
	if err != nil {
		return "", err
	}

	state := filepath.Join(s.workDir, "state")
	cache := filepath.Join(s.workDir, "cache")
	hssDir := filepath.Join(state, "keystore", "hss", s.nickname)
	// Clear any key material left by a previous run before writing a fresh key,
	// so a stale key can never be adopted.
	if err := removeKeyMaterial(s.workDir); err != nil {
		return "", err
	}
	for _, d := range []string{s.workDir, state, cache, hssDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "", fmt.Errorf("create %s: %w", d, err)
		}
	}

	keyBytes, err := key.MarshalKeystoreKey()
	if err != nil {
		return "", err
	}
	keyPath := filepath.Join(hssDir, tor.KeystoreFileName)
	if err := os.WriteFile(keyPath, keyBytes, 0o600); err != nil {
		return "", fmt.Errorf("write onion key: %w", err)
	}
	s.keyPath = keyPath

	cfgPath := filepath.Join(s.workDir, "arti.toml")
	if err := os.WriteFile(cfgPath, []byte(renderConfig(state, cache, s.nickname, localAddr)), 0o600); err != nil {
		return "", fmt.Errorf("write arti config: %w", err)
	}

	// Enable the SOCKS listener on a free loopback port so the backend can dial
	// contacts' onion services outbound (Phase 4). Hosting and dialing share the
	// one Arti instance.
	socksPort, err := freeLoopbackPort()
	if err != nil {
		return "", fmt.Errorf("allocate socks port: %w", err)
	}
	s.socksPort = socksPort
	cmd := exec.Command(bin, "proxy", "-c", cfgPath, "-p", socksPort)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}
	s.logfile, _ = os.OpenFile(filepath.Join(s.workDir, "arti.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err := cmd.Start(); err != nil {
		if s.logfile != nil {
			s.logfile.Close()
			s.logfile = nil
		}
		return "", fmt.Errorf("start arti: %w", err)
	}
	s.cmd = cmd
	s.ready.Store(false)
	s.dialable.Store(false)
	go s.watch(stderr)

	addr := identity.AccountNumberForPub(ed25519.PublicKey(key.Public[:])) + ".onion"
	return addr, nil
}

// StartClient runs Arti as a client only: a SOCKS proxy, no onion service and
// no key on disk. A secondary device uses this — it must not publish the
// account address (that would collide with the primary on the HSDir hashring)
// but still needs a transport to send messages and pull sync.
func (s *Sidecar) StartClient(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil {
		return errors.New("sidecar already started")
	}
	bin, err := s.resolveBin()
	if err != nil {
		return err
	}
	state := filepath.Join(s.workDir, "state")
	cache := filepath.Join(s.workDir, "cache")
	// No onion service means no key material; sweep any a previous primary
	// session left behind rather than leaving the account key on disk.
	if err := removeKeyMaterial(s.workDir); err != nil {
		return err
	}
	for _, d := range []string{s.workDir, state, cache} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", d, err)
		}
	}
	cfgPath := filepath.Join(s.workDir, "arti.toml")
	if err := os.WriteFile(cfgPath, []byte(renderClientConfig(state, cache)), 0o600); err != nil {
		return fmt.Errorf("write arti config: %w", err)
	}
	socksPort, err := freeLoopbackPort()
	if err != nil {
		return fmt.Errorf("allocate socks port: %w", err)
	}
	s.socksPort = socksPort
	cmd := exec.Command(bin, "proxy", "-c", cfgPath, "-p", socksPort)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	s.logfile, _ = os.OpenFile(filepath.Join(s.workDir, "arti.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err := cmd.Start(); err != nil {
		if s.logfile != nil {
			s.logfile.Close()
			s.logfile = nil
		}
		return fmt.Errorf("start arti: %w", err)
	}
	s.cmd = cmd
	// A client publishes nothing, so the descriptor marker never appears.
	// Readiness here means "the proxy is usable", which is what callers of a
	// client-mode sidecar actually need to know.
	s.ready.Store(false)
	s.dialable.Store(false)
	go s.watchClient(stderr)
	return nil
}

// Ready reports whether the descriptor has been published (primary mode), or
// that the proxy has bootstrapped (client mode).
func (s *Sidecar) Ready() bool { return s.ready.Load() }

// Dialable reports whether the proxy has bootstrapped enough to carry outbound
// circuits — the send-ready signal (see tor.OnionService.Dialable). It goes
// true at bootstrap, before Ready's descriptor publication in primary mode.
func (s *Sidecar) Dialable() bool { return s.dialable.Load() }

// SocksAddr is the loopback address of Arti's SOCKS proxy, for dialing peer
// onion services. Empty until the service is started.
func (s *Sidecar) SocksAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.socksPort == "" {
		return ""
	}
	return "127.0.0.1:" + s.socksPort
}

// Dialer returns a Tor dialer over Arti's SOCKS proxy for reaching peer onion
// services.
func (s *Sidecar) Dialer() tor.Dialer {
	return tor.SocksDialer{Addr: s.SocksAddr()}
}

// freeLoopbackPort asks the OS for an unused loopback TCP port to hand to Arti.
func freeLoopbackPort() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port), nil
}

// Sweep removes any onion key material left on disk by a previous run — e.g.
// one that crashed or was killed before Stop could delete the key. Call it at
// startup, before unlock, so a leftover plaintext key never survives into a new
// session. It is a no-op while the service is running.
func (s *Sidecar) Sweep() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil {
		return nil
	}
	return removeKeyMaterial(s.workDir)
}

// removeKeyMaterial scrubs and deletes persisted HS private keys and their
// runtime state, keeping the non-secret consensus cache and the long-term guard
// list (rotating guards every launch would hurt anonymity). Uses wipe.Dir to
// overwrite files before unlink, defeating forensic recovery on flash/SSD.
func removeKeyMaterial(workDir string) error {
	var firstErr error
	for _, p := range []string{
		filepath.Join(workDir, "state", "keystore"),
		filepath.Join(workDir, "state", "hss"),
	} {
		if err := wipe.Dir(p); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Stop terminates Arti and removes the plaintext key file.
func (s *Sidecar) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var firstErr error
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_, _ = s.cmd.Process.Wait()
		s.cmd = nil
	}
	if s.keyPath != "" {
		if err := wipe.File(s.keyPath); err != nil && !os.IsNotExist(err) {
			firstErr = err
		}
		s.keyPath = ""
	}
	if s.logfile != nil {
		s.logfile.Close()
		s.logfile = nil
	}
	s.socksPort = ""
	s.ready.Store(false)
	s.dialable.Store(false)
	return firstErr
}

// watch tees Arti's stderr to the log file and flips readiness. Two markers, two
// signals: bootstrap ("Sufficiently bootstrapped") means outbound circuits are
// available, so the device can SEND (dialable); descriptor publication
// ("reuploading descriptor") means peers can reach us INBOUND (ready). Bootstrap
// always precedes publication, so dialable goes true first.
func (s *Sidecar) watch(r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if s.logfile != nil {
			fmt.Fprintln(s.logfile, line)
		}
		// Publication logically implies bootstrap, so latch dialable on EITHER
		// marker: even if a future Arti drops/renames the bootstrap line, a
		// published descriptor can never leave us stuck non-sendable.
		if strings.Contains(line, clientReadyMarker) || strings.Contains(line, readyMarker) {
			s.dialable.Store(true)
		}
		if strings.Contains(line, readyMarker) {
			s.ready.Store(true)
		}
	}
}

// watchClient mirrors watch but keys readiness off bootstrap rather than
// descriptor publication, since a client never publishes one. In client mode
// bootstrap is both the send-ready (dialable) and the fully-ready signal.
func (s *Sidecar) watchClient(r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if s.logfile != nil {
			fmt.Fprintln(s.logfile, line)
		}
		if strings.Contains(line, clientReadyMarker) {
			s.dialable.Store(true)
			s.ready.Store(true)
		}
	}
}

// renderClientConfig is renderConfig without any onion service.
func renderClientConfig(stateDir, cacheDir string) string {
	var b strings.Builder
	b.WriteString("[storage]\n")
	fmt.Fprintf(&b, "state_dir = %s\n", strconv.Quote(stateDir))
	fmt.Fprintf(&b, "cache_dir = %s\n", strconv.Quote(cacheDir))
	return b.String()
}

// renderConfig produces an Arti TOML config that stores state under our private
// dir and forwards the onion virtual port 80 to localAddr.
func renderConfig(stateDir, cacheDir, nickname, localAddr string) string {
	var b strings.Builder
	b.WriteString("[storage]\n")
	fmt.Fprintf(&b, "state_dir = %s\n", strconv.Quote(stateDir))
	fmt.Fprintf(&b, "cache_dir = %s\n\n", strconv.Quote(cacheDir))
	fmt.Fprintf(&b, "[onion_services.%s]\n", strconv.Quote(nickname))
	fmt.Fprintf(&b, "proxy_ports = [[\"80\", %s]]\n", strconv.Quote(localAddr))
	return b.String()
}

// Ensure Sidecar satisfies the interface.
var _ tor.OnionService = (*Sidecar)(nil)

// BootstrapFrac returns 1.0 once bootstrapped (dialable), 0 otherwise. The
// desktop sidecar doesn't expose arti's granular progress.
func (s *Sidecar) BootstrapFrac() float32 {
	if s.dialable.Load() {
		return 1.0
	}
	return 0.0
}

// LogLines reads the arti.log file and returns its most recent lines. Returns
// nil if no log file exists.
func (s *Sidecar) LogLines() []string {
	s.mu.Lock()
	path := filepath.Join(s.workDir, "arti.log")
	s.mu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	// Return last 100 lines max.
	if len(lines) > 100 {
		lines = lines[len(lines)-100:]
	}
	return lines
}
