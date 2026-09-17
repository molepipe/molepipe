// Command mailbox is the standalone Molepipe mailbox server: a small,
// multi-tenant store-and-forward service that holds encrypted, opaque blobs for
// recipients who are offline. It holds no identity and can never read the mail
// it stores (see internal/mailbox). It can expose itself either as its own Tor
// onion service (operator wants the box's location hidden too) or on a clearnet
// host:port behind ordinary hosting (clients still reach it via Tor). Configured
// entirely by env vars so it drops cleanly into a Docker container.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/molepipe/molepipe/backend/internal/mailbox"
	"github.com/molepipe/molepipe/backend/internal/tor"
	"github.com/molepipe/molepipe/backend/internal/torsidecar"
)

func main() {
	cfg := loadConfig()

	store, err := mailbox.New(mailbox.Config{
		Dir:       filepath.Join(cfg.dataDir, "mailboxes"),
		Defaults:  cfg.caps,
		Overrides: loadOverrides(cfg.overridesFile),
	})
	if err != nil {
		log.Fatalf("mailbox store: %v", err)
	}
	handler := mailbox.NewServer(store).Handler()

	// Bind the HTTP server. In onion mode it listens on loopback and Arti
	// forwards the onion to it; in clearnet mode it binds the operator's address.
	bind := cfg.addr
	if cfg.onion {
		bind = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		log.Fatalf("listen %s: %v", bind, err)
	}
	// ReadHeaderTimeout alone does not bound the BODY read; a drop-off body can be
	// megabytes on an image-enabled box, and it is read before the envelope
	// signature is checked, so a stalled reader must not hold a connection open
	// indefinitely. Timeouts are generous because clients dial over Tor (slow) and
	// a pickup response can carry a full mailbox.
	httpSrv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       90 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.onion {
		addr, err := startOnion(ctx, cfg, ln.Addr().String())
		if err != nil {
			log.Fatalf("onion service: %v", err)
		}
		fmt.Println("Mailbox onion address:", addr)
		fmt.Println("Share this as the mailbox URL:", addr)
	} else {
		fmt.Println("Mailbox listening (clearnet) on:", ln.Addr().String())
		fmt.Println("Clients reach it via Tor; put it behind your own hosting/TLS as you like.")
	}

	// Periodic expiry of stale blobs and idle tenancies.
	go sweepLoop(ctx, store)

	fmt.Println("Mailbox is running. Press Ctrl-C to stop.")
	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
}

func startOnion(ctx context.Context, cfg config, localAddr string) (string, error) {
	seed, err := loadOrCreateSeed(filepath.Join(cfg.dataDir, "onion_seed"))
	if err != nil {
		return "", err
	}
	key, err := tor.DeriveOnionKey(seed)
	if err != nil {
		return "", err
	}
	sidecar := torsidecar.New(cfg.artiBin, filepath.Join(cfg.dataDir, "arti"), "mailbox")
	return sidecar.Start(ctx, key, localAddr)
}

// loadOrCreateSeed persists the mailbox's onion seed so its address is stable
// across restarts. 0600, since anyone with it controls the mailbox address.
func loadOrCreateSeed(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("onion seed at %s is corrupt (%d bytes)", path, len(b))
		}
		return b, nil
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		return nil, err
	}
	return seed, nil
}

func sweepLoop(ctx context.Context, store *mailbox.Store) {
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := store.Sweep(); err != nil {
				log.Printf("sweep: %v", err)
			}
		}
	}
}

type config struct {
	dataDir       string
	addr          string
	onion         bool
	artiBin       string
	overridesFile string
	caps          mailbox.Caps
}

func loadConfig() config {
	return config{
		dataDir:       env("MAILBOX_DATA_DIR", "./mailbox-data"),
		addr:          env("MAILBOX_ADDR", ":8443"),
		onion:         envBool("MAILBOX_ONION"),
		artiBin:       env("MAILBOX_ARTI", "arti"),
		overridesFile: env("MAILBOX_OVERRIDES_FILE", ""),
		caps: mailbox.Caps{
			MaxMessages: envInt("MAILBOX_MAX_MESSAGES", 500),
			MaxBytes:    int64(envInt("MAILBOX_MAX_BYTES", 20<<20)),         // 20 MiB per account
			MaxMessage:  int64(envInt("MAILBOX_MAX_MESSAGE_BYTES", 32<<10)), // 32 KiB per blob
			// Backups are opt-in per server: zero MaxBackupBytes disables them.
			// A group image envelope is a few MiB, so the per-blob ceiling is
			// separate from (and much larger than) the 32 KiB message ceiling.
			MaxBackupBytes:   int64(envInt("MAILBOX_MAX_BACKUP_BYTES", 0)),
			MaxBackupMessage: int64(envInt("MAILBOX_MAX_BACKUP_MESSAGE_BYTES", 6<<20)), // 6 MiB per backup blob
			BlobTTL:          time.Duration(envInt("MAILBOX_BLOB_TTL_DAYS", 14)) * 24 * time.Hour,
			IdleTTL:          time.Duration(envInt("MAILBOX_IDLE_TTL_DAYS", 30)) * 24 * time.Hour,
		},
	}
}

// loadOverrides reads an optional JSON file of per-account cap overrides the
// operator maintains for tenants who need more headroom.
func loadOverrides(path string) map[string]mailbox.Caps {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		log.Printf("overrides file %s: %v (ignoring)", path, err)
		return nil
	}
	var m map[string]mailbox.Caps
	if err := json.Unmarshal(b, &m); err != nil {
		log.Printf("overrides file %s: bad JSON: %v (ignoring)", path, err)
		return nil
	}
	return m
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

// envBool is true only for explicitly truthy values, so MAILBOX_ONION=0/false
// disables onion mode rather than enabling it (any non-empty string would).
func envBool(key string) bool {
	switch os.Getenv(key) {
	case "1", "true", "TRUE", "yes", "on":
		return true
	default:
		return false
	}
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
		log.Printf("%s=%q is not an integer; using default %d", key, os.Getenv(key), def)
	}
	return def
}
