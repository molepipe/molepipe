// Command server runs the local HTTP server that hosts the UI and backend API.
// It exposes an explicit lifecycle (Start/Shutdown) so the same server logic
// can later be driven by Android gomobile hooks instead of a main().
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/molepipe/molepipe/backend/internal/api"
	"github.com/molepipe/molepipe/backend/internal/datalock"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/tor"
	"github.com/molepipe/molepipe/backend/internal/torsidecar"
)

func main() {
	var (
		dataDir     = flag.String("data-dir", "", "identity data directory (default: $TORMSG_DATA_DIR or OS config dir)")
		addr        = flag.String("addr", "127.0.0.1:0", "loopback address to bind (0 = OS-assigned port)")
		noTor       = flag.Bool("no-tor", false, "run without starting the Tor onion service")
		artiBin     = flag.String("arti", "arti", "arti binary: a path, or a name looked up next to this executable then on PATH")
		openBrowser = flag.Bool("open", true, "open the UI in the default browser once the server is listening")
	)
	flag.Parse()

	store, err := identity.NewStore(*dataDir)
	if err != nil {
		log.Fatalf("data dir: %v", err)
	}

	// Refuse to share a data directory with another running instance. Two
	// instances on one directory derive the same identity and onion key, so
	// they publish competing descriptors for the same address and overwrite
	// each other's messages.enc — corruption that shows up much later as
	// unreachable peers and vanished contacts, with nothing pointing back here.
	unlock, err := datalock.Acquire(store.Dir)
	if err != nil {
		log.Fatalf("%v", err)
	}
	defer unlock()

	// Mirror the log into the data directory. A packaged app is launched from a
	// file manager with no terminal attached, so without this every diagnostic
	// — the ones that found four real bugs in this project — is invisible to
	// whoever is running it. The duress and account-removal wipes empty this
	// file, because it names the accounts you talked to.
	if logFile, err := os.OpenFile(filepath.Join(store.Dir, api.LogFileName),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		log.SetOutput(io.MultiWriter(os.Stderr, logFile))
		defer logFile.Close()
	} else {
		log.Printf("could not open the log file (continuing without one): %v", err)
	}

	// The Arti sidecar is desktop-only glue and is created here (not in the
	// portable api/tor packages) so os/exec never enters the gomobile core.
	var onion tor.OnionService
	if !*noTor {
		onion = torsidecar.New(*artiBin, filepath.Join(store.Dir, "arti"), "molepipe")
	}

	srv := api.New(store, onion)
	url, err := srv.Start(*addr)
	if err != nil {
		log.Fatalf("start server: %v", err)
	}

	// The UI must load with a token so its /api calls are accepted; the bare base
	// URL would load the page but every request would be refused. Because this
	// entry point opens the user's DEFAULT BROWSER (unlike the embedded-webview
	// shells), use a single-use exchange token (?x=…) the UI trades once for the
	// real token — so the durable secret never lands in browser history, the
	// address-bar autocomplete DB, or an extension's view. A manual re-open just
	// needs a fresh URL (re-run, or the printed one before it is spent).
	url = srv.BootstrapExchangeURL()
	fmt.Println("Molepipe is running.")
	fmt.Println("Open:", url)
	fmt.Println("Onion-facing listener:", srv.PublicAddr())
	if !store.Exists() {
		fmt.Println("No account on this device yet — the page that just opened will walk you through creating one.")
	}
	fmt.Println("Press Ctrl-C to stop.")

	// Open the UI once the listener is actually accepting, never before, or the
	// first thing a new user sees is a connection-refused page.
	if *openBrowser {
		go openInBrowser(url)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	fmt.Println("\nShutting down…")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

// openInBrowser asks the desktop to open the UI. Failure is not fatal — the URL
// is already printed, and a headless or unusual environment is a normal way to
// run this, not an error.
func openInBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("could not open a browser automatically (open %s yourself): %v", url, err)
	}
}
