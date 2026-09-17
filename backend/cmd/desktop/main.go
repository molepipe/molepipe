// Command desktop runs Molepipe as a desktop application: the same
// api.Server as cmd/server, displayed in a native window instead of a browser
// tab, with a tray icon and a close button that hides rather than quits.
//
// It is a shell, not a second implementation. Identity, crypto, Tor, protocol
// and storage all come from the same internal packages cmd/server uses, and
// cmd/server is unchanged — it remains the headless and development path.
//
// Build it with:
//
//	CGO_ENABLED=1 go build -tags "desktop production webkit2_41" ./cmd/desktop
//
// See tools/build-release.sh, which is the supported way to produce it.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	wr "github.com/wailsapp/wails/v2/pkg/runtime"

	"fyne.io/systray"

	"github.com/molepipe/molepipe/backend/internal/api"
	"github.com/molepipe/molepipe/backend/internal/datalock"
	"github.com/molepipe/molepipe/backend/internal/desktop"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/tor"
	"github.com/molepipe/molepipe/backend/internal/torsidecar"
)

// backgroundNotice is what the user is told the first time they close the
// window. Background persistence is the whole point of the tray — but a
// messenger that keeps running after you close it, without saying so, is a
// surprise nobody should get from a privacy tool.
const (
	noticeSummary = "Molepipe is still running"
	noticeBody    = "It stays in the background so you can receive messages. " +
		"Click the tray icon to reopen it, or choose Quit there to stop it completely."
)

var (
	// quitting distinguishes a real quit from a close-to-tray.
	//
	// This flag is load-bearing, and its absence is not a subtle bug: Wails
	// routes runtime.Quit() and its Ctrl-C handler through OnBeforeClose too,
	// so a handler that unconditionally hides the window and returns true
	// refuses every exit path. Without this the app cannot be quit at all.
	quitting atomic.Bool

	ctxMu  sync.Mutex
	appCtx context.Context

	srv   *api.Server
	state *desktop.State
)

func main() {
	var (
		dataDir = flag.String("data-dir", "", "identity data directory (default: $TORMSG_DATA_DIR or OS config dir)")
		addr    = flag.String("addr", "127.0.0.1:0", "loopback address to bind (0 = OS-assigned port)")
		noTor   = flag.Bool("no-tor", false, "run without starting the Tor onion service")
		artiBin = flag.String("arti", "arti", "arti binary: a path, or a name looked up next to this executable then on PATH")
	)
	flag.Parse()

	if !nativeWindow {
		log.Printf("warning: built without -tags \"desktop production\", so this is not a native window build. " +
			"See the package comment; use tools/build-release.sh.")
	}

	store, err := identity.NewStore(*dataDir)
	if err != nil {
		log.Fatalf("data dir: %v", err)
	}

	// Same single-instance guard as cmd/server, and for the same reason: two
	// instances on one data directory publish competing onion descriptors and
	// overwrite each other's messages. A second launch of a windowed app is
	// much more likely than a second `go run`, so this path matters more here.
	unlock, err := datalock.Acquire(store.Dir)
	if err != nil {
		// There is no terminal behind a launcher icon, so say it where it can
		// actually be seen before giving up.
		_ = desktop.Notify("Molepipe is already running",
			"Look for its icon in the system tray.")
		log.Fatalf("%v", err)
	}
	defer unlock()

	if logFile, err := os.OpenFile(filepath.Join(store.Dir, api.LogFileName),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		log.SetOutput(io.MultiWriter(os.Stderr, logFile))
		defer logFile.Close()
	} else {
		log.Printf("could not open the log file (continuing without one): %v", err)
	}

	var onion tor.OnionService
	if !*noTor {
		onion = torsidecar.New(*artiBin, filepath.Join(store.Dir, "arti"), "molepipe")
	}

	srv = api.New(store, onion)
	// The login entry always names the resolved data directory rather than
	// relying on flags or $TORMSG_DATA_DIR being present at login — a desktop
	// session starts with an environment nothing here controls, and an entry
	// that silently opened a different (empty) account would look like data loss.
	srv.SetDesktop(newShell("-data-dir", store.Dir))
	state = desktop.LoadState(store.Dir)

	url, err := srv.Start(*addr)
	if err != nil {
		log.Fatalf("start server: %v", err)
	}
	log.Printf("Molepipe desktop: control UI on %s, onion-facing listener on %s", url, srv.PublicAddr())

	// Signals must set the flag before asking Wails to quit, or OnBeforeClose
	// treats Ctrl-C as a close-to-tray and the process becomes unkillable
	// without a SIGKILL.
	//
	// A plain channel rather than signal.NotifyContext: that context is also
	// cancelled during normal teardown, which had this logging "signal
	// received" on every clean quit — a line that would send anyone reading
	// the log after a crash looking in the wrong place.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("%v received, shutting down", sig)
		requestQuit()
	}()

	go runTray()

	err = wails.Run(&options.App{
		Title:     "Molepipe",
		Width:     1100,
		Height:    760,
		MinWidth:  420,
		MinHeight: 560,
		AssetServer: &assetserver.Options{
			// A holding page, shown for the instant before the webview is sent
			// to the real UI. The app's own HTML/CSS/JS is NOT served from here
			// — see navigateToServer.
			Assets: bootAssets,
		},
		Linux: &linux.Options{
			Icon:                desktop.Icon(),
			WindowIsTranslucent: false,
		},
		OnStartup:     onStartup,
		OnBeforeClose: onBeforeClose,
		OnShutdown:    onShutdown,
	})
	if err != nil {
		log.Fatalf("desktop window: %v", err)
	}
}

// onStartup points the webview at the running server.
//
// This is the whole integration, and the reason nothing about the security
// model changes. The page is loaded over real HTTP from 127.0.0.1, so it has a
// real loopback origin: the Origin and Host headers the UI sends are the ones
// the host allowlist and the fail-closed origin guard already expect, and the
// CSP the server sets applies exactly as it does in a browser.
//
// Serving the UI from Wails' own asset scheme would instead give the page a
// wails:// origin, which the origin guard rejects — and "fix" that by relaxing
// the guard and the anti-CSRF property goes with it. So the assets embedded
// above are only a holding page.
func onStartup(ctx context.Context) {
	ctxMu.Lock()
	appCtx = ctx
	ctxMu.Unlock()
	// ?shell=desktop is purely a display hint — the UI drops the floating-card
	// frame that a browser tab wants and fills the window instead. A query
	// string is not part of Host, Origin or the CSP, so it reaches none of the
	// guards; the page's origin is the same loopback origin either way.
	wr.WindowExecJS(ctx, fmt.Sprintf("window.location.replace(%q)", srv.URL()+"/?shell=desktop&ct="+srv.ControlToken()))
}

// onBeforeClose runs for every close request, including runtime.Quit().
// Returning true cancels the close.
func onBeforeClose(ctx context.Context) bool {
	if quitting.Load() {
		return false // a real quit: let it through to onShutdown
	}
	wr.WindowHide(ctx)
	// Only ever once per data directory, and only at the moment it becomes
	// true — telling someone at first launch that closing the window will keep
	// the app running is advice about a thing they have not done yet.
	if state.NeedsBackgroundNotice() {
		if err := desktop.Notify(noticeSummary, noticeBody); err != nil {
			log.Printf("desktop notification unavailable (%v); the in-app notice will carry it", err)
		}
		// Posted regardless. The window is hidden, so the user cannot see this
		// yet — it waits until they open it again, which is the one moment
		// they are certain to be looking.
		srv.PostNotice(noticeSummary + ". " + noticeBody)
	}
	return true
}

// onShutdown runs the graceful shutdown before the process exits.
//
// It runs synchronously inside Wails' teardown, which is what makes the Phase 3
// promise hold: Shutdown stops the onion service, which deletes the unencrypted
// onion identity key from the Arti keystore. Quitting without waiting for this
// would leave that key on disk — a packaging change silently weakening the
// threat model.
func onShutdown(_ context.Context) {
	systray.Quit()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	log.Printf("stopped")
}

// requestQuit is the single way this app exits. Idempotent: a double-click on
// the tray's Quit item must not race two shutdowns.
func requestQuit() {
	if !quitting.CompareAndSwap(false, true) {
		return
	}
	if ctx := currentCtx(); ctx != nil {
		wr.Quit(ctx)
		return
	}
	// Quit before the window ever came up: there is no Wails loop to stop, so
	// tear down directly rather than leaving the server running headless.
	onShutdown(context.Background())
	os.Exit(0)
}

func currentCtx() context.Context {
	ctxMu.Lock()
	defer ctxMu.Unlock()
	return appCtx
}

// showWindow brings the window back from the tray.
func showWindow() {
	ctx := currentCtx()
	if ctx == nil {
		return
	}
	wr.WindowShow(ctx)
	wr.WindowUnminimise(ctx)
}

// runTray owns the tray icon. On Linux this is a StatusNotifierItem over the
// session bus (no GTK involved), so it does not compete with the webview for
// the main loop.
func runTray() {
	systray.Run(func() {
		systray.SetIcon(desktop.Icon())
		systray.SetTitle("Molepipe")
		systray.SetTooltip("Molepipe")

		open := systray.AddMenuItem("Open", "Show the Molepipe window")
		lock := systray.AddMenuItem("Lock", "Lock the app and take the account offline")
		systray.AddSeparator()
		quit := systray.AddMenuItem("Quit", "Stop Molepipe completely")

		// This callback MUST return. systray only marks the menu as built once
		// it does, and until then every GetLayout call blocks — which is the
		// method the panel uses to draw the menu. Handling clicks inline here
		// instead of in a goroutine leaves a tray icon that appears normally,
		// responds to nothing, and shows no menu on right-click. It is not a
		// subtle failure, but it is an invisible one from the Go side: firing
		// menu events directly still works, so only opening the real menu
		// catches it.
		go func() {
			for {
				select {
				case <-open.ClickedCh:
					showWindow()
				case <-lock.ClickedCh:
					// Locks in-process. The HTTP route needs the session
					// token, which only the page holds; both call the same
					// method.
					srv.LockNow()
					log.Printf("locked from the tray")
					showWindow()
				case <-quit.ClickedCh:
					requestQuit()
					return
				}
			}
		}()
	}, nil)
}
