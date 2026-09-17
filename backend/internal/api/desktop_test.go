package api

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/desktop"
)

// fakeShell stands in for cmd/desktop: the same interface, with the OS write
// replaced by a variable so the wiring can be tested without a login entry.
type fakeShell struct {
	available bool
	on        bool
	failSet   bool
	failOpen  bool
	opened    string // last URL passed to OpenExternal
}

func (f *fakeShell) AutostartAvailable() bool        { return f.available }
func (f *fakeShell) AutostartEnabled() (bool, error) { return f.on, nil }
func (f *fakeShell) SetAutostart(on bool) error {
	if f.failSet {
		return errors.New("nope")
	}
	f.on = on
	return nil
}
func (f *fakeShell) OpenExternal(url string) error {
	if f.failOpen {
		return errors.New("nope")
	}
	f.opened = url
	return nil
}

func unlocked(t *testing.T) (*Server, string) {
	t.Helper()
	s, pw := newTestServer(t)
	r := s.do(t, "POST", "/api/unlock", `{"password":"`+pw+`"}`, map[string]string{"Origin": s.origin()})
	tok, _ := decode(t, r.Body)["session_token"].(string)
	if tok == "" {
		t.Fatal("unlock returned no token")
	}
	return s, tok
}

// With no shell registered — every cmd/server run and every test — the settings
// must report themselves unavailable rather than appearing and then failing.
func TestDesktopUnavailableWithoutAShell(t *testing.T) {
	s, tok := unlocked(t)
	body := decode(t, s.do(t, "GET", "/api/desktop", "", authHdr(s, tok)).Body)
	if body["available"] != false {
		t.Fatalf("expected available:false without a shell, got %v", body)
	}
	if _, ok := body["autostart"]; ok {
		t.Fatal("no shell must mean no autostart state at all, not a default")
	}
	// And asking to turn it on is refused, not silently ignored.
	r := s.do(t, "POST", "/api/desktop", `{"autostart":true}`, authHdr(s, tok))
	if r.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with no shell, got %d (%s)", r.Code, r.Body)
	}
}

func TestAutostartToggleRoundTrips(t *testing.T) {
	s, tok := unlocked(t)
	shell := &fakeShell{available: true}
	s.SetDesktop(shell)

	body := decode(t, s.do(t, "GET", "/api/desktop", "", authHdr(s, tok)).Body)
	if body["available"] != true || body["autostart_available"] != true || body["autostart"] != false {
		t.Fatalf("unexpected initial state %v", body)
	}
	// Off by default is a requirement, not an accident: registering a shell must
	// not have turned anything on above.
	if shell.on {
		t.Fatal("registering the shell enabled start-at-login by itself")
	}

	body = decode(t, s.do(t, "POST", "/api/desktop", `{"autostart":true}`, authHdr(s, tok)).Body)
	if body["autostart"] != true || !shell.on {
		t.Fatalf("enabling did not take: %v (shell=%v)", body, shell.on)
	}
	body = decode(t, s.do(t, "POST", "/api/desktop", `{"autostart":false}`, authHdr(s, tok)).Body)
	if body["autostart"] != false || shell.on {
		t.Fatalf("disabling did not take: %v (shell=%v)", body, shell.on)
	}
}

// A failed write must surface. The alternative — reporting success and leaving
// the setting off — is the kind of quiet lie this project has been avoiding.
func TestAutostartFailureIsReported(t *testing.T) {
	s, tok := unlocked(t)
	s.SetDesktop(&fakeShell{available: true, failSet: true})
	r := s.do(t, "POST", "/api/desktop", `{"autostart":true}`, authHdr(s, tok))
	if r.Code != http.StatusInternalServerError {
		t.Fatalf("expected the failure to be reported, got %d (%s)", r.Code, r.Body)
	}
}

// The open-external route hands the URL to the shell, but only for http(s) and
// only when a shell exists — otherwise the frontend must fall back to
// window.open, which it can only do if the route says no.
func TestOpenExternalGoesToTheShell(t *testing.T) {
	s, tok := unlocked(t)
	shell := &fakeShell{available: true}
	s.SetDesktop(shell)

	if r := s.do(t, "POST", "/api/open-external", `{"url":"https://example.com/x"}`, authHdr(s, tok)); r.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", r.Code, r.Body)
	}
	if shell.opened != "https://example.com/x" {
		t.Fatalf("shell was asked to open %q, want the posted URL", shell.opened)
	}

	// Non-http(s) is refused before it ever reaches the shell.
	shell.opened = ""
	if r := s.do(t, "POST", "/api/open-external", `{"url":"file:///etc/passwd"}`, authHdr(s, tok)); r.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a non-http(s) URL, got %d", r.Code)
	}
	if shell.opened != "" {
		t.Fatalf("a rejected scheme still reached the shell: %q", shell.opened)
	}
}

// With no shell (cmd/server in a browser) the route reports unavailable so the
// frontend knows to use window.open instead.
func TestOpenExternalUnavailableWithoutAShell(t *testing.T) {
	s, tok := unlocked(t)
	if r := s.do(t, "POST", "/api/open-external", `{"url":"https://example.com"}`, authHdr(s, tok)); r.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with no shell, got %d (%s)", r.Code, r.Body)
	}
}

// The desktop routes are guarded exactly like every other route: no token, no
// answer; no origin, no write.
func TestDesktopRoutesKeepTheGuards(t *testing.T) {
	s, tok := unlocked(t)
	s.SetDesktop(&fakeShell{available: true})

	if r := s.do(t, "GET", "/api/desktop", "", map[string]string{"Origin": s.origin()}); r.Code != http.StatusUnauthorized {
		t.Fatalf("GET without a token should be 401, got %d", r.Code)
	}
	if r := s.do(t, "POST", "/api/desktop", `{"autostart":true}`, map[string]string{
		"Authorization": "Bearer " + tok, // token but no Origin
	}); r.Code != http.StatusForbidden {
		t.Fatalf("POST without an Origin should be 403, got %d", r.Code)
	}
	if r := s.do(t, "POST", "/api/desktop", `{"autostart":true}`, map[string]string{
		"Origin": "http://evil.example", "Authorization": "Bearer " + tok,
	}); r.Code != http.StatusForbidden {
		t.Fatalf("POST from a foreign origin should be 403, got %d", r.Code)
	}
}

// The notice is delivered until the UI says it has been seen — it is raised
// while the window is hidden, so a single unacknowledged poll would drop it.
func TestNoticeSurvivesUntilDismissed(t *testing.T) {
	s, tok := unlocked(t)
	s.PostNotice("still running in the background")

	for range 3 {
		body := decode(t, s.do(t, "GET", "/api/desktop", "", authHdr(s, tok)).Body)
		if body["notice"] != "still running in the background" {
			t.Fatalf("the notice was dropped before it was acknowledged: %v", body)
		}
	}
	s.do(t, "POST", "/api/desktop", `{"dismiss_notice":true}`, authHdr(s, tok))
	body := decode(t, s.do(t, "GET", "/api/desktop", "", authHdr(s, tok)).Body)
	if body["notice"] != "" {
		t.Fatalf("the notice survived being dismissed: %v", body)
	}
}

// Removing the account must also remove the start-at-login entry. It is the
// only piece of this app's state outside the data directory, so nothing else
// in the wipe reaches it — and after a duress wipe, a leftover entry named
// "Molepipe" is the wipe announcing itself.
func TestWipeRemovesTheAutostartEntry(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	entry := filepath.Join(cfg, "autostart", desktop.EntryName)

	a, err := desktop.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Set(true); err != nil {
		t.Skipf("start-at-login is not implemented on this platform: %v", err)
	}
	if _, err := os.Stat(entry); err != nil {
		t.Fatalf("setup failed to write the entry: %v", err)
	}

	s, _ := newTestServer(t)
	s.removeAccountFromDevice()

	if _, err := os.Stat(entry); !os.IsNotExist(err) {
		t.Fatal("the account wipe left the start-at-login entry behind")
	}
}

// desktop.json only exists once the window has been closed at least once, so a
// directory that still has it is visibly a directory that has been used — and
// the one the duress wipe leaves behind is meant to look untouched. Same class
// as the missing relay/ directory and the leftover duress.enc before it.
func TestWipeRemovesTheDesktopStateFile(t *testing.T) {
	s, _ := newTestServer(t)
	state := filepath.Join(s.store.Dir, desktop.StateFile)

	desktop.LoadState(s.store.Dir).NeedsBackgroundNotice()
	if _, err := os.Stat(state); err != nil {
		t.Fatalf("setup did not write the state file: %v", err)
	}

	s.removeAccountFromDevice()
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("the wipe left desktop.json behind, marking the directory as used")
	}
}
