package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/duress"
	"github.com/molepipe/molepipe/backend/internal/identity"
)

// dirEntries lists the data directory, for comparing a post-removal state
// against a genuinely fresh install.
func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func TestForgetIdentityFromTheLockScreen(t *testing.T) {
	s, pw := newTestServer(t)
	dir := s.store.Dir
	token := unlockWithPassword(t, s, pw)
	// Give it everything a real install would have.
	enablePIN(t, s, token, pw, testPIN)
	armDuress(t, s, token, pw, testDuressCode)
	s.do(t, "POST", "/api/lock", "", map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + token})

	// No token at all — that is the entire point.
	r := s.do(t, "POST", "/api/forget-identity", `{"confirm":"DELETE"}`,
		map[string]string{"Origin": s.origin()})
	if r.Code != http.StatusOK {
		t.Fatalf("forget: got %d, want 200 (%s)", r.Code, r.Body)
	}

	// The account and every trace of it are gone.
	for _, name := range []string{"identity.enc", "messages.enc", "pin.enc", duress.FileName} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s survived removal (err=%v)", name, err)
		}
	}
	// The app is back to onboarding, not to a lock screen for a dead account.
	status := decode(t, s.do(t, "GET", "/api/status", "", nil).Body)
	if has, _ := status["has_identity"].(bool); has {
		t.Error("status still reports an identity after removal")
	}
	if on, _ := status["pin_enabled"].(bool); on {
		t.Error("status still advertises a PIN after removal")
	}
	// The old credentials open nothing.
	for _, cred := range []string{pw, testDuressCode} {
		if r := s.do(t, "POST", "/api/unlock", `{"password":"`+cred+`"}`,
			map[string]string{"Origin": s.origin()}); r.Code == http.StatusOK {
			t.Errorf("credential %q still unlocks after removal", cred)
		}
	}
}

// The removed device must look like one that never had an account — the same
// check that caught the missing relay/ directory in the duress decoy.
func TestForgetLeavesADirectoryLikeAFreshInstall(t *testing.T) {
	// A genuinely fresh install: server started, no identity ever created.
	freshStore, err := identity.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fresh := New(freshStore, nil)
	if _, err := fresh.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fresh.Shutdown(nil) })

	// A used install, then removed.
	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)
	enablePIN(t, s, token, pw, testPIN)
	armDuress(t, s, token, pw, testDuressCode)
	s.do(t, "POST", "/api/lock", "", map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + token})
	if r := s.do(t, "POST", "/api/forget-identity", `{"confirm":"DELETE"}`,
		map[string]string{"Origin": s.origin()}); r.Code != http.StatusOK {
		t.Fatalf("forget: %d", r.Code)
	}

	got := strings.Join(dirEntries(t, s.store.Dir), ",")
	want := strings.Join(dirEntries(t, freshStore.Dir), ",")
	if got != want {
		t.Errorf("a removed device is distinguishable from a fresh install:\n removed: %s\n fresh:   %s", got, want)
	}
}

// Having the recovery phrase must mean nothing is actually lost.
func TestForgetThenRestoreWithRecoveryPhrase(t *testing.T) {
	store, err := identity.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(id, []byte("forgotten-password")); err != nil {
		t.Fatal(err)
	}
	s := New(store, nil)
	if _, err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(nil) })

	if r := s.do(t, "POST", "/api/forget-identity", `{"confirm":"DELETE"}`,
		map[string]string{"Origin": s.origin()}); r.Code != http.StatusOK {
		t.Fatalf("forget: %d (%s)", r.Code, r.Body)
	}
	// Recover with the phrase and a brand-new password: same account back.
	body, _ := json.Marshal(map[string]string{"mnemonic": id.MnemonicString(), "password": "A-new-password1"})
	rec := s.do(t, "POST", "/api/recover", string(body), map[string]string{"Origin": s.origin()})
	if rec.Code != http.StatusOK {
		t.Fatalf("recover after removal: %d (%s)", rec.Code, rec.Body)
	}
	if acct := decode(t, rec.Body)["account_number"]; acct != id.AccountNumber() {
		t.Fatalf("recovered a different account: %v vs %v", acct, id.AccountNumber())
	}
}

func TestForgetRequiresTypedConfirmationAndOrigin(t *testing.T) {
	s, pw := newTestServer(t)
	_ = pw

	// Wrong or missing confirmation.
	for _, body := range []string{`{}`, `{"confirm":""}`, `{"confirm":"yes"}`, `{"confirm":"DELET"}`} {
		if r := s.do(t, "POST", "/api/forget-identity", body,
			map[string]string{"Origin": s.origin()}); r.Code != http.StatusBadRequest {
			t.Errorf("confirm=%s: got %d, want 400", body, r.Code)
		}
	}
	if !s.store.Exists() {
		t.Fatal("a rejected confirmation must not remove anything")
	}
	// CSRF guard still applies: a malicious page must not be able to wipe the
	// account just because the endpoint takes no token.
	if r := s.do(t, "POST", "/api/forget-identity", `{"confirm":"DELETE"}`, nil); r.Code != http.StatusForbidden {
		t.Errorf("no origin: got %d, want 403", r.Code)
	}
	if r := s.do(t, "POST", "/api/forget-identity", `{"confirm":"DELETE"}`,
		map[string]string{"Origin": "http://evil.example"}); r.Code != http.StatusForbidden {
		t.Errorf("foreign origin: got %d, want 403", r.Code)
	}
	if !s.store.Exists() {
		t.Fatal("a cross-origin request must not remove anything")
	}
}

// Removal while another tab holds an unlocked session must not leave that
// session live with keys for an account whose files are gone.
func TestForgetWhileUnlockedTearsTheSessionDown(t *testing.T) {
	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)

	if r := s.do(t, "POST", "/api/forget-identity", `{"confirm":"DELETE"}`,
		map[string]string{"Origin": s.origin()}); r.Code != http.StatusOK {
		t.Fatalf("forget: %d", r.Code)
	}
	if s.vault.unlocked() {
		t.Error("the vault is still unlocked after removal")
	}
	if r := s.do(t, "GET", "/api/identity", "",
		map[string]string{"Authorization": "Bearer " + token}); r.Code != http.StatusUnauthorized {
		t.Errorf("the old session token still works: got %d, want 401", r.Code)
	}
}

// Removing when there is nothing to remove is not an error.
func TestForgetWithNoIdentityIsHarmless(t *testing.T) {
	store, err := identity.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(store, nil)
	if _, err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(nil) })
	if r := s.do(t, "POST", "/api/forget-identity", `{"confirm":"DELETE"}`,
		map[string]string{"Origin": s.origin()}); r.Code != http.StatusOK {
		t.Fatalf("forget with no identity: got %d, want 200 (%s)", r.Code, r.Body)
	}
}
