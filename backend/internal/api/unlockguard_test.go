package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/unlockguard"
)

// setWipePolicy arms (or disarms) the erase-after-failed-unlocks policy.
func setWipePolicy(t *testing.T, s *Server, token, pw string, enabled bool, threshold int) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"action": "wipe-set", "password": pw, "wipe_enabled": enabled, "wipe_threshold": threshold,
	})
	return s.do(t, "POST", "/api/security", string(body),
		map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + token})
}

func wrongUnlock(t *testing.T, s *Server) *httptest.ResponseRecorder {
	t.Helper()
	return s.do(t, "POST", "/api/unlock", `{"password":"not-the-password"}`,
		map[string]string{"Origin": s.origin()})
}

func TestSecurityStatusReportsWipePolicy(t *testing.T) {
	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)

	// Off by default.
	st := decode(t, s.do(t, "GET", "/api/security", "",
		map[string]string{"Authorization": "Bearer " + token}).Body)
	if on, _ := st["wipe_enabled"].(bool); on {
		t.Fatal("wipe policy is on by default")
	}
	if avail, _ := st["wipe_available"].(bool); !avail {
		t.Fatal("wipe policy reported unavailable on a normal test device")
	}

	if r := setWipePolicy(t, s, token, pw, true, 4); r.Code != http.StatusOK {
		t.Fatalf("arm policy: %d (%s)", r.Code, r.Body)
	}
	st = decode(t, s.do(t, "GET", "/api/security", "",
		map[string]string{"Authorization": "Bearer " + token}).Body)
	if on, _ := st["wipe_enabled"].(bool); !on {
		t.Fatal("wipe policy did not report as enabled after arming")
	}
	if thr, _ := st["wipe_threshold"].(float64); int(thr) != 4 {
		t.Fatalf("threshold: got %v, want 4", st["wipe_threshold"])
	}
}

func TestWipePolicyNeedsPasswordAndFloor(t *testing.T) {
	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)

	// Wrong password can't arm it.
	body, _ := json.Marshal(map[string]any{"action": "wipe-set", "password": "nope", "wipe_enabled": true, "wipe_threshold": 5})
	if r := s.do(t, "POST", "/api/security", string(body),
		map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + token}); r.Code != http.StatusUnauthorized {
		t.Fatalf("arm with wrong password: got %d, want 401", r.Code)
	}
	// Below the floor is refused.
	if r := setWipePolicy(t, s, token, pw, true, 2); r.Code != http.StatusBadRequest {
		t.Fatalf("threshold below floor: got %d, want 400 (%s)", r.Code, r.Body)
	}
}

func TestFailedPasswordAttemptsReportRemainingThenErase(t *testing.T) {
	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)
	if r := setWipePolicy(t, s, token, pw, true, 3); r.Code != http.StatusOK {
		t.Fatalf("arm policy: %d (%s)", r.Code, r.Body)
	}

	// First two failures are within the free window (no backoff) and report the
	// countdown.
	for i, wantLeft := range []int{2, 1} {
		r := wrongUnlock(t, s)
		if r.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: got %d, want 401 (%s)", i+1, r.Code, r.Body)
		}
		got := decode(t, r.Body)
		if left, _ := got["attempts_left"].(float64); int(left) != wantLeft {
			t.Fatalf("failure %d: attempts_left=%v, want %d", i+1, got["attempts_left"], wantLeft)
		}
		if wiped, _ := got["wiped"].(bool); wiped {
			t.Fatalf("failure %d erased the account early", i+1)
		}
	}

	// The third failure hits the threshold and erases the account.
	r := wrongUnlock(t, s)
	if r.Code != http.StatusForbidden {
		t.Fatalf("threshold failure: got %d, want 403 (%s)", r.Code, r.Body)
	}
	if wiped, _ := decode(t, r.Body)["wiped"].(bool); !wiped {
		t.Fatal("threshold failure did not report wiped:true")
	}
	// The account is gone: onboarding, and the real password opens nothing.
	if s.store.Exists() {
		t.Fatal("identity survived the erase-after-failed-unlocks trigger")
	}
	status := decode(t, s.do(t, "GET", "/api/status", "", nil).Body)
	if has, _ := status["has_identity"].(bool); has {
		t.Fatal("status still reports an identity after the erase")
	}
	if r := s.do(t, "POST", "/api/unlock", `{"password":"`+pw+`"}`,
		map[string]string{"Origin": s.origin()}); r.Code == http.StatusOK {
		t.Fatal("the old password still unlocks after the erase")
	}
}

func TestSuccessfulUnlockResetsTheCounter(t *testing.T) {
	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)
	if r := setWipePolicy(t, s, token, pw, true, 3); r.Code != http.StatusOK {
		t.Fatalf("arm policy: %d", r.Code)
	}
	// Two failures, then a correct unlock resets the counter.
	wrongUnlock(t, s)
	wrongUnlock(t, s)
	if r := s.do(t, "POST", "/api/unlock", `{"password":"`+pw+`"}`,
		map[string]string{"Origin": s.origin()}); r.Code != http.StatusOK {
		t.Fatalf("correct unlock after failures: %d (%s)", r.Code, r.Body)
	}
	// Two more failures must not erase — the count restarted from zero.
	wrongUnlock(t, s)
	r := wrongUnlock(t, s)
	if r.Code != http.StatusUnauthorized {
		t.Fatalf("after reset, failure got %d, want 401 (not an erase)", r.Code)
	}
	if !s.store.Exists() {
		t.Fatal("the account was erased even though the counter had been reset")
	}
}

// A duress code entered at the prompt must trigger the decoy wipe, never the
// erase-after-N counter — and must work even with the policy armed.
func TestDuressStillWinsOverTheFailedAttemptCounter(t *testing.T) {
	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)
	armDuress(t, s, token, pw, testDuressCode)
	if r := setWipePolicy(t, s, token, pw, true, 3); r.Code != http.StatusOK {
		t.Fatalf("arm policy: %d", r.Code)
	}
	// Entering the duress code returns a (decoy) session, not a failure.
	r := s.do(t, "POST", "/api/unlock", `{"password":"`+testDuressCode+`"}`,
		map[string]string{"Origin": s.origin()})
	if r.Code != http.StatusOK {
		t.Fatalf("duress unlock: got %d, want 200 (%s)", r.Code, r.Body)
	}
	if _, ok := decode(t, r.Body)["session_token"].(string); !ok {
		t.Fatal("duress unlock returned no session token")
	}
}

// Enabling the policy writes unlock_guard.json; a removed device must still be
// indistinguishable from a fresh install afterwards.
func TestForgetAfterArmingWipePolicyMatchesFreshInstall(t *testing.T) {
	freshStore, err := identity.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fresh := New(freshStore, nil)
	if _, err := fresh.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fresh.Shutdown(nil) })

	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)
	if r := setWipePolicy(t, s, token, pw, true, 5); r.Code != http.StatusOK {
		t.Fatalf("arm policy: %d", r.Code)
	}
	// Confirm the file is actually present before removal (else the test proves nothing).
	if _, err := os.Stat(filepath.Join(s.store.Dir, unlockguard.FileName)); err != nil {
		t.Fatalf("expected %s to exist after arming the policy: %v", unlockguard.FileName, err)
	}
	s.do(t, "POST", "/api/lock", "", map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + token})
	if r := s.do(t, "POST", "/api/forget-identity", `{"confirm":"DELETE"}`,
		map[string]string{"Origin": s.origin()}); r.Code != http.StatusOK {
		t.Fatalf("forget: %d (%s)", r.Code, r.Body)
	}

	got := strings.Join(dirEntries(t, s.store.Dir), ",")
	want := strings.Join(dirEntries(t, freshStore.Dir), ",")
	if got != want {
		t.Errorf("a removed device with an armed wipe policy is distinguishable from a fresh install:\n removed: %s\n fresh:   %s", got, want)
	}
}
