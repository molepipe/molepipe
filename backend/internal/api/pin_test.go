package api

import (
	"net/http"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/pin"
)

const testPIN = "135790"

// unlockWithPassword returns a session token for the password path.
func unlockWithPassword(t *testing.T, s *Server, pw string) string {
	t.Helper()
	r := s.do(t, "POST", "/api/unlock", `{"password":"`+pw+`"}`,
		map[string]string{"Origin": s.origin()})
	if r.Code != http.StatusOK {
		t.Fatalf("unlock: got %d, want 200 (%s)", r.Code, r.Body)
	}
	tok, _ := decode(t, r.Body)["session_token"].(string)
	if tok == "" {
		t.Fatal("no session token")
	}
	s.WaitReady()
	return tok
}

func enablePIN(t *testing.T, s *Server, token, pw, code string) {
	t.Helper()
	r := s.do(t, "POST", "/api/security", `{"action":"pin-enable","password":"`+pw+`","code":"`+code+`"}`,
		map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + token})
	if r.Code != http.StatusOK {
		t.Fatalf("enable pin: got %d, want 200 (%s)", r.Code, r.Body)
	}
}

func pinEnabledInStatus(t *testing.T, s *Server) bool {
	t.Helper()
	r := s.do(t, "GET", "/api/status", "", nil)
	on, _ := decode(t, r.Body)["pin_enabled"].(bool)
	return on
}

func TestPINEnableThenUnlock(t *testing.T) {
	s, pw := newTestServer(t)
	if pinEnabledInStatus(t, s) {
		t.Fatal("a fresh install should have no pin shortcut")
	}

	token := unlockWithPassword(t, s, pw)
	acct := decode(t, s.do(t, "GET", "/api/identity", "",
		map[string]string{"Authorization": "Bearer " + token}).Body)["account_number"]
	enablePIN(t, s, token, pw, testPIN)

	if !pinEnabledInStatus(t, s) {
		t.Fatal("/api/status should advertise the shortcut so the UI shows the pin pad")
	}

	// Lock, then come back in with the PIN alone.
	s.do(t, "POST", "/api/lock", "", map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + token})

	r := s.do(t, "POST", "/api/pin/unlock", `{"pin":"`+testPIN+`"}`,
		map[string]string{"Origin": s.origin()})
	if r.Code != http.StatusOK {
		t.Fatalf("pin unlock: got %d, want 200 (%s)", r.Code, r.Body)
	}
	body := decode(t, r.Body)
	pinToken, _ := body["session_token"].(string)
	if pinToken == "" {
		t.Fatal("pin unlock returned no session token")
	}
	if body["account_number"] != acct {
		t.Fatalf("pin unlock yielded a different account: %v vs %v", body["account_number"], acct)
	}
	// The token is a real session: an authenticated route accepts it.
	if r := s.do(t, "GET", "/api/identity", "",
		map[string]string{"Authorization": "Bearer " + pinToken}); r.Code != http.StatusOK {
		t.Fatalf("session from pin unlock: got %d, want 200", r.Code)
	}
}

// The password stays the real secret: it is required to create the shortcut,
// even from an already-unlocked session.
func TestPINEnableRequiresThePassword(t *testing.T) {
	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)

	r := s.do(t, "POST", "/api/security", `{"action":"pin-enable","password":"wrong","code":"`+testPIN+`"}`,
		map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + token})
	if r.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: got %d, want 401", r.Code)
	}
	if pinEnabledInStatus(t, s) {
		t.Fatal("a rejected password must not create a shortcut")
	}
}

func TestPINEnableRequiresSessionAndOrigin(t *testing.T) {
	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)

	// No session token.
	if r := s.do(t, "POST", "/api/security", `{"action":"pin-enable","password":"`+pw+`","code":"`+testPIN+`"}`,
		map[string]string{"Origin": s.origin()}); r.Code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", r.Code)
	}
	// No Origin header — the CSRF guard fails closed.
	if r := s.do(t, "POST", "/api/security", `{"action":"pin-enable","password":"`+pw+`","code":"`+testPIN+`"}`,
		map[string]string{"Authorization": "Bearer " + token}); r.Code != http.StatusForbidden {
		t.Fatalf("no origin: got %d, want 403", r.Code)
	}
	if pinEnabledInStatus(t, s) {
		t.Fatal("no shortcut should exist after rejected requests")
	}
}

func TestPINUnlockIsOriginGuarded(t *testing.T) {
	s, pw := newTestServer(t)
	enablePIN(t, s, unlockWithPassword(t, s, pw), pw, testPIN)

	if r := s.do(t, "POST", "/api/pin/unlock", `{"pin":"`+testPIN+`"}`, nil); r.Code != http.StatusForbidden {
		t.Fatalf("no origin: got %d, want 403", r.Code)
	}
	if r := s.do(t, "POST", "/api/pin/unlock", `{"pin":"`+testPIN+`"}`,
		map[string]string{"Origin": "http://evil.example"}); r.Code != http.StatusForbidden {
		t.Fatalf("foreign origin: got %d, want 403", r.Code)
	}
}

func TestPINUnlockWrongPIN(t *testing.T) {
	s, pw := newTestServer(t)
	enablePIN(t, s, unlockWithPassword(t, s, pw), pw, testPIN)

	r := s.do(t, "POST", "/api/pin/unlock", `{"pin":"000000"}`,
		map[string]string{"Origin": s.origin()})
	if r.Code != http.StatusUnauthorized {
		t.Fatalf("wrong pin: got %d, want 401 (%s)", r.Code, r.Body)
	}
	left, _ := decode(t, r.Body)["attempts_left"].(float64)
	if int(left) != pin.MaxAttempts-1 {
		t.Fatalf("attempts_left: got %v, want %d", left, pin.MaxAttempts-1)
	}
	// The correct PIN still works — the shortcut is not spent.
	if r := s.do(t, "POST", "/api/pin/unlock", `{"pin":"`+testPIN+`"}`,
		map[string]string{"Origin": s.origin()}); r.Code != http.StatusOK {
		t.Fatalf("correct pin after a failure: got %d, want 200", r.Code)
	}
}

func TestPINUnlockWhenNotSetUp(t *testing.T) {
	s, _ := newTestServer(t)
	if r := s.do(t, "POST", "/api/pin/unlock", `{"pin":"`+testPIN+`"}`,
		map[string]string{"Origin": s.origin()}); r.Code != http.StatusConflict {
		t.Fatalf("no shortcut: got %d, want 409", r.Code)
	}
}

func TestPINTooShortIsRejected(t *testing.T) {
	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)
	r := s.do(t, "POST", "/api/security", `{"action":"pin-enable","password":"`+pw+`","code":"1234"}`,
		map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + token})
	if r.Code != http.StatusBadRequest {
		t.Fatalf("short pin: got %d, want 400 (%s)", r.Code, r.Body)
	}
	if pinEnabledInStatus(t, s) {
		t.Fatal("a rejected pin must not create a shortcut")
	}
}

func TestPINDisable(t *testing.T) {
	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)
	enablePIN(t, s, token, pw, testPIN)

	if r := s.do(t, "POST", "/api/security", `{"action":"pin-disable"}`,
		map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + token}); r.Code != http.StatusOK {
		t.Fatalf("disable: got %d, want 200", r.Code)
	}
	if pinEnabledInStatus(t, s) {
		t.Fatal("the shortcut should be gone after disable")
	}
	// The password path is unaffected.
	unlockWithPassword(t, s, pw)
}

// Removing the account must not leave a PIN-openable copy of the mnemonic
// behind.
func TestDeleteIdentityRemovesTheShortcut(t *testing.T) {
	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)
	enablePIN(t, s, token, pw, testPIN)

	if r := s.do(t, "POST", "/api/delete-identity", `{"password":"`+pw+`"}`,
		map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + token}); r.Code != http.StatusOK {
		t.Fatalf("delete identity: got %d, want 200 (%s)", r.Code, r.Body)
	}
	if s.pin.Exists() {
		t.Fatal("pin.enc survived account removal")
	}
	if r := s.do(t, "POST", "/api/pin/unlock", `{"pin":"`+testPIN+`"}`,
		map[string]string{"Origin": s.origin()}); r.Code != http.StatusConflict {
		t.Fatalf("pin unlock after removal: got %d, want 409", r.Code)
	}
}
