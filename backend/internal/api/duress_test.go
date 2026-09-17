package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/duress"
)

const testDuressCode = "911911"

func armDuress(t *testing.T, s *Server, token, pw, code string) {
	t.Helper()
	r := s.do(t, "POST", "/api/security", `{"action":"duress-set","password":"`+pw+`","code":"`+code+`"}`,
		map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + token})
	if r.Code != http.StatusOK {
		t.Fatalf("arm duress: got %d, want 200 (%s)", r.Code, r.Body)
	}
}

func TestDuressCodeWipesAndOpensDecoy(t *testing.T) {
	s, pw := newTestServer(t)
	dir := s.store.Dir
	token := unlockWithPassword(t, s, pw)
	realAccount, _ := decode(t, s.do(t, "GET", "/api/identity", "",
		map[string]string{"Authorization": "Bearer " + token}).Body)["account_number"].(string)

	// Seed the state that must not survive: a contact, and a PIN shortcut.
	s.do(t, "POST", "/api/contacts", `{"account":"`+realAccount+`","name":"x"}`,
		map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + token})
	enablePIN(t, s, token, pw, testPIN)
	armDuress(t, s, token, pw, testDuressCode)

	messages := filepath.Join(dir, "messages.enc")
	realMessages, err := os.ReadFile(messages)
	if err != nil {
		t.Fatalf("expected messages.enc to exist before the wipe: %v", err)
	}
	realCipher, err := os.ReadFile(s.store.Path())
	if err != nil {
		t.Fatal(err)
	}

	s.do(t, "POST", "/api/lock", "", map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + token})

	// Enter the duress code at the ordinary password prompt.
	r := s.do(t, "POST", "/api/unlock", `{"password":"`+testDuressCode+`"}`,
		map[string]string{"Origin": s.origin()})
	s.WaitReady()

	// It must look exactly like a successful unlock: same status, same fields.
	if r.Code != http.StatusOK {
		t.Fatalf("duress unlock: got %d, want 200 — an error is a tell (%s)", r.Code, r.Body)
	}
	body := decode(t, r.Body)
	decoyAccount, _ := body["account_number"].(string)
	if tok, _ := body["session_token"].(string); tok == "" || decoyAccount == "" {
		t.Fatalf("duress unlock must return the same shape as a real unlock: %v", body)
	}
	if decoyAccount == realAccount {
		t.Fatal("the decoy must not be the real account")
	}
	for _, k := range []string{"duress", "decoy", "wiped", "panic"} {
		if strings.Contains(strings.ToLower(r.Body.String()), k) {
			t.Fatalf("response leaks %q: %s", k, r.Body)
		}
	}

	// The real data is gone. messages.enc exists again — the decoy's session
	// enrolls its device and writes one, exactly as a genuinely fresh account
	// does, so its ABSENCE would be the anomaly. What matters is that it no
	// longer holds the real account's contents.
	nowMessages, err := os.ReadFile(messages)
	if err != nil {
		t.Fatalf("a fresh account would have written messages.enc; its absence is a tell: %v", err)
	}
	if string(nowMessages) == string(realMessages) {
		t.Error("messages.enc still holds the real account's contacts and history")
	}
	decoyToken, _ := body["session_token"].(string)
	contacts := s.do(t, "GET", "/api/contacts", "",
		map[string]string{"Authorization": "Bearer " + decoyToken}).Body.String()
	if strings.Contains(contacts, realAccount) {
		t.Errorf("the decoy session still shows the real account's contacts: %s", contacts)
	}
	// The data directory must be shape-identical to a genuinely fresh account:
	// same files present, none missing. relay/ in particular is created by a new
	// install, so a decoy without it stands out under a directory comparison.
	for _, name := range []string{"identity.enc", "duress.enc", "device.json", "messages.enc", "relay"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("a fresh account would have %s; its absence is a tell: %v", name, err)
		}
	}
	// The PIN shortcut is not recreated: the decoy has no PIN, like any new account.
	if _, err := os.Stat(filepath.Join(dir, "pin.enc")); !os.IsNotExist(err) {
		t.Error("the PIN shortcut survived the duress wipe")
	}
	// identity.enc still exists — but it is the decoy, and the real ciphertext
	// was scrubbed rather than merely unlinked.
	nowCipher, err := os.ReadFile(s.store.Path())
	if err != nil {
		t.Fatalf("identity.enc must exist after the wipe (its absence is the tell): %v", err)
	}
	if string(nowCipher) == string(realCipher) {
		t.Fatal("identity.enc still holds the real identity")
	}

	// The real password no longer opens anything.
	if r := s.do(t, "POST", "/api/unlock", `{"password":"`+pw+`"}`,
		map[string]string{"Origin": s.origin()}); r.Code == http.StatusOK {
		t.Fatal("the real password still unlocks after a duress wipe")
	}
}

// Entering the duress code a second time must be an ordinary unlock of the
// decoy, not another wipe — otherwise a coercer who makes you unlock twice sees
// a different account the second time.
func TestDuressCodeIsStableAcrossRepeats(t *testing.T) {
	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)
	armDuress(t, s, token, pw, testDuressCode)
	s.do(t, "POST", "/api/lock", "", map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + token})

	first := decode(t, s.do(t, "POST", "/api/unlock", `{"password":"`+testDuressCode+`"}`,
		map[string]string{"Origin": s.origin()}).Body)["account_number"]
	tok2, _ := decode(t, s.do(t, "POST", "/api/unlock", `{"password":"`+testDuressCode+`"}`,
		map[string]string{"Origin": s.origin()}).Body)["session_token"].(string)
	_ = tok2
	second := decode(t, s.do(t, "POST", "/api/unlock", `{"password":"`+testDuressCode+`"}`,
		map[string]string{"Origin": s.origin()}).Body)["account_number"]

	if first == nil || first != second {
		t.Fatalf("the decoy account must be stable across repeats: %v then %v", first, second)
	}
}

// The panic code has to work at the PIN prompt too — including while the PIN is
// throttled, which is the state after someone has been forcing guesses.
func TestDuressWorksAtThePINPromptEvenWhenThrottled(t *testing.T) {
	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)
	enablePIN(t, s, token, pw, testPIN)
	armDuress(t, s, token, pw, testDuressCode)
	s.do(t, "POST", "/api/lock", "", map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + token})

	// Burn enough wrong PINs to open a backoff window.
	for range 3 {
		s.do(t, "POST", "/api/pin/unlock", `{"pin":"000000"}`, map[string]string{"Origin": s.origin()})
	}
	if r := s.do(t, "POST", "/api/pin/unlock", `{"pin":"`+testPIN+`"}`,
		map[string]string{"Origin": s.origin()}); r.Code != http.StatusTooManyRequests {
		t.Fatalf("expected the PIN to be throttled first, got %d", r.Code)
	}

	r := s.do(t, "POST", "/api/pin/unlock", `{"pin":"`+testDuressCode+`"}`,
		map[string]string{"Origin": s.origin()})
	if r.Code != http.StatusOK {
		t.Fatalf("duress at a throttled PIN prompt: got %d, want 200 (%s)", r.Code, r.Body)
	}
	// The shortcut the coercer was guessing against is gone with everything else.
	if _, err := os.Stat(filepath.Join(s.store.Dir, "pin.enc")); !os.IsNotExist(err) {
		t.Error("the PIN shortcut survived a duress wipe from the PIN prompt")
	}
	if r := s.do(t, "POST", "/api/unlock", `{"password":"`+pw+`"}`,
		map[string]string{"Origin": s.origin()}); r.Code == http.StatusOK {
		t.Error("the real password still unlocks after a duress wipe from the PIN prompt")
	}
}

// The blob must exist whether or not a code is armed. If it only appeared for
// users who configured one, its presence on disk would announce that a panic
// code exists — the exact fact the feature has to hide.
func TestDuressBlobExistsEvenWhenUnarmed(t *testing.T) {
	s, pw := newTestServer(t)
	blob := filepath.Join(s.store.Dir, duress.FileName)
	if _, err := os.Stat(blob); !os.IsNotExist(err) {
		t.Fatal("precondition: no blob before the first unlock")
	}
	unlockWithPassword(t, s, pw)
	if _, err := os.Stat(blob); err != nil {
		t.Fatalf("an unarmed install must still carry a duress blob: %v", err)
	}
	// And it must be inert: nothing should trigger a wipe.
	if _, ok := s.checkDuress("123456"); ok {
		t.Fatal("the inert blob matched a guessable code")
	}
}

// An armed blob and an unarmed one must be indistinguishable by shape, and both
// indistinguishable from a real identity file.
func TestDuressBlobIsShapeIdenticalToIdentity(t *testing.T) {
	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)
	blob := filepath.Join(s.store.Dir, duress.FileName)

	unarmed, err := os.ReadFile(blob)
	if err != nil {
		t.Fatal(err)
	}
	armDuress(t, s, token, pw, testDuressCode)
	armed, err := os.ReadFile(blob)
	if err != nil {
		t.Fatal(err)
	}
	realID, err := os.ReadFile(s.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	keys := func(b []byte) []string {
		var out []string
		for _, line := range strings.Split(string(b), "\n") {
			if i := strings.Index(line, `":`); i > 0 {
				out = append(out, strings.TrimSpace(line[:i+1]))
			}
		}
		return out
	}
	u, a, r := strings.Join(keys(unarmed), ","), strings.Join(keys(armed), ","), strings.Join(keys(realID), ",")
	if u != a {
		t.Errorf("armed and unarmed blobs differ in shape:\n unarmed %s\n armed   %s", u, a)
	}
	if a != r {
		t.Errorf("the duress blob is distinguishable from identity.enc:\n duress   %s\n identity %s", a, r)
	}
}

// A duress code that could never fire is refused rather than silently accepted.
func TestDuressRefusesCodesThatWouldNeverFire(t *testing.T) {
	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)
	hdr := map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + token}

	// Same as the password: the password wins, so it would never trigger.
	if r := s.do(t, "POST", "/api/security", `{"action":"duress-set","password":"`+pw+`","code":"`+pw+`"}`, hdr); r.Code != http.StatusBadRequest {
		t.Fatalf("code == password: got %d, want 400", r.Code)
	}
	// Same as the PIN: the PIN wins at its own prompt.
	enablePIN(t, s, token, pw, testPIN)
	if r := s.do(t, "POST", "/api/security", `{"action":"duress-set","password":"`+pw+`","code":"`+testPIN+`"}`, hdr); r.Code != http.StatusBadRequest {
		t.Fatalf("code == pin: got %d, want 400", r.Code)
	}
	// Too short.
	if r := s.do(t, "POST", "/api/security", `{"action":"duress-set","password":"`+pw+`","code":"1234"}`, hdr); r.Code != http.StatusBadRequest {
		t.Fatalf("short code: got %d, want 400", r.Code)
	}
	// Wrong password.
	if r := s.do(t, "POST", "/api/security", `{"action":"duress-set","password":"nope","code":"`+testDuressCode+`"}`, hdr); r.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: got %d, want 401", r.Code)
	}
}

func TestDuressDisableStopsTheWipe(t *testing.T) {
	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)
	armDuress(t, s, token, pw, testDuressCode)
	if r := s.do(t, "POST", "/api/security", `{"action":"duress-clear"}`,
		map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + token}); r.Code != http.StatusOK {
		t.Fatalf("disable: got %d, want 200", r.Code)
	}
	s.do(t, "POST", "/api/lock", "", map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + token})

	if r := s.do(t, "POST", "/api/unlock", `{"password":"`+testDuressCode+`"}`,
		map[string]string{"Origin": s.origin()}); r.Code != http.StatusUnauthorized {
		t.Fatalf("a cleared duress code must just fail: got %d, want 401", r.Code)
	}
	// And the real password still works.
	unlockWithPassword(t, s, pw)
}

// Setup is origin-guarded and requires a session, like every other mutation.
func TestDuressSetupRequiresSessionAndOrigin(t *testing.T) {
	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)
	body := `{"action":"duress-set","password":"` + pw + `","code":"` + testDuressCode + `"}`
	if r := s.do(t, "POST", "/api/security", body, map[string]string{"Origin": s.origin()}); r.Code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", r.Code)
	}
	if r := s.do(t, "POST", "/api/security", body,
		map[string]string{"Authorization": "Bearer " + token}); r.Code != http.StatusForbidden {
		t.Fatalf("no origin: got %d, want 403", r.Code)
	}
}

// /api/status is tokenless and reachable before unlocking. It must never hint
// that a duress code exists.
func TestStatusNeverLeaksDuressState(t *testing.T) {
	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)
	armDuress(t, s, token, pw, testDuressCode)
	body := s.do(t, "GET", "/api/status", "", nil).Body.String()
	for _, k := range []string{"duress", "decoy", "panic"} {
		if strings.Contains(strings.ToLower(body), k) {
			t.Fatalf("/api/status leaks %q: %s", k, body)
		}
	}
}

// The request logger records paths. If duress setup had a path of its own, the
// log would tell anyone who reads it that a panic code exists — which is the
// fact the feature exists to hide, and it outlives the setup screen. PIN and
// duress changes must therefore share one path, so the logged line is ambiguous.
func TestDuressSetupSharesAPathWithOrdinarySettings(t *testing.T) {
	s, pw := newTestServer(t)
	token := unlockWithPassword(t, s, pw)
	hdr := map[string]string{"Origin": s.origin(), "Authorization": "Bearer " + token}

	// No route may name duress. A 404 here is the point.
	for _, p := range []string{"/api/duress/enable", "/api/duress/disable", "/api/duress"} {
		if r := s.do(t, "POST", p, `{"password":"`+pw+`","code":"`+testDuressCode+`"}`, hdr); r.Code != http.StatusNotFound {
			t.Errorf("%s should not exist as a route (got %d) — it would name the feature in the log", p, r.Code)
		}
	}
	// The shared path serves both, so the log line cannot discriminate.
	if r := s.do(t, "POST", "/api/security", `{"action":"pin-enable","password":"`+pw+`","code":"`+testPIN+`"}`, hdr); r.Code != http.StatusOK {
		t.Fatalf("pin via the shared path: %d (%s)", r.Code, r.Body)
	}
	if r := s.do(t, "POST", "/api/security", `{"action":"duress-set","password":"`+pw+`","code":"`+testDuressCode+`"}`, hdr); r.Code != http.StatusOK {
		t.Fatalf("duress via the shared path: %d (%s)", r.Code, r.Body)
	}
	// And it really did arm.
	if _, ok := s.checkDuress(testDuressCode); !ok {
		t.Fatal("the duress code was not armed through the shared path")
	}
}
