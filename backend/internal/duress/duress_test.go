package duress

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

func TestEnsureCreatesInertFile(t *testing.T) {
	dir := t.TempDir()
	if err := Ensure(dir); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); err != nil {
		t.Fatalf("Ensure did not create %s: %v", FileName, err)
	}
}

func TestEnsureIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	if err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	f1, _ := os.Stat(filepath.Join(dir, FileName))
	if err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	f2, _ := os.Stat(filepath.Join(dir, FileName))
	if f1.ModTime() != f2.ModTime() {
		t.Fatal("Ensure modified an existing file")
	}
}

func TestSetRejectsShortCode(t *testing.T) {
	dir := t.TempDir()
	if err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	if err := Set(dir, []byte("12345")); err != ErrTooShort {
		t.Errorf("Set with 5 chars: got %v, want ErrTooShort", err)
	}
}

func TestSetArmsDuressCode(t *testing.T) {
	dir := t.TempDir()
	if err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	code := []byte("panictime")
	if err := Set(dir, code); err != nil {
		t.Fatalf("Set: %v", err)
	}
	id, ok := Check(dir, code)
	if !ok {
		t.Fatal("Check failed for the correct code after Set")
	}
	if id == nil {
		t.Fatal("Check returned nil identity for correct code")
	}
}

func TestCheckRejectsWrongCode(t *testing.T) {
	dir := t.TempDir()
	if err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	if err := Set(dir, []byte("panictime")); err != nil {
		t.Fatal(err)
	}
	id, ok := Check(dir, []byte("wrongcode"))
	if ok {
		t.Fatal("Check succeeded with wrong code")
	}
	if id != nil {
		t.Fatal("Check returned non-nil identity for wrong code")
	}
}

func TestCheckRejectsEmptyDir(t *testing.T) {
	dir := t.TempDir()
	id, ok := Check(dir, []byte("anything"))
	if ok {
		t.Fatal("Check succeeded in empty dir")
	}
	if id != nil {
		t.Fatal("Check returned non-nil identity in empty dir")
	}
}

func TestClearDisarmsCode(t *testing.T) {
	dir := t.TempDir()
	if err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	if err := Set(dir, []byte("panictime")); err != nil {
		t.Fatal(err)
	}
	if err := Clear(dir); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	// The file must still exist (Clear does not remove it).
	if _, err := os.Stat(filepath.Join(dir, FileName)); err != nil {
		t.Fatalf("Clear removed the file: %v", err)
	}
	// The old code must no longer work.
	if _, ok := Check(dir, []byte("panictime")); ok {
		t.Fatal("old code still works after Clear")
	}
}

func TestClearIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	if err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	if err := Clear(dir); err != nil {
		t.Fatal(err)
	}
	if err := Clear(dir); err != nil {
		t.Fatal("Clear on already-cleared dir should not error")
	}
}

func TestFileAlwaysExists(t *testing.T) {
	dir := t.TempDir()
	// Before Ensure, the file does not exist.
	if _, err := os.Stat(filepath.Join(dir, FileName)); err == nil {
		t.Fatal("duress file should not exist in a fresh dir")
	}
	// After Ensure, it does.
	if err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); err != nil {
		t.Fatal("duress file missing after Ensure")
	}
	// After Clear, it still does.
	if err := Clear(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); err != nil {
		t.Fatal("duress file missing after Clear")
	}
}

func TestDecoyIdentityIsDifferent(t *testing.T) {
	dir := t.TempDir()
	// Set a duress code and check the decoy.
	if err := Set(dir, []byte("panictime")); err != nil {
		t.Fatal(err)
	}
	decoy, ok := Check(dir, []byte("panictime"))
	if !ok {
		t.Fatal("Check failed")
	}
	// The decoy must be a valid identity with a real account number.
	acct := decoy.AccountNumber()
	if len(acct) == 0 {
		t.Fatal("decoy has empty account number")
	}
	// Each Set produces a fresh decoy.
	if err := Set(dir, []byte("another1")); err != nil {
		t.Fatal(err)
	}
	decoy2, ok := Check(dir, []byte("another1"))
	if !ok {
		t.Fatal("Check failed for second code")
	}
	if decoy.AccountNumber() == decoy2.AccountNumber() {
		t.Fatal("two successive Set calls produced the same decoy identity")
	}
}

func TestDuressFileIsNotPlaintext(t *testing.T) {
	dir := t.TempDir()
	code := []byte("panictime")
	if err := Set(dir, code); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if strings.Contains(s, "panictime") {
		t.Fatal("duress code found in plaintext in the file")
	}
	if strings.Contains(s, "duress") {
		t.Fatal("the word 'duress' found in the file")
	}
}

func TestWrongPasswordOnInertBlob(t *testing.T) {
	dir := t.TempDir()
	if err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	// The inert blob is sealed under a random 32-byte code. A human-readable
	// password must not open it.
	if _, ok := Check(dir, []byte("password123")); ok {
		t.Fatal("inert blob opened with a human password")
	}
}

func TestSetThenClearThenSet(t *testing.T) {
	dir := t.TempDir()
	if err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	code1 := []byte("firstcode")
	if err := Set(dir, code1); err != nil {
		t.Fatal(err)
	}
	if _, ok := Check(dir, code1); !ok {
		t.Fatal("first code not recognized")
	}
	if err := Clear(dir); err != nil {
		t.Fatal(err)
	}
	if _, ok := Check(dir, code1); ok {
		t.Fatal("first code still works after Clear")
	}
	code2 := []byte("secondc")
	if err := Set(dir, code2); err != nil {
		t.Fatal(err)
	}
	if _, ok := Check(dir, code2); !ok {
		t.Fatal("second code not recognized after re-arm")
	}
}

func TestDecoyAccountNumberIsValid(t *testing.T) {
	dir := t.TempDir()
	if err := Set(dir, []byte("panictime")); err != nil {
		t.Fatal(err)
	}
	decoy, ok := Check(dir, []byte("panictime"))
	if !ok {
		t.Fatal("Check failed")
	}
	// The account number must be 56 lowercase base32 chars (v3 onion format).
	acct := decoy.AccountNumber()
	if len(acct) != 56 {
		t.Errorf("decoy account number length = %d, want 56", len(acct))
	}
	if acct != strings.ToLower(acct) {
		t.Error("decoy account number is not lowercase")
	}
	// Must be parseable back to a public key.
	if _, err := identity.AccountNumberFromString(acct); err != nil {
		t.Errorf("decoy account number not parseable: %v", err)
	}
}
