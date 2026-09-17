package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/updatecheck"
	"github.com/molepipe/molepipe/backend/internal/version"
)

// TestUpdateCheckDisabledByDefault proves the wiring and the safe default: with
// no release pins compiled in (the only state that exists in tests and dev
// builds, and the Play flavor), the handler reports "disabled" and never touches
// the onion or the network.
func TestUpdateCheckDisabledByDefault(t *testing.T) {
	store, err := identity.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(store, nil) // nil onion: must not be dereferenced on the disabled path

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/update-check", nil)
	s.handleUpdateCheck(rr, req, nil) // identity is unused by this handler

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var res updatecheck.Result
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.State != updatecheck.StateDisabled {
		t.Fatalf("state = %q, want %q (no pins built in)", res.State, updatecheck.StateDisabled)
	}
}

// TestResolveRunningCode checks the desktop-fallback and injected-code branches.
// The Android fail-closed branch is not reachable off-android and is covered by
// inspection (runtime.GOOS gate).
func TestResolveRunningCode(t *testing.T) {
	store, err := identity.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(store, nil)

	// Default (-1) on this desktop host falls back to the ldflags stamp.
	if code, ok := s.resolveRunningCode(); !ok || code != version.Code() {
		t.Fatalf("default resolveRunningCode = (%d,%v), want (%d,true)", code, ok, version.Code())
	}

	// An injected code wins.
	s.SetRunningVersionCode(4242)
	if code, ok := s.resolveRunningCode(); !ok || code != 4242 {
		t.Fatalf("injected resolveRunningCode = (%d,%v), want (4242,true)", code, ok)
	}

	// The setter is called at startup while the reader runs on an HTTP goroutine,
	// so the two genuinely cross goroutines in production. Exercise that crossing
	// here so `go test -race` fails if runningVersionCode ever reverts to a plain
	// int — the earlier same-goroutine assertions would pass vacuously otherwise.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			s.SetRunningVersionCode(i)
		}
		close(done)
	}()
	for i := 0; i < 1000; i++ {
		s.resolveRunningCode()
	}
	<-done
}
