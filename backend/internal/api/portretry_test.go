package api

import (
	"net"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

// mobile.Start remembers the loopback port it bound (so the WebView's
// origin-keyed localStorage survives a restart) and asks for it again next
// time. If something else grabbed that port while the app was away, it falls
// back to "127.0.0.1:0" by calling Start a SECOND time on the same *Server.
// That retry only works if a failed Start left the Server untouched — no
// half-registered mux, no stray goroutine, no stale s.port. Exercise exactly
// that sequence; it is the branch a reboot hits in the field and never here.
func TestStartRetriesAfterPortInUse(t *testing.T) {
	// Squat on a port so the first Start cannot have it.
	squatter, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer squatter.Close()
	taken := squatter.Addr().String()

	store, err := identity.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(id, []byte("test-password")); err != nil {
		t.Fatal(err)
	}
	s := New(store, nil)

	if _, err := s.Start(taken); err == nil {
		t.Fatalf("Start(%s) succeeded on a port already in use", taken)
	}
	if s.Port() != "" {
		t.Fatalf("failed Start left s.port = %q; the retry would persist a port nothing is listening on", s.Port())
	}

	url, err := s.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("retry on 127.0.0.1:0 after a failed Start: %v", err)
	}
	t.Cleanup(func() { s.Shutdown(nil) })
	if s.Port() == "" {
		t.Fatal("retry succeeded but s.Port() is empty; mobile.Start would write an empty hint")
	}

	// The retry must have produced a server that actually serves, not just a
	// listener: a half-built mux would show up here and nowhere else.
	c, err := net.Dial("tcp", "127.0.0.1:"+s.Port())
	if err != nil {
		t.Fatalf("dial retried server at %s: %v", url, err)
	}
	c.Close()
}
