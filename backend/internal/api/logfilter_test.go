package api

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRoutineLocalKeepsEverythingWorthReading(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		path    string
		status  int
		dur     time.Duration
		routine bool
	}{
		{"a poll tick", "GET", "/api/contacts", 200, time.Millisecond, true},
		// The shell is kept: GET / marks an app relaunch, and these are ~90 lines
		// per log rather than the 53k the poll cycle was contributing.
		{"the shell loading", "GET", "/app.js", 200, 2 * time.Millisecond, false},
		{"a relaunch", "GET", "/", 200, time.Millisecond, false},
		{"a poll that 401s after lock", "GET", "/api/identity", 401, time.Millisecond, false},
		{"a poll that stalled", "GET", "/api/messages", 200, time.Second, false},
		{"sending a message", "POST", "/api/messages", 200, time.Millisecond, false},
		{"fetching an image", "GET", "/api/attachment", 200, time.Millisecond, false},
		{"an avatar", "GET", "/api/avatar", 200, time.Millisecond, false},
		{"a missing asset", "GET", "/nope.js", 404, time.Millisecond, false},
		{"an unlock", "POST", "/api/unlock", 200, 50 * time.Millisecond, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(c.method, c.path, nil)
			if got := routineLocal(r, c.status, c.dur); got != c.routine {
				t.Errorf("routineLocal(%s %s -> %d in %v) = %v, want %v", c.method, c.path, c.status, c.dur, got, c.routine)
			}
		})
	}
}

// The filter must never touch the onion-facing listener: peer traffic is the
// whole diagnostic value of the log. A bare GET / there is the reachability
// probe that proves our descriptor is being served, and /p2p/profile is a peer
// polling us — both share a path shape with filtered local routes, so this
// guards against the quiet-list being applied to the wrong chain.
func TestPublicListenerLogsEveryPeerRequest(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	flags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() { log.SetOutput(old); log.SetFlags(flags) }()

	h := logRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for _, p := range []string{"/", "/p2p/profile", "/p2p/friend-accept"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", p, nil))
	}
	out := buf.String()
	for _, want := range []string{"GET / -> 200", "GET /p2p/profile -> 200", "GET /p2p/friend-accept -> 200"} {
		if !strings.Contains(out, want) {
			t.Errorf("the public listener dropped %q from the log; got:\n%s", want, out)
		}
	}
}

// A quiet request writes nothing until the rollup window is up, and then writes
// exactly one line carrying the count.
func TestRoutineLocalRequestsRollUpInsteadOfLogging(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	flags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() { log.SetOutput(old); log.SetFlags(flags) }()

	quietCount.Store(0)
	quietSince.Store(0)

	h := logLocalRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for i := 0; i < 20; i++ {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/contacts", nil))
	}
	// Assert the absence of the polls themselves, not an empty buffer: log
	// output is process-global and this package's other tests leave background
	// goroutines (watchdog, mailbox loop, outbox retry) logging as they go.
	if out := buf.String(); strings.Contains(out, "/api/contacts") {
		t.Fatalf("routine polls were logged individually:\n%s", out)
	}

	// Backdate the window past the rollup interval; the next poll flushes it.
	quietSince.Store(time.Now().Add(-2 * quietRollup).UnixNano())
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/contacts", nil))
	if out := buf.String(); !strings.Contains(out, "21 routine local-UI requests") {
		t.Errorf("want a rollup line counting all 21 suppressed requests, got:\n%s", out)
	}

	// Something worth reading still goes straight to the log.
	buf.Reset()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/messages", nil))
	if out := buf.String(); !strings.Contains(out, "POST /api/messages -> 200") {
		t.Errorf("a mutating request was filtered out; got:\n%s", out)
	}
}
