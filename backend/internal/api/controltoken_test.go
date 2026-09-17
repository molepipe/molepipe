package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// A same-device caller that does not present the control token (a co-installed
// Android app forging Host/Origin, say) must be refused on the /api surface,
// even for the tokenless-by-design status endpoint, while static assets still
// load so the first-party UI can bootstrap and fetch the token.
func TestControlGuardBlocksTokenlessAPI(t *testing.T) {
	s, _ := newTestServer(t)

	// Forge everything a native app can set, but omit the capability token.
	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Host = "127.0.0.1:" + s.port
	req.Header.Set("Origin", s.origin())
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != 403 {
		t.Fatalf("/api/status without control token: got %d, want 403", rr.Code)
	}

	// A wrong token is refused too.
	req = httptest.NewRequest("POST", "/api/unlock", strings.NewReader(`{"password":"x"}`))
	req.Host = "127.0.0.1:" + s.port
	req.Header.Set("Origin", s.origin())
	req.Header.Set("X-Control-Token", "not-the-token")
	rr = httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != 403 {
		t.Fatalf("/api/unlock with wrong control token: got %d, want 403", rr.Code)
	}

	// Static assets stay reachable without the token so the page can load.
	req = httptest.NewRequest("GET", "/", nil)
	req.Host = "127.0.0.1:" + s.port
	rr = httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("static index without token: got %d, want 200", rr.Code)
	}

	// The correct token gets through (status is reachable pre-unlock).
	if rr := s.do(t, "GET", "/api/status", "", nil); rr.Code != 200 {
		t.Fatalf("/api/status with control token: got %d, want 200", rr.Code)
	}
}

// TestExchangeTokenSingleUse covers the cmd/server browser bootstrap: the launch
// URL carries a one-time exchange token (never the durable control token), which
// /control-token trades for the real token exactly once, and only with a valid
// Origin.
func TestExchangeTokenSingleUse(t *testing.T) {
	s, _ := newTestServer(t)

	url := s.BootstrapExchangeURL()
	if strings.Contains(url, s.ControlToken()) {
		t.Fatalf("bootstrap URL leaks the durable control token: %s", url)
	}
	i := strings.Index(url, "?x=")
	if i < 0 {
		t.Fatalf("bootstrap URL has no exchange token: %s", url)
	}
	x := url[i+3:]

	post := func(body string, origin bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/control-token", strings.NewReader(body))
		req.Host = "127.0.0.1:" + s.port
		if origin {
			req.Header.Set("Origin", s.origin())
		}
		rr := httptest.NewRecorder()
		s.routes().ServeHTTP(rr, req)
		return rr
	}

	// A wrong token is refused.
	if rr := post(`{"x":"nope"}`, true); rr.Code != 403 {
		t.Fatalf("wrong exchange token: got %d, want 403", rr.Code)
	}
	// The real token yields the control token, once.
	rr := post(`{"x":"`+x+`"}`, true)
	if rr.Code != 200 {
		t.Fatalf("valid exchange: got %d, want 200 (%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), s.ControlToken()) {
		t.Fatalf("exchange did not return the control token")
	}
	// Spent: replaying the same token is refused.
	if rr := post(`{"x":"`+x+`"}`, true); rr.Code != 403 {
		t.Fatalf("replayed exchange token: got %d, want 403", rr.Code)
	}
	// A fresh token with no Origin (CSRF) is refused by the origin guard.
	url2 := s.BootstrapExchangeURL()
	x2 := url2[strings.Index(url2, "?x=")+3:]
	if rr := post(`{"x":"`+x2+`"}`, false); rr.Code != 403 {
		t.Fatalf("exchange without Origin: got %d, want 403", rr.Code)
	}
}
