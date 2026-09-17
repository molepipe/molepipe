package updatecheck

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// goldManifest is a fixed, deterministic manifest whose canonical bytes are
// frozen below. It must never depend on keys or the clock.
func goldManifest() Manifest {
	return Manifest{
		Ver:     1,
		Channel: "direct",
		Latest: Release{
			VersionCode: 42,
			VersionName: "1.2.3",
			Notes:       "golden notes",
			APKURL:      "http://releaseonion.onion/onion-chat-1.2.3.apk",
			APKSHA256:   "0000000000000000000000000000000000000000000000000000000000000000",
			PublishedAt: "2026-09-01T00:00:00Z",
		},
		MinSupportedCode: 10,
	}
}

// TestCanonicalGolden freezes the ABSOLUTE bytes of the v1 canonical manifest
// layout. Every sign→verify round-trip test passes even if two fields are
// swapped in canonicalBytes (signer and verifier drift together and still
// agree); only a frozen literal catches that silent drift, after which the
// release machine and the fleet would disagree forever about what was signed. A
// change here is a NEW manifest version, never an edit to the constant.
func TestCanonicalGolden(t *testing.T) {
	got := hex.EncodeToString(canonicalBytes(goldManifest()))
	// "" triggers a generation pass: run the test, copy the logged value here.
	const want = goldCanonicalHex
	if want == "" {
		t.Logf("GOLDEN canonical = %q", got)
		return
	}
	if got != want {
		t.Fatalf("canonical bytes drifted:\n got  %s\n want %s\n(a wire change ships as a new manifest version, not an edit here)", got, want)
	}
}

// Frozen 2026-09-02 against the known-correct v1 canonical layout (round-trip
// tests green). A change to canonicalBytes (field order, encoding, context) is a
// new manifest version, not an edit to this constant.
const goldCanonicalHex = "0000001c6f6e696f6e636861742d7570646174652d6d616e69666573742d763100000001310000000664697265637400000002343200000005312e322e330000000c676f6c64656e206e6f7465730000002e687474703a2f2f72656c656173656f6e696f6e2e6f6e696f6e2f6f6e696f6e2d636861742d312e322e332e61706b000000403030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303000000014323032362d30392d30315430303a30303a30305a000000023130"

// TestContextDistinct asserts the manifest signature domain cannot be confused
// with the wire-protocol domain — a signature valid in one must be invalid in
// the other. Mirrors protocol.TestSigContextForV2IsReserved's distinctness check.
func TestContextDistinct(t *testing.T) {
	for _, other := range []string{"onion-chat/v1", "onion-chat/v2"} {
		if manifestContext == other {
			t.Fatalf("manifest context %q collides with wire context %q", manifestContext, other)
		}
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	m := goldManifest()
	m.Sig = Sign(m, priv)
	if err := Verify(m, pub); err != nil {
		t.Fatalf("Verify of freshly signed manifest failed: %v", err)
	}
}

func TestVerifyRejectsTamper(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	m := goldManifest()
	m.Sig = Sign(m, priv)
	m.Latest.VersionCode = 99 // change a signed field after signing
	if err := Verify(m, pub); err == nil {
		t.Fatal("Verify accepted a manifest tampered after signing")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	m := goldManifest()
	m.Sig = Sign(m, priv)
	if err := Verify(m, otherPub); err == nil {
		t.Fatal("Verify accepted a manifest signed by a different key")
	}
}

func TestVerifyRejectsUnsupportedFormatVersion(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	m := goldManifest()
	m.Ver = 2 // outside [1,1]
	m.Sig = Sign(m, priv)
	if err := Verify(m, pub); err == nil {
		t.Fatal("Verify accepted an unsupported manifest format version")
	}
}

// --- Check pipeline via a fake onion dialer routed to an httptest server ---

// fakeDialer routes every DialOnion to a fixed backend address, so the whole
// HTTP path in Check runs against a local test server regardless of the .onion
// host the URL names.
type fakeDialer struct{ backend string }

func (d fakeDialer) DialOnion(ctx context.Context, _ string) (net.Conn, error) {
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", d.backend)
}

// serve starts a test server returning body for GET /<channel>.json (404
// otherwise) and returns a dialer pointing at it.
func serve(t *testing.T, channel string, body []byte) fakeDialer {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+channel+".json" {
			w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return fakeDialer{backend: u.Host}
}

func signedJSON(t *testing.T, m Manifest, priv ed25519.PrivateKey) []byte {
	t.Helper()
	m.Sig = Sign(m, priv)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCheckAvailable(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	m := goldManifest()
	m.Latest.PublishedAt = now.Add(-time.Hour).Format(time.RFC3339)
	m.Latest.APKSHA256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	d := serve(t, "direct", signedJSON(t, m, priv))

	res := Check(context.Background(), d, "releaseonion", "direct", pub, 41 /* running < 42 */, now)
	if res.State != StateAvailable {
		t.Fatalf("state = %q, want available", res.State)
	}
	if res.VersionCode != 42 || res.VersionName != "1.2.3" {
		t.Fatalf("release fields not populated: %+v", res)
	}
	if res.Mandatory { // running 41 >= min_supported_code 10 → not mandatory
		t.Fatalf("Mandatory should be false when running >= min_supported_code: %+v", res)
	}
}

func TestCheckMandatoryWhenBelowFloor(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	m := goldManifest()
	m.MinSupportedCode = 40
	m.Latest.PublishedAt = now.Add(-time.Hour).Format(time.RFC3339)
	m.Latest.APKSHA256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	d := serve(t, "direct", signedJSON(t, m, priv))

	res := Check(context.Background(), d, "releaseonion", "direct", pub, 20 /* below floor 40 */, now)
	if res.State != StateAvailable || !res.Mandatory {
		t.Fatalf("want available+mandatory, got %+v", res)
	}
}

func TestCheckUpToDate(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	m := goldManifest()
	m.Latest.PublishedAt = now.Add(-time.Hour).Format(time.RFC3339)
	m.Latest.APKSHA256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	d := serve(t, "direct", signedJSON(t, m, priv))

	res := Check(context.Background(), d, "releaseonion", "direct", pub, 42 /* == latest */, now)
	if res.State != StateUpToDate {
		t.Fatalf("state = %q, want up_to_date", res.State)
	}
	if res.APKURL != "" {
		t.Fatalf("non-actionable result must not carry a payload: %+v", res)
	}
}

func TestCheckStaleWhenOld(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	m := goldManifest()
	m.Latest.PublishedAt = now.Add(-30 * 24 * time.Hour).Format(time.RFC3339) // > 14d
	m.Latest.APKSHA256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	d := serve(t, "direct", signedJSON(t, m, priv))

	res := Check(context.Background(), d, "releaseonion", "direct", pub, 1, now)
	if res.State != StateStale {
		t.Fatalf("state = %q, want stale (signed but old)", res.State)
	}
}

func TestCheckRejectsFuturePublishedAt(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	m := goldManifest()
	m.Latest.PublishedAt = now.Add(60 * 24 * time.Hour).Format(time.RFC3339) // far future
	m.Latest.APKSHA256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	d := serve(t, "direct", signedJSON(t, m, priv))

	res := Check(context.Background(), d, "releaseonion", "direct", pub, 1, now)
	if res.State != StateError {
		t.Fatalf("state = %q, want error (a never-aging manifest defeats freshness)", res.State)
	}
}

func TestCheckRejectsWrongChannel(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	m := goldManifest()
	m.Channel = "fdroid" // validly signed, but for the wrong channel
	m.Latest.PublishedAt = now.Add(-time.Hour).Format(time.RFC3339)
	// serve it at the DIRECT path so fetch succeeds and the subject check is what rejects.
	d := serve(t, "direct", signedJSON(t, m, priv))

	res := Check(context.Background(), d, "releaseonion", "direct", pub, 1, now)
	if res.State != StateError {
		t.Fatalf("state = %q, want error (wrong-channel manifest)", res.State)
	}
}

func TestCheckRejectsTamperedSig(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	m := goldManifest()
	m.Latest.PublishedAt = now.Add(-time.Hour).Format(time.RFC3339)
	m.Sig = Sign(m, priv)
	m.Latest.VersionCode = 999 // change after signing
	b, _ := json.Marshal(m)
	d := serve(t, "direct", b)

	res := Check(context.Background(), d, "releaseonion", "direct", pub, 1, now)
	if res.State != StateError {
		t.Fatalf("state = %q, want error (tampered manifest must fail closed, not prompt)", res.State)
	}
}

func TestCheckRejectsBadSHA256(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	m := goldManifest()
	m.Latest.PublishedAt = now.Add(-time.Hour).Format(time.RFC3339)
	m.Latest.APKSHA256 = "not-hex"
	d := serve(t, "direct", signedJSON(t, m, priv))

	res := Check(context.Background(), d, "releaseonion", "direct", pub, 1, now)
	if res.State != StateError {
		t.Fatalf("state = %q, want error (malformed apk_sha256)", res.State)
	}
}
