// Package updatecheck implements the notify-only update mechanism: fetch a
// signed release manifest from the project's own release onion over Tor, verify
// it against a pinned Ed25519 key, and report whether a newer build exists. It
// NEVER downloads or installs anything — the client only compares version codes
// and tells the user. See docs/UPDATE_CHANNEL.md for the full design.
//
// Two failure modes are deliberately asymmetric (UPDATE_CHANNEL.md steps 4–5):
//
//   - A bad signature, parse error, wrong format version, or wrong channel is a
//     FAIL-CLOSED, non-actionable StateError. Anyone can serve bytes at the
//     release path over Tor; only our key can produce a manifest we act on, and
//     a forgery must be indistinguishable from "couldn't check" — never a prompt.
//   - A genuinely-signed manifest that is simply too old is a VISIBLE StateStale.
//     A pinned key cannot forge a manifest, but an on-path party CAN replay an
//     old, validly-signed one to freeze the fleet on a known-vulnerable build;
//     surfacing staleness is the defense against that freeze.
//
// The engine is platform-independent and pure: it takes the running build's
// version code and the current time as arguments so the caller owns the
// platform-specific "which build am I" decision (desktop trusts the ldflags
// stamp; Android must inject PackageInfo.longVersionCode instead).
package updatecheck

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/molepipe/molepipe/backend/internal/tor"
)

const (
	// manifestContext is the signature domain, distinct from the wire-protocol
	// context ("onion-chat/v1") so a signature from one can never be replayed as
	// the other. Frozen by the golden test; a change is a v2 manifest, not an edit.
	manifestContext = "onionchat-update-manifest-v1"

	// Manifest format version window. The single field is advisory today; a
	// layout change ships as v2 with the old layout still accepted here.
	manifestVerMin     = 1
	manifestVerCurrent = 1

	// FreshnessWindow bounds how old a signed manifest may be before it is
	// treated as stale (see the freeze-attack note in the package doc).
	FreshnessWindow = 14 * 24 * time.Hour

	// clockSkewTolerance lets a client whose clock runs behind the signer still
	// accept a just-published manifest. A published_at further into the future
	// than this is rejected outright: a far-future timestamp never ages into
	// staleness, which would defeat the freshness defense with a signed file.
	clockSkewTolerance = 24 * time.Hour

	// maxManifestBytes bounds the fetch, mirroring getJSON's 64 KiB cap. A real
	// manifest is well under 1 KiB.
	maxManifestBytes = 1 << 16

	maxNotesRunes = 2000

	// fetchBackstop caps the fetch even when the caller passes an unbounded
	// context (the shipped handler supplies a 90s ctx, but Check is exported and
	// tested with context.Background()). Mirrors protocol.onionClient's
	// clientBackstopTimeout so a stuck circuit can never hang a caller forever.
	fetchBackstop = 2 * time.Minute
)

// Release is the newest published build described by a manifest.
type Release struct {
	VersionCode int    `json:"version_code"`
	VersionName string `json:"version_name"`
	Notes       string `json:"notes"`
	APKURL      string `json:"apk_url"`
	APKSHA256   string `json:"apk_sha256"`
	PublishedAt string `json:"published_at"` // RFC3339; signed as the exact string
}

// Manifest is the signed document served at the release onion. Every field
// except Sig is covered by the signature (see canonicalBytes).
type Manifest struct {
	Ver              int     `json:"ver"`
	Channel          string  `json:"channel"` // "direct" | "fdroid"
	Latest           Release `json:"latest"`
	MinSupportedCode int     `json:"min_supported_code"`
	Sig              string  `json:"sig"` // base64 detached Ed25519 over canonicalBytes
}

// canonicalBytes serializes every signed field of a manifest into an unambiguous
// blob, in a FIXED order with 4-byte big-endian length prefixes — identical in
// spirit to protocol.signBlob. Length-prefixing makes distinct field sequences
// impossible to collide; the fixed order avoids JSON canonicalization pitfalls
// (key ordering, number formatting, escaping) entirely. published_at is signed
// as its exact string form so timezone/precision reformatting can never change
// the signed bytes. This layout is FROZEN by the golden test — a change is a new
// manifest version, never an edit here.
func canonicalBytes(m Manifest) []byte {
	parts := [][]byte{
		[]byte(manifestContext),
		[]byte(strconv.Itoa(m.Ver)),
		[]byte(m.Channel),
		[]byte(strconv.Itoa(m.Latest.VersionCode)),
		[]byte(m.Latest.VersionName),
		[]byte(m.Latest.Notes),
		[]byte(m.Latest.APKURL),
		[]byte(m.Latest.APKSHA256),
		[]byte(m.Latest.PublishedAt),
		[]byte(strconv.Itoa(m.MinSupportedCode)),
	}
	var b []byte
	var l [4]byte
	for _, p := range parts {
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		b = append(b, l[:]...)
		b = append(b, p...)
	}
	return b
}

// Sign returns the base64 detached signature for a manifest. Used by the offline
// signing tool (cmd/update-manifest) and the round-trip tests; the client only
// ever verifies.
func Sign(m Manifest, priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonicalBytes(m)))
}

// ErrVerify is the single opaque verification failure. Callers map it to
// StateError and MUST NOT surface which check failed — distinguishing a forged
// signature from a malformed field would hand an on-path party an oracle.
var ErrVerify = errors.New("manifest verification failed")

// Verify checks the format version window and the Ed25519 signature. It is the
// fail-closed gate: any problem returns ErrVerify and nothing about the manifest
// should be trusted or shown.
func Verify(m Manifest, pub ed25519.PublicKey) error {
	if m.Ver < manifestVerMin || m.Ver > manifestVerCurrent {
		return ErrVerify
	}
	sig, err := base64.StdEncoding.DecodeString(m.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrVerify
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, canonicalBytes(m), sig) {
		return ErrVerify
	}
	return nil
}

// State is the outcome the UI renders. Only StateAvailable is actionable.
type State string

const (
	StateDisabled  State = "disabled"   // no release onion / key compiled in (dev or Play flavor)
	StateOffline   State = "offline"    // onion not dialable yet — try again once connected
	StateUnknown   State = "unknown"    // running build number unknown (Android without injection)
	StateError     State = "error"      // fetch/parse/verify/channel failure — fail closed, not actionable
	StateUpToDate  State = "up_to_date" // signed, fresh, running >= latest
	StateStale     State = "stale"      // signed but older than FreshnessWindow — release service may be unreachable
	StateAvailable State = "available"  // signed, fresh, a newer build exists
)

// Result is the JSON-serializable verdict. The release fields are populated only
// for StateAvailable — a non-actionable state carries no clickable payload.
type Result struct {
	State       State  `json:"state"`
	VersionName string `json:"version_name,omitempty"`
	VersionCode int    `json:"version_code,omitempty"`
	Notes       string `json:"notes,omitempty"`
	APKURL      string `json:"apk_url,omitempty"`
	APKSHA256   string `json:"apk_sha256,omitempty"`
	PublishedAt string `json:"published_at,omitempty"`
	// Mandatory is true when the running build is below the manifest's
	// min_supported_code — the update is not merely available but effectively
	// required (peers may refuse an old build after a wire break). Advisory to
	// the UI; the client is notify-only either way.
	Mandatory bool `json:"mandatory,omitempty"`
}

// Check runs the whole pipeline synchronously within ctx (no goroutine escapes
// into the caller's session path, keeping -race meaningful). It maps every
// failure to a non-panicking Result. onionHost is the 56-char release onion
// WITHOUT the ".onion" suffix; expectChannel is the flavor's channel and also
// selects the manifest path ("/<channel>.json").
func Check(ctx context.Context, dialer tor.Dialer, onionHost, expectChannel string, pub ed25519.PublicKey, runningCode int, now time.Time) Result {
	m, err := fetch(ctx, dialer, onionHost, expectChannel)
	if err != nil {
		return Result{State: StateError}
	}
	// 1. Signature FIRST, before freshness, so StateStale can only ever describe
	// a genuinely-signed-but-old manifest (the real freeze attack) and never
	// bytes an on-path party synthesized to force a visible "couldn't reach"
	// state. Fail closed, silently.
	if err := Verify(m, pub); err != nil {
		return Result{State: StateError}
	}
	// 2. Subject check: a validly-signed manifest for a DIFFERENT channel served
	// at this path is still the wrong manifest — mirror FetchProfile's account
	// mismatch check (signature valid, wrong subject).
	if m.Channel != expectChannel {
		return Result{State: StateError}
	}
	// 3. Freshness. A malformed or far-future published_at is rejected; older
	// than the window is stale (visible, so the freeze attack is observable).
	published, err := time.Parse(time.RFC3339, m.Latest.PublishedAt)
	if err != nil {
		return Result{State: StateError}
	}
	if published.After(now.Add(clockSkewTolerance)) {
		return Result{State: StateError}
	}
	if now.Sub(published) > FreshnessWindow {
		return Result{State: StateStale}
	}
	// 4. Compare. version_code is the sole authority for "newer"; a well-formed
	// apk_sha256 is required before any release payload reaches the UI.
	if !validHexSHA256(m.Latest.APKSHA256) {
		return Result{State: StateError}
	}
	if m.Latest.VersionCode <= runningCode {
		return Result{State: StateUpToDate}
	}
	return Result{
		State:       StateAvailable,
		VersionName: m.Latest.VersionName,
		VersionCode: m.Latest.VersionCode,
		Notes:       clampNotes(m.Latest.Notes),
		APKURL:      m.Latest.APKURL,
		APKSHA256:   m.Latest.APKSHA256,
		PublishedAt: m.Latest.PublishedAt,
		Mandatory:   runningCode < m.MinSupportedCode,
	}
}

// fetch GETs the channel manifest from the release onion over Tor. It mirrors
// protocol.onionClient (per-onion DialContext, keep-alives disabled) and bounds
// the read like getJSON.
func fetch(ctx context.Context, dialer tor.Dialer, onionHost, channel string) (Manifest, error) {
	onion := onionHost + ".onion:80"
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialOnion(ctx, onion)
			},
			DisableKeepAlives: true,
		},
		Timeout: fetchBackstop,
	}
	url := "http://" + onionHost + ".onion/" + channel + ".json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Manifest{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return Manifest{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Manifest{}, fmt.Errorf("manifest fetch: status %d", resp.StatusCode)
	}
	var m Manifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxManifestBytes)).Decode(&m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// validHexSHA256 reports whether s is exactly 64 lowercase/uppercase hex chars,
// i.e. a syntactically valid SHA-256. Cheap validation before the value reaches
// the UI, in the spirit of clampAvatarHash.
func validHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// clampNotes bounds the release-notes string before it reaches the UI. The
// manifest is signed by our own release key, so this is belt-and-suspenders
// against a mis-invoked signing tool, not an untrusted-peer guard.
func clampNotes(s string) string {
	r := []rune(s)
	if len(r) > maxNotesRunes {
		r = r[:maxNotesRunes]
	}
	return string(r)
}
