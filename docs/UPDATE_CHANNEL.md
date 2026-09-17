# In-app update channel (over `.onion`)

Status: **design** — not yet implemented. This is the spec for the direct /
F-Droid lane's "is there a newer build?" check. Name-independent: it depends on
nothing about the eventual `applicationId`, only on the transport primitives that
already exist.

## Why this shape

The threat model (`docs/THREAT_MODEL.md`) is an anonymity messenger with an
**onion-only transport** — `tor.SocksDialer.DialOnion` reaches `.onion` hosts and
nothing else, and there is no TLS-over-Tor client in the tree. So an update check
that hit GitHub / a clearnet URL would need an **exit hop** (leaves the Tor
network, against the threat model) *and* a new TLS stack we don't have.

The privacy-correct design is therefore: **a signed manifest served from a
self-hosted release `.onion`, fetched with the existing `DialOnion` primitive,
and verified against a release public key pinned in the app binary.** This is the
same trust structure the app already uses for a peer's signed profile card
(`FetchProfile` → `onionClient` → verify against the account key) — reused for
release metadata instead of a peer identity.

Two properties fall out of pinning the key in the client:

- **A malicious or seized release onion cannot forge an update.** It cannot make
  the client act on a manifest it didn't sign, because the signing key lives only
  in the app + on the release-signing machine, never on the onion host.
- **But it *can* freeze you** — this is the one attack a pinned key does not cover,
  and for an anonymity tool it is the important one (pinning everyone at a build
  with a known bug is exactly what an adversary who holds the onion would want).
  A validly-signed *old* manifest, replayed forever, would otherwise have the
  client cheerfully report "up to date." The defense is freshness, not
  signature — see `published_at` handling below.
- **No downgrade / replay.** The client acts only on `version_code` strictly
  greater than *its own* running code (`internal/version` stamped at build time,
  surfaced at `/api/version`). A replayed old signed manifest is inert.

## Two keys, do not conflate

| Key | Lives where | Protects |
|---|---|---|
| **APK signing key** (`~/onion-chat-release.jks`) | your machine; Android holds the public half after first install | Android's *install-time* same-signer rule — that the APK a tester installs over the top is from you |
| **Manifest signing key** (new, Ed25519) | your release machine; **public half compiled into the app** | the *content* of the update check — that the "there's a v42" claim is authentic even though the onion serving it is untrusted |

They answer different questions ("is this APK installable over the old one?" vs.
"is this update notice real?") and must be independent. The manifest key is *not*
the APK key and *not* an account identity key.

## Manifest format

Served at a fixed path on the release onion, e.g.
`GET http://<release-onion>.onion/update/direct.json`. One file per channel
(`direct`, `fdroid`) so the two lanes can move at different cadences.

```json
{
  "ver": 1,
  "channel": "direct",
  "latest": {
    "version_code": 42,
    "version_name": "v0.9.0",
    "notes": "Short human-readable changelog for this release.",
    "apk_url": "http://<release-onion>.onion/dl/onionchat-v0.9.0.apk",
    "apk_sha256": "9f2c…（64 hex）",
    "published_at": "2026-09-01T00:00:00Z"
  },
  "min_supported_code": 30,
  "sig": "base64(ed25519 detached signature)"
}
```

- **`ver`** — manifest-format version, so the parser can evolve. Unlike a profile
  card's `Ver` (an *unauthenticated hint* on an ungated card, which is why
  `candidateVersions` tries every version), `ver` here sits **inside the signed
  payload** — so it is authenticated. The client checks `ver` ∈ its known window
  and rejects out-of-window up front with a clear error, then verifies the
  signature **once**. Do not build the try-every-version path; there is nothing
  to tolerate on an authenticated field.
- **`sig`** — Ed25519 detached signature over the **canonical serialization of
  every field except `sig`**, under a domain-separation context string
  `onionchat-update-manifest-v1` (mirror `protocol.signBlob`'s context-prefix
  convention so this signature can never be cross-purposed with a profile or
  challenge signature). Verified against the pinned release public key.
- **`apk_sha256`** — lets a human verify a directly-downloaded APK matches what
  the (signed) manifest claims, independent of the transport that delivered the
  bytes. Also what the public APK page publishes.
- **`min_supported_code`** — optional floor for a future "you must update, this
  build can no longer talk to the network" nudge. Unused at launch; reserved so
  adding it later is not another format break.
- **`published_at`** — RFC 3339 timestamp, and it is **load-bearing, not
  cosmetic**: the client rejects a manifest older than a freshness window (e.g.
  14 days) and surfaces a distinct **"update check is stale — couldn't reach the
  release service"** state, *not* "you're up to date." This is the only defense
  against the freeze attack above. A re-signed manifest with a current
  `published_at` must be published on a cadence at least inside the window even
  when nothing changed (a heartbeat), so a genuine "no new version" stays fresh
  and only a real denial goes stale. Freshness fails **visibly**; signature fails
  **closed and silently** (treated as no update). They are different states.

## Client flow (notify-only)

The client **never downloads or installs** — it fetches the manifest, compares,
and *notifies*. This is both a policy constraint (Google Play forbids in-app APK
self-install, so the `play` flavor must not contain this code at all) and a
safety one (the user stays in control of what lands on their device; the manifest
hands them the URL + sha256 to verify).

1. **Trigger** — on-demand from a Settings "Check for updates" button, and
   optionally opportunistically once after unlock. **Never from a render path.**
2. **Guard** — only when `onion.Dialable()` is true (outbound Tor is up), exactly
   like the presence sweep. If not dialable, the button says "connect first",
   it does not hang.
3. **Fetch** — `DialOnion` to the pinned release onion, plain framed HTTP GET of
   the channel manifest. Bounded context (a few seconds; caller owns the
   deadline, per `client.go`'s backstop note). No account number, no identity,
   no cookie is sent — an ungated GET over a fresh circuit.
4. **Verify** — check `ver` ∈ window, then verify `sig` once against the pinned
   key. A verify (or parse, or version-out-of-window) failure is treated as "no
   update" — **fail closed, silently**, never an actionable prompt.
5. **Freshness** — reject if `published_at` is older than the freshness window,
   and show the distinct **stale** state ("couldn't reach the release service").
   This is a *visible* failure, unlike step 4 — a freeze must not read as "up to
   date".
6. **Compare** — act only if `latest.version_code` > the **running** versionCode.
   Source of truth for "running" differs by platform, and getting this wrong
   compares the wrong number silently:
   - **Android** — the package manager is authoritative: read
     `PackageInfo.longVersionCode` at startup and hand it into the Go layer. Do
     **not** rely on an ldflags-stamped code here, because `build-aar.sh` runs
     standalone in the common dev path and would carry a stale/absent code while
     the installed APK carries the real one (`build-release-apk.sh` stamps the
     APK via `-PonionVersionCode` but exports only `VERSION` to the AAR build).
   - **Desktop** — there is no package manager, so the ldflags-stamped
     `internal/version` code *is* the source of truth.
7. **Notify** (was 6, below).
   **Notify** — show `version_name` + `notes` + (direct flavor) the `apk_url` and
   `apk_sha256`. On `fdroid` the notice points at F-Droid instead of a URL.

## Flavor gating

- **`direct`** (your key, sideloaded APK): update check **active**, notice links
  to `apk_url`.
- **`fdroid`** (your key, reproducible build): update check **active**, notice
  points at the F-Droid client (F-Droid does the actual updating).
- **`play`** (AAB, Google-signed): update check **compiled out** entirely —
  Google Play is the update mechanism and Play policy forbids the alternative.

The pinned release public key and the release onion address are `BuildConfig` /
build-time constants, so the `play` build simply doesn't include them and the
updater code is behind a flavor source set / build flag.

## What the check reveals (be honest)

The check is a Tor request to *your* release onion. Over Tor it carries no
account number and no stable identity, but the release-onion operator (you) can
see that *some* client fetched the manifest, and roughly when. That is strictly
less than any clearnet updater reveals (no IP, no device fingerprint, no account),
and it is the minimum for "is there a newer build?" to be answerable at all.
Document it plainly in the privacy notes; do not imply the check is invisible.

## Implementation status (2026-09-02)

The **backend engine is built and inert-by-default** — it does nothing until the
release pins are stamped (below), so it ships safely ahead of the infra.

Landed:

- **`internal/version.VersionCode`** — the monotonic integer, injected via
  ldflags (`build-release.sh` derives it as `git rev-list --count HEAD`).
  `version.Code()` parses it (0 on unset/malformed); `/api/version` reports it as
  build metadata. This is the **desktop source of truth** only.
- **`internal/updatecheck`** — the pure, platform-independent engine: canonical
  length-prefixed signing (frozen by a golden test), signature-before-freshness
  verification, channel-subject check, future-timestamp rejection, hex-validated
  `apk_sha256`, and the synchronous `Check` that maps every failure to a
  non-actionable state. Signature/parse/channel failures fail closed as `error`;
  a signed-but-old manifest surfaces as `stale` (the freeze-attack signal).
- **`internal/updatepin`** — the compiled-in pins (`ReleaseOnion`,
  `ManifestPubKeyHex`, `Channel`), EMPTY by default → `Enabled()` false →
  the check reports `disabled`. This is the Go-side flavor gate: the Play flavor
  simply never stamps them.
- **`GET /api/update-check`** (authed) — runs the check and returns the state.
  The **running-code seam** is fail-closed: desktop falls back to
  `version.Code()`; Android must call `Server.SetRunningVersionCode(…)` with
  `PackageInfo.longVersionCode` at startup, and until it does the handler returns
  `unknown` rather than trust the standalone-built (possibly stale) stamp.
- **`cmd/update-manifest`** — the offline signing tool: `-genkey` mints a manifest
  keypair; given the private key + release fields it emits a signed, self-verified
  `<channel>.json`. It fabricates no secret of its own.
- **`build-release.sh`** — stamps `VersionCode`, and arms the pins when
  `RELEASE_ONION` + `MANIFEST_PUBKEY` + `UPDATE_CHANNEL` are all set in the env.

Remaining (in order):

- **Release onion + manifest key generation** — your infra actions, like the APK
  keystore. Run `update-manifest -genkey`, publish the release onion, then stamp
  the onion + public key + channel into the `direct`/`fdroid` builds (the three
  env vars above). I must not fabricate either secret.
- **Android running-code injection + the UI + AAR/APK rebuild** — deliberately
  deferred until the pins exist. The Kotlin layer must call
  `SetRunningVersionCode(PackageInfo.longVersionCode)` at startup, and a
  "Check for updates" control in Settings renders the states. Both need the
  313 MB AAR+APK rebuild, so they land together with the first real pinned build
  rather than shipping an inert button now.
