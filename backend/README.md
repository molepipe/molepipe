# backend — Molepipe core

Portable Go backend for a local-first, zero-knowledge messenger. Kept free of
desktop/UI/OS-process assumptions so it can later be `gomobile bind`-wrapped for
Android without a rewrite.

## Layout

```
cmd/tormsg/        CLI test harness (create / unlock / recover / selftest)
cmd/server/        localhost HTTP server + Arti onion-service sidecar (headless entrypoint)
cmd/desktop/       the same server in a Wails window with a tray icon (desktop entrypoint)
cmd/mailbox/       standalone mailbox server (env-configured; Docker-friendly)
cmd/update-manifest/  offline signing tool for update manifests
internal/crypto/   BIP39, SLIP-0010 Ed25519 derivation, Argon2id KDF, AES-256-GCM
internal/identity/ account-number derivation + encrypted identity.enc storage
internal/api/      loopback HTTP API + embedded unlock UI
internal/tor/      OnionService interface + onion-key derivation/keystore encoding (portable)
internal/torsidecar/ Arti child-process manager (desktop-only; uses os/exec)
internal/protocol/  peer protocol: signed challenge handshake, messages, friend
                    requests, mailbox/relay envelopes, delete-for-everyone
internal/chatstore/ encrypted contacts + history, and the multi-device merge
internal/mailbox/   store-and-forward blob store (shared by the server and the
                    standalone mailbox daemon)
internal/pin/       device-bound PIN unlock shortcut
internal/duress/    duress code + pre-generated decoy identity
internal/wipe/      overwrite-before-unlink file removal
internal/datalock/  single-instance guard for a data directory
internal/device/    per-device key + role (primary/secondary)
internal/desktop/   OS glue for the windowed build: start-at-login entry,
                    native notification, tray/window icon
mobile/             gomobile bindings for Android
```

## Releasing

```sh
tools/build-release.sh          # -> dist/molepipe-<version>-<os>-<arch>.tar.gz
```

The tarball carries **two builds of the app** — `molepipe-desktop` (its own window
and tray icon) and `molepipe` (opens in a browser) — plus the `molepipe-cli` tool,
**the Arti binary**, a launcher and a desktop entry.

Both are shipped because they are not interchangeable. `molepipe` is built
`CGO_ENABLED=0` and is self-contained; `molepipe-desktop` needs cgo and links
against `libwebkit2gtk-4.1` and `libgtk-3` at runtime, so it cannot be
cross-compiled and will not start on a machine without them. The launcher runs
`ldd` and falls back to the browser build rather than failing silently. The
desktop build is skipped with a warning — not an error — when the GTK/WebKit
development packages are absent, so a release can still be cut anywhere; pass
`DESKTOP=0` to skip it deliberately. Arti ships alongside
rather than embedded in the Go binary: embedding would mean owning an
extract-to-temp path and its cleanup for no gain over a folder with two files
in it, and a separate binary keeps Arti's provenance obvious.

The app finds Arti by looking at `-arti`, then next to its own executable, then
`PATH` — so the same build works from an unpacked tarball and from a developer
checkout. Verify a release by unpacking it somewhere clean and running it with
Arti *absent from* `PATH`; that is the only check that says anything about a
machine other than yours.

A packaged run has no terminal, so the log is mirrored to `molepipe.log` in the
data directory. It names the accounts you exchanged messages with, which is why
both the duress wipe and account removal empty it.

## Running two instances

Each instance needs its **own** data directory. Sharing one means two processes
derive the same identity and onion key, publish competing descriptors for the
same address, and overwrite each other's history — silent corruption that
surfaces later as unreachable peers. `datalock` refuses to start the second
instance rather than let that happen.

```sh
go run ./cmd/server                                # default dir
go run ./cmd/server -data-dir ~/molepipe-test-b    # a second, independent instance
```

## The desktop build

```sh
CGO_ENABLED=1 go build -tags "desktop production webkit2_41" ./cmd/desktop
```

All three tags matter. `desktop production` is what makes Wails draw a native
window (without them it still **compiles** — which is why `go build ./...` and
`go test ./...` work everywhere — but falls back to a browser, and the binary
says so at startup). `webkit2_41` is needed because Wails v2 defaults its
pkg-config to `webkit2gtk-4.0`, and current distributions ship 4.1. No `wails`
CLI is required: the CLI exists to run a JS bundler, and this frontend is
already vendored and `go:embed`ed.

## Build & test

```sh
go test ./...              # unit tests (SLIP-0010 official vectors, DH, storage)
go run ./cmd/tormsg selftest   # end-to-end proof: create → lock → unlock → recover
```

## CLI

```sh
tormsg create     # generate identity, print account number + recovery phrase, store encrypted
tormsg unlock     # decrypt stored identity, show account number
tormsg recover    # rebuild identity from a recovery phrase, re-encrypt under a new password
tormsg selftest   # self-check with a throwaway data dir
```

Data dir: `$TORMSG_DATA_DIR`, default `<user config dir>/molepipe`. The
identity lives in `identity.enc` (mode `0600`). Passwords are read from the TTY
(or piped stdin for automation) — never from a flag. `create` and `recover`
take the data-dir lock, so they refuse to run against a directory a server is
using; the read-only commands do not.

## Crypto design

| Concern | Choice |
|---|---|
| Recovery phrase | BIP39, 24 words / 256-bit entropy |
| Key derivation | BIP39 seed → SLIP-0010 Ed25519 (pinned to official test vectors) |
| Signing key | Ed25519 at `m/0'/0'` — the identity key (and future v3 onion key) |
| Agreement key | X25519 at `m/0'/1'`, distinct index (no key reuse across sign/DH) |
| Account number | v3-onion-style `base32(pubkey ‖ checksum ‖ 0x03)` — commits to the **full** public key, so it is collision-resistant and doubles as the onion address |
| Password KDF | Argon2id, 64 MiB / t=3 / p=4 (mobile-safe); params stored in-file |
| At-rest encryption | AES-256-GCM over the recovery phrase (the single root of truth) |

The recovery phrase is the only root of truth: unlock re-derives all keys from
it, and `recover` reproduces the exact same identity from the phrase alone —
independent of the stored file or its Argon2 parameters.

See [`../docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md) for what this does and
does not protect against.
