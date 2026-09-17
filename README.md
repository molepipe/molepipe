# Molepipe

Private peer-to-peer messaging over Tor.

Molepipe is a local-first, zero-knowledge messenger where your account number is a Tor v3 onion address. Messages are end-to-end encrypted, peers communicate directly over Tor onion services, and no server ever sees plaintext or metadata beyond what Tor itself reveals.

## Features

- **End-to-end encrypted messaging** using XChaCha20-Poly1305 with per-direction keys derived from X25519 ECDH
- **Tor onion service** — your address is your account number; no IP is ever exposed
- **Zero-knowledge recovery** — a 24-word BIP39 phrase is the only root of truth; no server escrow
- **Offline delivery** via a mailbox server (store-and-forward) or friend relay
- **Multi-device sync** with per-device keys and role management
- **Group messaging** with client-side fan-out and content-addressed image sharing
- **Duress code** — a second code that wipes data and opens a pre-generated decoy account
- **PIN unlock** — device-bound shortcut with brute-force protection
- **Desktop and Android** — native window with tray on Linux, WebView with foreground service on Android

## Architecture

Molepipe has a portable Go backend that runs on desktop (via Wails or browser) and Android (via gomobile). The backend exposes a localhost HTTP API; the UI is an embedded Material 3 web application.

```
molepipe/
├── backend/          Go backend (crypto, protocol, API, storage)
│   ├── cmd/          Entry points: server, desktop, tormsg CLI, mailbox
│   └── internal/     Core packages: crypto, protocol, api, chatstore, tor
├── android/          Android app (Kotlin/Compose + gomobile AAR)
├── torhost/          Rust crate — Arti C-ABI shim for Android Tor
├── docs/             Architecture, protocol, threat model, recovery
└── tools/            Build scripts
```

See [`docs/architecture.md`](docs/architecture.md) for the full technical architecture and [`docs/protocol.md`](docs/protocol.md) for the wire protocol specification.

## Building

### Desktop (Linux)

```sh
# Requires: Go 1.26+, libwebkit2gtk-4.1-dev, libgtk-3-dev
cd backend
CGO_ENABLED=1 go build -tags "desktop production webkit2_41" -o molepipe-desktop ./cmd/desktop
```

### Headless server

```sh
cd backend
CGO_ENABLED=0 go build -o molepipe-server ./cmd/server
```

### Android AAR

```sh
# Requires: Rust, cargo-ndk, gomobile, Android NDK
./android/build-aar.sh
```

### Release tarball

```sh
./tools/build-release.sh
```

## Running

```sh
# Headless (opens browser)
./molepipe-server

# Desktop (native window + tray)
./molepipe-desktop

# CLI
./molepipe-cli create    # generate identity
./molepipe-cli unlock    # decrypt stored identity
./molepipe-cli recover   # rebuild from recovery phrase
./molepipe-cli selftest  # end-to-end self-check
```

Data directory: `$TORMSG_DATA_DIR`, default `~/.config/molepipe`.

## Security

See [`SECURITY.md`](SECURITY.md) for the security model and vulnerability reporting process.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the comprehensive threat model covering adversary classes, security properties, and metadata surface.

## Documentation

| Document | Description |
|---|---|
| [`docs/OVERVIEW.md`](docs/OVERVIEW.md) | What Molepipe is and everything it does — a feature overview |
| [`docs/architecture.md`](docs/architecture.md) | Technical architecture — identity, keys, storage, networking, components |
| [`docs/protocol.md`](docs/protocol.md) | Wire protocol — handshake, encryption, message format, versioning |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Threat model — adversaries, security properties, metadata surface |
| [`docs/RECOVERY.md`](docs/RECOVERY.md) | Recovery guide — what the recovery phrase does and does not restore |
| [`CHANGELOG.md`](CHANGELOG.md) | Release history |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Development setup and contribution guide |

## License

See [`LICENSE.md`](LICENSE.md).

## Security Reporting

See [`SECURITY.md`](SECURITY.md) for how to report vulnerabilities.
