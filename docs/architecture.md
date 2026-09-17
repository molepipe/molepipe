# Architecture

This document describes the technical architecture of Molepipe based on the current implementation.

## Overview

Molepipe is a local-first, zero-knowledge messenger built on Tor v3 onion services. The Go backend handles all crypto, networking, and storage; the UI is an embedded Material 3 web application served over localhost HTTP.

```
┌─────────────────────────────────────────────────────┐
│                    User Device                       │
│                                                      │
│  ┌──────────┐    ┌──────────────┐    ┌───────────┐  │
│  │   UI     │◄──►│  HTTP API    │◄──►│  Crypto   │  │
│  │ (WebView)│    │  (localhost) │    │  Engine   │  │
│  └──────────┘    └──────┬───────┘    └───────────┘  │
│                         │                             │
│                  ┌──────┴───────┐                     │
│                  │  Peer Proto  │                     │
│                  │  (onion)     │                     │
│                  └──────┬───────┘                     │
│                         │                             │
│                  ┌──────┴───────┐                     │
│                  │  Tor (Arti)  │                     │
│                  └──────┬───────┘                     │
└─────────────────────────┼───────────────────────────┘
                          │
                    ┌─────┴─────┐
                    │    Tor    │
                    │  Network  │
                    └─────┬─────┘
                          │
                   ┌──────┴──────┐
                   │  Peer's     │
                   │  Onion      │
                   └─────────────┘
```

## Identity

### Key Hierarchy

All keys derive deterministically from a 24-word BIP39 recovery phrase (256-bit entropy):

```
BIP39 Mnemonic (24 words)
    │
    ▼
BIP39 Seed (64 bytes)
    │
    ├── SLIP-0010 m/0'/0' ──► Ed25519 Signing Key (identity key)
    │                              │
    │                              ├── Account number (v3 onion address)
    │                              └── Onion service key
    │
    ├── SLIP-0010 m/0'/1' ──► X25519 Agreement Key (DH key)
    │
    └── HKDF-SHA256 ──────────► Store Key (encrypts messages.enc)
```

**Key files:**
- `crypto/keys.go` — Key derivation from BIP39 seed via SLIP-0010
- `crypto/slip10.go` — SLIP-0010 implementation (HMAC-SHA512, hardened-only)
- `identity/identity.go` — Account number derivation (v3 onion encoding)

### Account Number

The account number is a v3 onion address encoding of the Ed25519 public key:

```
base32(Ed25519_pubkey(32) || SHA3-256(".onion checksum" || pubkey || 0x03)[:2] || 0x03)
```

This format is collision-resistant and doubles as the `.onion` address for Tor routing.

### Identity Storage

The recovery phrase and optional passphrase are encrypted in `identity.enc`:

- **Encryption:** AES-256-GCM
- **Key derivation:** Argon2id (64 MiB, t=3, p=4) from user password
- **Format:** JSON envelope with version, KDF parameters, salt, nonce, ciphertext
- **Permissions:** 0600 (owner read/write only)
- **Atomic writes:** Write to temp file, fsync, rename

**Key file:** `identity/store.go`

## Key Generation

### Per-Device Keys

Each device generates a random 32-byte Ed25519 seed on first run, stored in `device.json`. From this:

- **Device local secret:** HKDF-SHA256 from device seed (domain-separated for PIN wrapping)
- **PIN wrap key:** Argon2id(PIN, salt) → HKDF(stretched, device_secret) — encrypts the device key in `pin.enc`
- **Unlock guard MAC:** HMAC under device secret — authenticates attempt counters

### Message Keys

For each connection direction, a unique AEAD key is derived:

1. **X25519 ECDH:** `shared_secret = X25519(sender_dh_private, recipient_dh_public)`
2. **HKDF-SHA256:** `key = HKDF(shared_secret, info="onion-chat/v1 msg <sender>-><receiver>")`

The `info` string encodes direction, so A→B and B→A never share a key.

**Key files:** `crypto/message.go`, `protocol/protocol.go`

## Recovery Mechanism

The recovery phrase is the only root of truth:

- `FromMnemonic(phrase, passphrase)` re-derives all keys deterministically
- Recovery restores the identity (Ed25519 + X25519 keypair, account number)
- Recovery does NOT restore: message history, contacts, device key, PIN, duress config
- A recovered device comes up as `RoleSecondary` to avoid publishing a conflicting onion descriptor

**Key file:** `identity/identity.go`

## Message Flow

### Direct Message (Online Peer)

```
Alice                              Bob (onion)
  │                                    │
  │── GET /p2p/challenge ────────────►│  (Tor circuit)
  │                                    │  Bob generates nonce, signs it
  │◄── Challenge{nonce,dh_pub,sig} ──│
  │                                    │
  │  [Verify Bob's Ed25519 sig]        │
  │  [Compute shared = X25519(...)]    │
  │  [Derive key = HKDF(shared, ...)]  │
  │  [Encrypt payload with XChaCha20]  │
  │                                    │
  │── POST /p2p/message ─────────────►│
  │   {sender, dh_pub, nonce, sig, box}│
  │                                    │  [Consume nonce (one-time)]
  │                                    │  [Verify Alice's sig]
  │                                    │  [Check contacts-only]
  │                                    │  [Decrypt box]
  │◄── 200 OK ────────────────────────│
```

### Offline Delivery (Mailbox)

When the recipient is offline, the sender drops a sealed `MailEnvelope` at the recipient's mailbox:

1. Sender fetches mailbox URL from gated `ContactProfile` (only disclosed to accepted contacts)
2. `POST /mailbox/dropoff` with E2E-encrypted `MailEnvelope`
3. Recipient picks up via authenticated `POST /mailbox/pupickup`

The mailbox server never decrypts content — it stores opaque, signed blobs.

### Friend Relay

When neither direct nor mailbox delivery works, a mutual contact relays the message:

1. Sender asks approved relay-holder via `POST /relay/dropoff`
2. Relay pushes to recipient via `POST /relay/deliver`
3. Envelope stays E2E-encrypted throughout; relay cannot read it

## Networking

### Two-Listener Architecture

The server binds two separate loopback listeners:

| Listener | Port | Serves | Access Control |
|---|---|---|---|
| **Control** | `127.0.0.1:<port>` | UI, `/api/*` endpoints | Capability token + host allowlist + origin guard + session token |
| **Onion-facing** | `127.0.0.1:0` (random) | `/p2p/*` protocol endpoints | Rate limit (32 concurrent) |

The Arti sidecar forwards Tor onion traffic to the onion-facing listener. The control listener is never reachable from the network.

**Key file:** `api/server.go`

### Tor Integration

- **Desktop:** Arti runs as a child process (`torsidecar`), providing a SOCKS5 proxy
- **Android:** Arti runs in-process via a Rust C-ABI shim (`torhost` crate → `artihost`)

The onion service key is derived from the Ed25519 signing seed and written to Arti's keystore while the service is running. It is deleted on lock/shutdown.

## Storage

### On-Disk Files

| File | Contents | Encryption |
|---|---|---|
| `identity.enc` | Recovery phrase + passphrase | AES-256-GCM, password-derived (Argon2id) |
| `messages.enc` | Contacts, messages, groups, profile, outbox, devices, invites | AES-256-GCM, seed-derived store key |
| `pin.enc` | Session material under device key, wrapped by PIN | Two-layer AES-256-GCM |
| `duress.enc` | Decoy identity for panic code | AES-256-GCM, duress code |
| `device.json` | Device role + Ed25519 device key seed | Plaintext (local-only) |
| `unlock_guard.json` | Failed unlock counter + wipe policy | HMAC-authenticated |
| `attachments/*.enc` | Image attachment blobs | AES-256-GCM, store key |
| `avatars/*.enc` | Avatar image blobs | AES-256-GCM, store key |

### Chat Store

`messages.enc` contains all application state: contacts, message history, groups, profile, outbox, device enrollment, and tombstones for deleted messages. The store is encrypted as a single blob with AES-256-GCM and decrypted on every startup.

## Components

### Entry Points

| Binary | Purpose |
|---|---|
| `cmd/server` | Headless HTTP server + Arti sidecar (opens browser) |
| `cmd/desktop` | Wails native window + system tray |
| `cmd/tormsg` | CLI test harness (create/unlock/recover/selftest) |
| `cmd/mailbox` | Standalone mailbox server (Docker-friendly) |
| `cmd/update-manifest` | Offline signing tool for update manifests |

### Core Packages

| Package | Purpose |
|---|---|
| `crypto` | BIP39, SLIP-0010, X25519, AES-256-GCM, XChaCha20-Poly1305, Argon2id, HKDF |
| `protocol` | Peer protocol: handshake, messages, groups, mailbox, relay |
| `api` | HTTP API layer (control + onion-facing listeners) |
| `chatstore` | Encrypted persistence for contacts, messages, groups |
| `identity` | Identity generation, account number encoding, encrypted store |
| `tor` | Onion service interface (platform-agnostic) |
| `torsidecar` | Desktop Arti child-process manager |
| `mailbox` | Store-and-forward blob store |
| `pin` | Device-bound PIN unlock |
| `duress` | Duress code + decoy identity |
| `unlockguard` | Brute-force protection + erase-after-N |

## Desktop vs Android

| Aspect | Desktop | Android |
|---|---|---|
| UI shell | Wails v2 webview + systray | Android WebView + foreground service |
| Tor | Arti sidecar (child process) | Arti via Rust shim (cgo) |
| Control token | In-process via `?ct=` URL param | `URLWithToken()` returned to Kotlin |
| Background | Tray keeps process alive | Foreground service + CPU wakelock |
| Battery | N/A | Dormant mode suspends Tor proactive tasks |
| Log | File + stderr (dual-writer) | File only (wipeable) |
