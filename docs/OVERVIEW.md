# Molepipe — Overview

**Private peer-to-peer messaging over Tor.**

Molepipe is a local-first, zero-knowledge messenger where your account number *is* a
Tor v3 onion address. Peers connect directly to each other over the Tor network, and
no server ever sees your messages, your metadata, or your IP.

- **End-to-end encrypted** — XChaCha20-Poly1305 with per-direction keys from an X25519 ECDH handshake
- **Zero-knowledge** — a 24-word BIP39 recovery phrase is the only root of truth; no server escrow
- **No accounts, no servers** — your identity is an onion service you own outright
- **No IP exposed** — all traffic rides Tor onion services

---

## What it is

Most messengers route your conversations through a company's servers. Molepipe doesn't
have any. Each person runs their own Tor onion service; two people connect straight to
each other through the Tor network. There is no address book in the cloud, no phone
number, no email — just a cryptographic account number that only you can prove ownership
of, backed up by a single recovery phrase that never leaves your device.

### How a message travels

| Stage | What happens |
|---|---|
| **1 · Identity** | Your device generates a Tor v3 keypair. The public half is your account number — a 56-character onion address. No signup. |
| **2 · Connect** | When you message someone, your app dials their onion service directly. Neither IP address is revealed to the other, or to anyone in between. |
| **3 · Encrypt** | Every message is sealed with a key only the two of you hold. The transport can't read it, nor can any relay that carries it. |
| **4 · Deliver** | If a peer is offline, sealed messages wait in an untrusted mailbox or hop through a mutual friend, then sync when they return. |

---

## Features

### A · Identity & encryption

- **Onion account number** — your address is a Tor v3 onion service you own outright; nobody assigns it, nobody can take it, and it exposes no IP (56-char v3 onion).
- **24-word recovery phrase** — one BIP39 phrase is the only root of truth. No server escrows it; anyone with it can rebuild the account, and it is re-viewable any time under **You › Security**.
- **Modern encryption** — messages are sealed with XChaCha20-Poly1305 using per-direction keys derived from an X25519 ECDH handshake between the two parties.
- **QR code sharing** — hand someone your account number in person by scanning a QR code, or copy it as plain text.
- **Display name & profile picture** — set a friendly name and a photo; a contact's avatar even shows at add-time, so you can confirm you're adding the right 56-character address.

### B · Messaging (one-to-one)

- **Direct chats** — real-time conversations with delivery and read receipts, plus one-tap retry when a message can't get through.
- **Photos & images** — send pictures end-to-end; attachments are content-addressed and encrypted at rest, with a built-in full-screen image viewer.
- **Reactions** — react to any message with an emoji.
- **Delete & multi-select** — remove a message for yourself, or enter multi-select to clear several at once (the back button steps out of selection first).
- **Block** — cut someone off entirely; a blocked account can't reach you and disappears from your conversations.
- **Friend requests** — add someone by their account number and send a request; they see your name and avatar and choose to accept or decline. No silent adds.

### C · Groups (many-to-many)

- **Group chats** — named groups with client-side fan-out; your app encrypts and delivers to each member directly, with no group server in the middle.
- **Invites & roles** — invite members, accept or decline invitations, promote admins, remove people, and set who's allowed to invite.
- **Shared images & backup** — share pictures to the whole group; group images are content-addressed and can be backed up and restored, so history survives a reinstall.
- **Rename, react & policy** — rename a group, react to messages, and tune group policy.

### D · Staying reachable (offline delivery)

- **Mailbox drop-off** — when a friend is offline, sealed messages wait in a store-and-forward mailbox that holds ciphertext only.
- **Friend relay** — route through a mutual contact when a direct path isn't available (request, approve, hand off), still end-to-end encrypted.
- **Presence** — see when contacts are around, so you know whether a message will land now or wait.
- **Notifications** — new-message notifications with a conversation-style layout and the sender's avatar, even while the app runs in the background.

### E · Safety under pressure

- **PIN unlock** — a device-bound PIN for quick access, with a shuffled keypad and brute-force protection.
- **Duress code** — a second code that silently wipes your real data and opens a pre-generated decoy account, indistinguishable from a normal unlock to anyone watching.
- **Erase after failed attempts** — optionally wipe everything after too many wrong tries, so a lost or seized device can't be brute-forced.
- **Password-gated settings** — sensitive actions (viewing the recovery phrase, changing security) require your full password, even on an already-unlocked screen.

### F · Your devices (multi-device)

- **Link a new device** — pair a phone and a desktop to the same account with per-device keys, so every device is its own credential rather than a shared secret.
- **Sync across devices** — contacts, profile, and settings stay in step over an authenticated channel; no plaintext leaves any device.
- **Primary device & roles** — promote a device to primary and manage the rest.
- **Guided onboarding** — a stepped setup wizard walks you from account creation through saving your phrase and learning the features, and resumes safely if you close it halfway.

---

## Under the hood

A single portable Go backend carries the crypto, protocol, and storage. Every platform
wraps that same core, so behaviour is identical whether you're on a phone or a laptop.

| Layer | Detail |
|---|---|
| **Backend** | Portable Go — cryptography, wire protocol, chat storage, and the localhost HTTP API the interface talks to. |
| **Tor** | Arti (Tor's Rust implementation), bridged into Android through a C-ABI shim so onion services run on-device. |
| **Interface** | A Material 3 web app, embedded and served locally — no browser tab, no external requests. |
| **Storage** | Everything encrypted at rest under a key derived from your password; the recovery phrase is the only way back in. |
| **Android** | Native WebView with a foreground service, so messages arrive while the app is in the background. |
| **Desktop** | Native window with a system tray on Linux, optional autostart, and links that open in your real browser. |

**Zero-knowledge by construction.** No server holds your account, your keys, or your
message history. The mailbox and relay only ever move sealed ciphertext, and Tor hides
the network path — the metadata surface is limited to what Tor itself reveals.

**Runs headless too.** Beyond the phone and desktop apps, the core ships as a headless
server and a command-line tool — create, unlock, recover, and self-test an identity
straight from the terminal.

### Platforms

- **Android** — WebView app with a background service, on-device Tor, and rich message notifications.
- **Desktop** — native Linux window with a tray icon, autostart, and external-link handling.
- **Server & CLI** — headless mode opens in a browser; the CLI creates, recovers, and self-tests identities.

---

## Further reading

| Document | Description |
|---|---|
| [`architecture.md`](architecture.md) | Technical architecture — identity, keys, storage, networking, components |
| [`protocol.md`](protocol.md) | Wire protocol — handshake, encryption, message format, versioning |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Threat model — adversaries, security properties, metadata surface |
| [`RECOVERY.md`](RECOVERY.md) | Recovery guide — what the recovery phrase does and does not restore |
