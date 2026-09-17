# Protocol

This document specifies the Molepipe wire protocol based on the current implementation (v1).

## Overview

Molepipe uses a challenge-response protocol over HTTP, routed through Tor v3 onion services. All peer communication is authenticated via Ed25519 signatures and encrypted via XChaCha20-Poly1305 with per-direction keys.

## Identity Format

### Account Number

The account number is a v3 onion address encoding of the Ed25519 public key:

```
base32(Ed25519_pubkey(32) || SHA3-256(".onion checksum" || pubkey || 0x03)[:2] || 0x03)
```

- **Length:** 56 characters (lowercase, unpadded base32)
- **Version byte:** `0x03`
- **Checksum:** First 2 bytes of SHA3-256

The account number doubles as the `.onion` address for Tor routing.

## Key Types

| Key | Derivation | Purpose |
|---|---|---|
| Ed25519 signing | SLIP-0010 `m/0'/0'` | Identity, signatures, onion service |
| X25519 agreement | SLIP-0010 `m/0'/1'` | ECDH key agreement for encryption |

**Note:** X25519 keys are static (derived from the seed). There is no application-layer forward secrecy — compromise of an identity key exposes all past messages at the app layer. Tor rendezvous provides transport-layer forward secrecy.

## Signature Format

All signatures use Ed25519 over a length-prefixed blob:

```
sigBlob = len(prefix) || prefix || len(label) || label || len(field1) || field1 || ...
```

Each component is prefixed with a 4-byte big-endian length. The first component is always the **signature domain** (`"onion-chat/v1"`), followed by a message-type label, then bound fields.

### Signature Domains

| Operation | Label | Bound Fields |
|---|---|---|
| Challenge | `"challenge"` | recipient_account, dh_pub |
| Profile | `"profile"` | account, display_name, dh_pub, avatar_hash |
| Contact Profile | `"contact-profile"` | nonce, recipient_account |
| Message | `"message"` | nonce, recipient_account, sender_dh_pub |
| Friend Request | `"friend-request"` | nonce, recipient, from_name, req_id |
| Friend Accept | `"friend-accept"` | nonce, recipient, from_name, req_id |
| Delete | `"delete-message"` | nonce, recipient, message_id |
| Reaction | `"react-message"` | nonce, recipient, message_id, emoji, remove |
| Relay Request | `"relay-request"` | nonce, recipient, req_id |
| Relay Accept | `"relay-accept"` | nonce, recipient, req_id |
| Group Message | `"group-message"` | group_id, timestamp_nanos, text |
| Group Reply | `"group-reply-message"` | group_id, timestamp_nanos, text, reply_id |
| Group Image | `"group-image-message"` | group_id, timestamp_nanos, thumb, thumb_mime, full_id, full_hash, full_mime, full_size |
| Group Reaction | `"group-reaction"` | group_id, target, emoji, timestamp_nanos, remove |
| Group Roster | `"group-roster"` | group_id, name, epoch, policy, sorted_members |
| Group Sync | `"group-sync"` | group_id, sender, SHA256(sorted_ids), have_epoch |
| Group Invite | `"group-invite"` | nonce, recipient, group_id, group_name, req_id |
| Attachment | `"attachment"` | nonce, recipient, sender_dh_pub, msg_id, mime |
| Mailbox Message | `"mailbox-message"` | recipient, sender_dh_pub, sent_at, box |
| Pair Enroll | `"pair-enroll"` | nonce, device_pub |
| Sync | `"sync"` | nonce, device_pub |

## Encryption

### Key Derivation

1. **X25519 ECDH:** `shared_secret = X25519(sender_dh_private, recipient_dh_public)`
2. **HKDF-SHA256:** `key = HKDF(shared_secret, info="onion-chat/v1 msg <sender>-><receiver>")`

The `info` string encodes direction, so A→B and B→A use different keys.

### AEAD

- **Algorithm:** XChaCha20-Poly1305
- **Nonce:** 192-bit random (24 bytes)
- **Wire format:** `nonce(24) || ciphertext_with_tag`
- **AAD:** `"<sender_account>|<receiver_account>"` (binds the envelope to both parties)

## Handshake

### Direct Message Flow

```
Alice                              Bob (onion)
  │                                    │
  │── GET /p2p/challenge ────────────►│
  │                                    │  Generate random 32-byte nonce
  │                                    │  Store nonce with 5-min TTL
  │◄── {nonce, dh_pub, sig, ver} ────│  Sign: sigBlob(ctx,"challenge",
  │                                    │         account, dh_pub)
  │                                    │
  │  [Verify Ed25519 signature]        │
  │  [Negotiate protocol version]      │
  │  [Compute shared_secret = X25519]  │
  │  [Derive key = HKDF(...)]          │
  │  [Encrypt: box = XChaCha20(...)]   │
  │  [Sign: sigBlob(ctx,"message",...)]│
  │                                    │
  │── POST /p2p/message ─────────────►│
  │   {sender, sender_dh_pub,          │  [Consume nonce (one-time)]
  │    nonce, sig, box}                │  [Verify Ed25519 signature]
  │                                    │  [Check: sender is accepted contact]
  │                                    │  [Decrypt box]
  │◄── 200 OK ────────────────────────│  [Deliver plaintext]
```

### Challenge Jar

- In-memory map of `nonce → expiry`
- TTL: 5 minutes
- Cap: 4096 entries (oldest-eviction on overflow)
- One-time use: nonce is deleted on first consumption
- Pruned on every challenge/consume call

## Message Format

### Direct Message Envelope

```json
{
  "sender": "<56-char account>",
  "sender_dh_pub": "<32 bytes>",
  "nonce": "<32 bytes>",
  "sig": "<Ed25519 signature>",
  "box": "<24-byte nonce || XChaCha20-Poly1305 ciphertext>"
}
```

### Plaintext Payload (inside box)

```json
{
  "id": "<sender-assigned wire message ID>",
  "text": "<message text>",
  "kind": "image",
  "mime": "image/jpeg",
  "data": "<base64 image bytes>",
  "reply_id": "<quoted message ID>",
  "reply_preview": "<snippet text>",
  "reply_author": "<author name>"
}
```

All optional fields use `omitempty`. A non-reply text message contains only `id` and `text`.

### Message Identifiers

Message IDs are **sender-assigned and carried inside the AEAD**, not derived as a content hash. This ensures both sender and receiver name the same message (required for "delete for everyone").

## Offline Delivery

### Mailbox Envelope

```json
{
  "recipient": "<account>",
  "sender": "<account>",
  "sender_dh_pub": "<32 bytes>",
  "sent_at": 1234567890,
  "box": "<nonce || ciphertext>",
  "sig": "<Ed25519 signature>"
}
```

- No live nonce (recipient is offline)
- Signature covers `"mailbox-message"` label
- Content-hash ID for deduplication: `SHA256(signBlob(...))[:16]`

### Mailbox Protocol

1. **Check-in:** `POST /mailbox/checkin` — Prove ownership (signed nonce), create tenancy
2. **Drop-off:** `POST /mailbox/dropoff` — Store sealed `MailEnvelope` (sender authenticates, content stays opaque)
3. **Pick-up:** `POST /mailbox/pickup` — Retrieve all pending blobs (authenticated)
4. **Delete:** `POST /mailbox/delete` — Remove delivered messages (authenticated)

### Friend Relay

When neither direct nor mailbox delivery works:

1. **Relay drop-off:** `POST /relay/dropoff` — Sender hands sealed envelope to approved relay-holder
2. **Relay deliver:** `POST /relay/deliver` — Relay pushes to actual recipient

The envelope stays E2E-encrypted; the relay cannot read it.

## Group Messaging

### Creation

- Admin creates a `SignedRoster` listing members with their DH keys, roles, and invite permissions
- Roster is signed under `"group-roster"` domain
- Epoch increases on every roster change

### Fan-Out

Messages are NOT broadcast from the author. Instead, each holder **re-seals** messages individually for each recipient using that recipient's DH key from the roster. Any member can forward to anyone missing a message.

### Sync

Pull-based reconciliation: each member periodically sends a `GroupSyncRequest` listing held message IDs. The responder returns missing messages, newer rosters, and missing reactions.

### Group Reactions

Self-authenticating and relayable. Each reaction is signed by the reactor. Convergence: per `(Target, Emoji, By)`, last-writer-wins by timestamp.

### Group Images

- Inline thumbnail (max 16 KiB JPEG) fans out with the group message
- Full image fetched on demand via `POST /p2p/group-image`
- Author signs `FullHash` (SHA-256) for integrity verification

## Versioning

### Constants

```go
protoVerMin    = 1  // minimum supported version
protoVerCurrent = 1  // current protocol version
sigContext     = "onion-chat/v1"  // v1 signature domain (frozen)
```

### Version Negotiation

- `negotiateVersion(theirMax)` returns `min(theirMax, ourMax)` if `theirMax >= ourMin`
- Called at challenge-fetch time — rejects unsupported peers up front
- Absent `Ver` (0) is treated as legacy v1

### Profile Card Tolerance

Self-signed profile cards have no handshake. `Ver` is a **hint, not a selector** — the verifier tries the hinted version first, then all supported versions. A flipped or absent `Ver` never causes a spurious reject.

### Golden Tests

Frozen hex vectors for `GroupMessage`, `MailEnvelope`, and signature blobs catch any drift in the wire format that would break backward compatibility.

## Replay Protection

| Mechanism | Scope | Details |
|---|---|---|
| Challenge nonce | Direct messages, reactions, deletes, friend requests | One-time, 5-min TTL, 4096 cap |
| Mailbox content hash | Mailbox messages | `ID = SHA256(signBlob(...))[:16]`, dedup on ingest |
| Group message ID | Group messages | Deterministic from author + timestamp + content, idempotent |
| Group sync | Group sync requests | Signed but no nonce; replays are idempotent |
