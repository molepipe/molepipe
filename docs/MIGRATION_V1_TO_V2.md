# Migration Path — v1 to v2 Protocol Upgrade

## Overview

Molepipe v2 introduces X3DH session establishment with signed prekeys and Double
Ratchet message encryption. v1 static-X25519 encryption is retained as a fallback
for peers that haven't upgraded yet.

## Backward Compatibility

### Protocol Negotiation

The `Challenge.Ver` field advertises the responder's maximum wire version. At v1
this field was unsigned (absent ⇒ v1); at v2 it is folded into the signed
challenge so a downgrade attack cannot force a v1 session on a v2-capable peer.

- v2 client → v1 peer: v1 session (static X25519, no forward secrecy)
- v1 client → v2 peer: v1 session (static X25519, no forward secrecy)
- v2 client → v2 peer: v2 session (X3DH + Double Ratchet, forward secrecy)

The version is negotiated per-session via `negotiateVersion()`. The
`candidateVersions()` function returns supported versions in descending order,
so a v2 client tries v2 first and falls back to v1.

### Store Migration

The chatstore format is bumped from v1 to v2. The migration (`migrate1to2`):

1. Sorts tombstones (canonicalization, no data loss)
2. Initializes prekey state as nil/empty

The application layer detects nil prekey state and generates initial material
on first unlock after upgrade.

### Signature Contexts

- v1: `"onion-chat/v1"` — used by all v1 messages and signatures
- v2: `"onion-chat/v2"` — used by v2 messages and signatures

The v1 context is frozen and must never change. The v2 context is used for new
signatures. Profile verification tolerates both v1 and v2 via `candidateVersions`.

## Upgrade Flow

### First Unlock After Upgrade

1. Load `messages.enc` (v1 format)
2. Detect `Prekeys == nil` → first v2 unlock
3. Generate initial signed prekey from identity key
4. Generate initial one-time prekey pool (100 prekeys)
5. Set next rotation time (7 days from now)
6. Save state as v2 format
7. Publish new signed prekey via challenge endpoint

### Ongoing Operation

1. On each unlock: check if rotation is due → rotate if needed
2. Periodically refill one-time prekey pool if below threshold
3. Clean up expired retired signed prekeys (30-day grace period)
4. Clean up consumed one-time prekeys

### Recovery Phrase Restoration

1. Recover permanent Ed25519 identity from 24-word phrase
2. Generate fresh signed prekey and one-time prekey pool
3. Establish new ratchet sessions with contacts on next online exchange
4. Previous ratchet state is NOT restored (forward secrecy)

## v1 Peer Interaction

When communicating with a v1 peer:

1. Challenge negotiation selects v1
2. Use existing static X25519 encryption (no ratchet)
3. No prekey exchange
4. No forward secrecy for this session

The v1 code path is retained in the protocol package and can be selected by
the version negotiation logic. The static X25519 key from `m/0'/1'` continues
to work for v1 sessions.

## Data Safety

- v1→v2 migration is non-destructive: existing messages and contacts are preserved
- The v2 format is a strict superset of v1 (new fields are omitempty/nil)
- A v1 client can read v2 data (new fields are ignored)
- A v2 client can read v1 data (nil prekey state triggers generation)
- The frozen AAD (`"onion-chat/v1 local-store"`) ensures cross-version decryption
