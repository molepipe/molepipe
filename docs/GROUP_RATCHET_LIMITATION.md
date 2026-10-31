# Group Messaging — Ratchet Limitation

## Current Architecture

Group messages use a **carrier relay model**, not pairwise encryption:

1. The author signs a `GroupMessage` with their Ed25519 identity key.
2. The author seals the signed message per-recipient using the **carrier's** X25519 key.
3. Any member can re-seal and forward (the "everyone relays" model).
4. The inner author signature provides authentication regardless of who relayed.

This is the existing architecture and it is NOT changed by the v2 ratchet upgrade.

## Why Groups Don't Use Pairwise Ratchet

The Double Ratchet is a **pairwise** protocol: each (Alice→Bob) session has independent ratchet state. Applying it to groups would require:

1. **Pairwise sessions between every member pair** — an N-member group requires N*(N-1)/2 independent ratchet sessions. For a 50-member group, that's 1,225 sessions, each with its own state, prekeys, and skipped-message-key storage.

2. **Sender keys** — a more efficient approach where the author generates a random "sender key" and encrypts it to each member using their pairwise ratchet session. The author then uses the sender key to encrypt group messages. This is what Signal uses for groups.

3. **Key distribution** — when a member joins or leaves, the sender key must be re-distributed to all remaining members via their pairwise sessions.

## Current Limitation

Group messages in Molepipe do **NOT** have forward secrecy beyond the carrier's pairwise session:

- The carrier's X25519 key encrypts group traffic to each recipient.
- If the carrier's key is compromised, all group messages forwarded by that carrier are exposed.
- The inner author signature provides authentication but NOT encryption.
- The author's signing key is NOT the encryption key for group messages.

## Recommendation

For a future group ratchet, implement **Sender Keys** (as Signal does):

1. The author generates a random sender key for each group epoch.
2. The sender key is encrypted to each member using their pairwise ratchet session.
3. Group messages are encrypted with the sender key (AES-256-GCM or XChaCha20-Poly1305).
4. When a member joins/leaves, a new sender key is distributed.

This is a separate protocol from the pairwise Double Ratchet and should be implemented as a distinct feature, not as an extension of the current pairwise ratchet.

## Security Implications

- Group messages are protected by the carrier's pairwise session (which now has forward secrecy via the ratchet).
- If a carrier's session key is compromised, only messages forwarded by that carrier during that session are exposed.
- The author's signing key is separate from the encryption key, so signing key compromise does not expose message content.
- The carrier model means any member can re-seal and forward, which is a design trade-off for relay resilience.
