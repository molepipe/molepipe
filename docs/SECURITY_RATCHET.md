# Security Review — Molepipe v2 Cryptographic Protocol

## 1. Current Cryptographic Architecture

### v1 (pre-upgrade)
- **Identity**: Ed25519 from BIP39 seed at path `m/0'/0'`
- **Encryption**: Static X25519 from BIP39 seed at path `m/0'/1'`
- **Key agreement**: Implicit static-static ECDH (no forward secrecy)
- **Message encryption**: XChaCha20-Poly1305 with random 192-bit nonce
- **Key derivation**: HKDF-SHA256 with directional info strings
- **Signature domain**: `"onion-chat/v1"`

### v2 (new)
- **Identity**: Ed25519 from BIP39 seed at path `m/0'/0'` (unchanged)
- **Signed prekeys**: Rotatable X25519 keypairs signed by Ed25519 identity
- **One-time prekeys**: Single-use X25519 keypairs for async session setup
- **Session establishment**: X3DH (Signal protocol)
- **Message encryption**: Double Ratchet with XChaCha20-Poly1305
- **Key derivation**: HMAC-SHA256 chain ratchet + HKDF-SHA256 DH ratchet
- **Signature domain**: `"onion-chat/v2"`

## 2. Key Lifetimes

| Key | Lifetime | Rotation | Storage |
|-----|----------|----------|---------|
| Ed25519 identity | Permanent | Never | Re-derived from BIP39 seed |
| X25519 static (v1 fallback) | Permanent | Never | Re-derived from BIP39 seed |
| Signed prekey | 7 days | Automatic | Private key in encrypted store |
| Retired signed prekey | 30 days | Grace period | Private key in encrypted store |
| One-time prekey | Single use | Pool refill | Private key deleted after use |
| Ratchet key | Per session | On DH ratchet | In-memory session state |
| Message key | Single use | Per message | Derived then deleted |
| Chain key | Per chain | Advanced per message | Derived from previous |

## 3. Key Deletion Rules

1. **Message keys**: Deleted after encryption/decryption. Never stored persistently.
2. **Chain keys**: Overwritten by next chain key after advancing. Not stored separately.
3. **One-time prekey private keys**: Deleted immediately after consumption (X3DH).
4. **Retired signed prekey private keys**: Deleted after 30-day grace period.
5. **Ratchet keys**: Overwritten by new keypair after DH ratchet. Old key discarded.
6. **Root key**: Overwritten after each DH ratchet step. Old value discarded.
7. **Identity key**: NEVER deleted. Re-derived from BIP39 seed on every unlock.

## 4. Rotation Rules

1. **Automatic signed prekey rotation**: Every 7 days (configurable)
2. **One-time prekey pool refill**: When unused count drops below 20 (target 100, max 200)
3. **Emergency rotation**: Manual rotation available for key compromise response
4. **Old key retirement**: Previous signed prekey marked "retired" with timestamp
5. **Grace period cleanup**: Retired prekeys older than 30 days are permanently deleted

## 5. Session Establishment Flow

1. Initiator fetches responder's prekey bundle (signed prekey + optional one-time prekey)
2. Initiator verifies signed prekey signature against responder's identity key
3. Initiator performs X3DH: 4 DH operations producing initial root secret
4. Initiator derives initial sending chain from root secret
5. Initiator sends first message with ratchet public key in header
6. Responder receives, performs DHRatchet to derive receiving chain
7. Both sides now have matching chain keys for the session

## 6. Ratchet Flow

1. Each message advances the symmetric ratchet: `chainKey → (messageKey, nextChainKey)`
2. When a new remote ratchet key is received, perform DH ratchet:
   - DH(old local, remote) → root key, receiving chain
   - Generate new local ratchet keypair
   - DH(new local, remote) → root key, sending chain
3. Skipped messages have their keys stored for out-of-order delivery
4. MAX_SKIP limit (1000) prevents resource exhaustion

## 7. Multi-Device Handling

Each device has:
- Independent signed prekey (with device-specific ID)
- Independent one-time prekey pool
- Independent ratchet sessions per (account, device) pair
- Independent session state in the encrypted store

The session manager handles per-device session lifecycle.

## 8. Offline Mailbox Handling

The mailbox remains blind to plaintext:
- Only handles encrypted ciphertext (AEAD boxes)
- No access to ratchet private keys, message keys, or chain keys
- No access to identity private keys
- May store: ciphertext, message IDs, expiration, routing info

## 9. Replay Handling

- **Challenge nonces**: Single-use, 5-minute TTL, max 4096 in jar
- **Mailbox messages**: Deterministic content hash (ID) collapses replays
- **Skipped message keys**: Stored with (ratchetPub, msgNum) key, MAX_SKIP limit
- **DH ratchet**: Prevents replay of old ratchet keys

## 10. DoS/Resource Limits

- **MAX_SKIP**: 1000 messages can be skipped in a single chain
- **MaxSkipKeys**: 10000 total skipped message keys stored
- **One-time prekey pool**: Max 200, refill threshold 20
- **Challenge nonces**: Max 4096, FIFO eviction
- **Message size**: 16 KiB max plaintext
- **Name length**: 64 runes max
- **Mailbox address**: 256 bytes max

## 11. Backward Compatibility

- v1 static X25519 encryption retained for peers that haven't upgraded
- Version negotiation via `Challenge.Ver` field
- Profile verification tolerates both v1 and v2 signatures
- Store migration is non-destructive (new fields are omitempty/nil)
- Frozen AAD ensures cross-version decryption

## 12. Remaining Limitations

1. **Group messages**: Carrier relay model, not pairwise ratchet. Forward secrecy limited to carrier's session.
2. **Device compromise**: Full device access exposes all session state and private keys.
3. **Recovery phrase**: Only recovers identity, not ratchet state. Fresh sessions established after restore.
4. **Post-quantum**: Not protected against quantum computer attacks (X25519 is vulnerable to Shor's algorithm).

## 13. Threat Model Changes

### Protected Against (v2)
- Passive interception of messages (forward secrecy)
- Compromise of old message keys after deletion
- Compromise of retired signed prekeys after grace period
- Malicious mailbox/relay (cannot decrypt ciphertext)
- Delayed/out-of-order delivery within configured limits

### Not Protected Against
- Complete device compromise
- Theft of permanent Ed25519 identity key
- Theft of recovery phrase
- Malware on unlocked device
- Screenshots of decrypted messages
- Attacker who copied private key material
- Quantum computer attacks

## 14. Areas Requiring Independent Review

1. **X3DH implementation**: The 4-DH computation and HKDF domain separation
2. **Double Ratchet initialization**: Alice/Bob asymmetric initialization (Section 3.3 of Signal spec)
3. **HKDF domain separation**: KDF_RK uses root key as IKM and DH output as salt
4. **HMAC chain ratchet**: KDF_CK uses HMAC-SHA256 with constants 0x01/0x02
5. **Skipped key storage**: MAX_SKIP enforcement and key deletion
6. **Prekey lifecycle**: Rotation timing, grace period, private key deletion

## 15. Test Coverage

| Category | Tests | Status |
|----------|-------|--------|
| X3DH key agreement | Both sides agree, optional prekey, different prekeys | ✅ Pass |
| Signed prekey verification | Tampered, wrong identity, uniqueness | ✅ Pass |
| Prekey bundle verification | Tampered sig, wrong version, wrong identity | ✅ Pass |
| Double Ratchet init | Alice/Bob asymmetric initialization | ✅ Pass |
| Bidirectional exchange | Alice→Bob, Bob→Alice, Alice→Bob | ✅ Pass |
| Multiple messages | 1000 messages in same chain | ✅ Pass |
| Out-of-order delivery | Messages received out of order | ✅ Pass |
| Duplicate rejection | Same message number rejected | ✅ Pass |
| Forward secrecy | Old key cannot decrypt later messages | ✅ Pass |
| Message key uniqueness | 10000 keys, no duplicates | ✅ Pass |
| Nonce determinism | Same msgNum → same nonce | ✅ Pass |
| Skipped key limit | MAX_SKIP enforcement | ✅ Pass |
| Empty message | Empty plaintext round-trips | ✅ Pass |
| Maximum size | 16 KiB message round-trips | ✅ Pass |
| Protocol negotiation | v1/v2 coexistence | ✅ Pass |
| Store migration | v1→v2 format upgrade | ✅ Pass |
