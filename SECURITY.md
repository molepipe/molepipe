# Security Policy

## Security Model

Molepipe is designed as a privacy-focused, local-first messenger with the following security properties:

- **End-to-end encryption** — Messages are encrypted with XChaCha20-Poly1305 under keys derived from X25519 ECDH between sender and recipient. No intermediary can read plaintext.
- **Onion routing** — All peer communication goes through Tor v3 onion services. No IP addresses are exposed to peers.
- **Zero-knowledge recovery** — The 24-word BIP39 recovery phrase is the only root of truth. No server holds keys or can decrypt data.
- **Encrypted storage** — Identity, contacts, and messages are encrypted at rest with AES-256-GCM under password-derived keys (Argon2id).
- **Contacts-only admission** — Messages are accepted only from accepted contacts, authenticated via Ed25519 signatures.

### Known Limitations

- **No application-layer forward secrecy** — X25519 keys are static; compromise of an identity key exposes past messages at the application layer. Tor rendezvous provides transport-layer forward secrecy.
- **Endpoint compromise is out of scope** — Malware, root access, or debuggers on the device can read keys from memory while unlocked.
- **Metadata visibility** — Tor hides network location but not that two onions communicated (visible to a global passive observer), liveness (observable via profile polling), or group membership (visible from client-side fan-out).

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the comprehensive threat model.

## Supported Versions

Molepipe is currently in pre-release development. Only the latest version is supported.

## Reporting a Vulnerability

If you discover a security vulnerability in Molepipe, please report it responsibly.

**Do not open a public GitHub issue for undisclosed vulnerabilities.**

Instead, please email security reports to the project maintainer. Include:

- A description of the vulnerability
- Steps to reproduce
- The potential impact
- Any suggested fixes (if applicable)

### What to Expect

- **Acknowledgement** within 72 hours of your report
- **Status update** within 1 week, including whether the issue has been confirmed
- **Fix timeline** once the issue is confirmed, coordinated with the reporter
- **Credit** in the changelog (unless the reporter prefers anonymity)

## Security Design Principles

1. **Local-first** — Data lives on the user's device, encrypted at rest. No cloud sync, no server-side storage of plaintext.
2. **Zero-knowledge** — The recovery phrase is the only root of truth. No account recovery without it.
3. **Fail-closed** — Authentication failures, malformed input, and missing tokens result in rejection, not fallback.
4. **Deniability** — The duress code provides a plausible decoy account; its presence is indistinguishable from a fresh install.
5. **Minimal trust** — Mailbox and relay servers never see plaintext; all content is end-to-end encrypted.
