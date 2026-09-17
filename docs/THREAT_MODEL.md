# Threat model

## How to read this document

This file has two layers, and they serve two different readers.

- **The synthesis below (dated 2026-09-02) is authoritative.** It is the
  reader-facing threat model an external reviewer should start from: the assets,
  the adversary classes, the security properties as explicit claims, and — the
  part a reviewer spends the most time on — the metadata surface assembled in one
  place. It reflects the code as it stands today.
- **The phase-by-phase sections after it are a historical engineering log.** They
  were written as each build phase landed and record *why* each mechanism exists,
  which is valuable, but individual claims in them can lag the code. Where a later
  change superseded a phase note, that section carries a dated **Superseded**
  line pointing back here. When the two layers disagree, the synthesis wins.

The recovery-loss story that testers need ("what do I lose if…") is deliberately
**not** here — a 700-line threat model is the wrong place for it. See
[`RECOVERY.md`](RECOVERY.md), which is written for a user, not a reviewer.

---

# Synthesis (as of 2026-09-02)

## Assets — what is being protected

1. **Identity private keys.** The Ed25519 identity key (its public half *is* the
   account number and the .onion address) and the separate X25519 agreement key.
2. **The root recovery phrase**, from which every key deterministically derives.
3. **Message content and the contact graph** — what you said and, just as
   sensitive, *who you talk to*.
4. **Network location (IP).** The core anonymity property: peers and the network
   learn your onion address, never your IP.
5. **The fact that you run Molepipe and hold an identity** — itself a
   deanonymizing signal, especially on a shared device.
6. **Local data at rest**, against a stolen disk, a backup, or a coercer.

## Adversary classes — what each can and cannot do

The account number is the system's capability token: it equals your onion
address and is shared out-of-band. Most of the surface is scoped by whether an
adversary holds it, and whether you have accepted them as a contact.

| Adversary | Can | Cannot |
|---|---|---|
| **Network / global passive observer** | See that *some* onion published a descriptor and that Tor circuits carry traffic; attempt end-to-end timing correlation if positioned on both sides | Read message content; learn your IP from the onion; map the contact graph from content (all E2E-encrypted) |
| **A stranger who holds your account number** | Dial your onion; learn your display name, avatar, DH key, and *that you are online right now* (liveness oracle); send a friend request | Read messages; learn your mailbox relay; alter your contact/trust state; add themselves as a contact |
| **An accepted contact** | Message you; learn your mailbox URL (gated); see your presence; in a shared group, see the roster | Read your other conversations; impersonate a third party (signatures are per-identity); remotely wipe you (delete-for-everyone is honour-based and inbound-only) |
| **Your mailbox relay operator** (a server you do not control) | See which accounts drop off / pick up ciphertext for you, and when — a metadata channel | Read message plaintext; forge or reorder authenticated envelopes |
| **A friend-relay holder** (a contact who relays for you when you're offline) | See that a ciphertext blob is queued for you, and timing | Read plaintext; deliver to a non-approved holder |
| **Another app on the same phone** (shared 127.0.0.1) | Reach the loopback socket | Reach the control plane — held off by a per-process capability token; forge the token; read the private data dir (Android sandbox) |
| **Someone with your data directory at rest** | Mount an offline attack bounded by Argon2id + password strength; brute-force a 6-digit PIN if PIN unlock was enabled (no rate limit applies to a copy) | Recover keys without the password; roll a verified monotonic counter forward |
| **A coercer forcing you to unlock** | Obtain whatever the duress code opens | Distinguish the decoy from a real account by file shape; prove a real account existed (see the residual-tells list in the duress section) |
| **A compromised endpoint** (malware, debugger, root, or the app's own UID) | Read keys in memory and the onion key on disk while unlocked | — **out of scope by design**; see below |

## Security properties — claim → mechanism, and the honest limit

- **Message confidentiality + integrity.** XChaCha20-Poly1305 under an X25519
  ECDH key with per-direction HKDF labels; AAD binds sender|recipient. *Limit:*
  no app-layer forward secrecy — X25519 keys are static, so identity-key
  compromise exposes past messages at the app layer. Tor's rendezvous circuit
  gives transport forward secrecy; an app-layer ratchet is future work.
- **Sender authentication.** Dialing an onion authenticates the *recipient*, not
  the caller; the recipient issues a one-time challenge nonce (5-min TTL) and the
  sender signs `ctx‖nonce‖recipient‖sender-X25519` with their Ed25519 identity.
  Verified against the key the sender's account number commits to. Replay- and
  redirect-resistant.
- **Identity at rest.** `identity.enc` = AES-256-GCM under an Argon2id-stretched
  password (64 MiB, t=3). Wrong password / tamper fails authentication.
- **Contacts-only admission.** Messages are accepted only from accepted contacts;
  trust state changes only *after* signature verification, never on an
  unauthenticated request. Friend requests may arrive from strangers but are
  authenticated, de-duplicated, capped, and rendered as text.
- **Anonymity / location hiding.** Reachability is via a Tor v3 onion service;
  no IP is exposed. Inherits Tor's threat model wholesale (see out-of-scope).
- **Wire-version tolerance.** Signed wire types carry a version domain
  (`sigContextFor(v)`); verifiers accept the current and supported prior layouts
  so a protocol change is not a flag-day that bricks un-upgraded peers.
  `protoVerCurrent = 1` today, v2 domain reserved and frozen by a golden test.
  *Limit:* the ungated self-signed `Profile` card treats its `Ver` as a hint, not
  a hard selector, so a flipped byte cannot deny a valid card.

## Metadata surface — the reviewer's map

This is the part the phase log never assembles in one place. Tor hides your IP;
it does **not** hide these application-level observables. Each row: who can
observe it, and what they learn.

- **Liveness oracle (inherent).** `GET /p2p/profile` returns 200 when unlocked,
  503 when locked. Anyone holding your account number can poll your online state
  without consent and without appearing in your requests list. Inherent to a
  reachable onion; presence (🟢🟡🔴) is a stated feature. Removable only by
  serving the card to accepted contacts only — a product trade-off, not a bug.
- **Ungated profile card.** The same endpoint serves, to any holder of your
  account number: display name (attacker-relevant only as a label), X25519 DH key
  (needed so a stranger can encrypt a friend request / offline mail to you), and
  your **avatar hash**. It no longer serves your mailbox URL — that moved to the
  contact-gated `/p2p/contact-profile` channel.
- **Ungated avatar bytes.** `AvatarPath` serves raw avatar bytes by hash to any
  caller, globally rate-limited (over Tor there is no per-caller identity on an
  ungated GET, so the bound is global bandwidth, not per-peer). Content-addressed,
  so clients cache forever. A stranger with your account number can fetch your
  face; this is the deliberate "confirm you're adding the right person" affordance.
- **Presence sweep is a traffic signature.** Periodic liveness sweeps produce a
  repeating outbound circuit pattern that is observable to a network-level
  adversary.
- **Mailbox operator's view.** Offline delivery drops ciphertext at a relay you
  may not control. That operator sees which accounts store-and-fetch for you and
  when — plaintext stays sealed, but the drop-off/pick-up pattern is a metadata
  channel inherent to store-and-forward. Choosing a mailbox you run removes it.
- **Friend-relay holder's view.** When a contact relays for you, they see a queued
  blob and its timing (not plaintext), gated behind an explicit RelayGrant.
- **Group fan-out reveals group size and timing.** Group messaging is
  **client-side fan-out**: sending one group message dials each member in turn. An
  observer counting your circuits learns the group's size and that a send
  happened; there is no server that could hide this. Inherent to a serverless
  group model.

## Recovery model (reviewer summary)

`/api/recover` rebuilds the **identity only** from the recovery phrase — there is
no server-side escrow of chats, contacts, or groups (this is a P2P app). A
recovered device deliberately comes up as a **secondary** and obtains the
feature-set data by re-syncing from a surviving primary over the
enrolled-device-gated `/sync` path. So "recovery" means *recover-then-resync*.
Recovery phrase **plus** a surviving device = full restore; recovery phrase
**and no surviving device** = identity back, chat data gone — **by design**, not
a failure. The user-facing version of this is in [`RECOVERY.md`](RECOVERY.md).

## Out of scope — stated plainly

- **A compromised endpoint.** Malware, a keylogger, a debugger, root, or the
  app's own UID compromised can read keys from memory and the onion key from disk
  *while unlocked*. Local-device compromise is not defended on any platform; a
  background/foreground service lengthens the unlocked window, which is why Lock
  is always one action away.
- **Weak passwords.** Argon2id raises per-guess cost; it cannot save a guessable
  password.
- **Whole-directory theft against the PIN.** A copied data dir defeats the PIN
  attempt-cap (no rate limit applies to a copy); a 6-digit PIN is a small
  keyspace with only the raised Argon2id cost as a brake. Users who model
  whole-directory theft should not enable PIN unlock.
- **Physical-media forensics.** Secure-deletion overwrites are best-effort and do
  not defeat forensics on copy-on-write filesystems or wear-levelled SSDs; what
  protects wiped data is that it was encrypted at rest to begin with.
- **Global traffic correlation.** An adversary who can observe *both* ends of a
  conversation can attempt timing correlation — the standard Tor limitation, not
  something this app can fix above Tor.

---

# Historical engineering log (per phase)

The sections below are the original phase notes. They are kept for the "why"
behind each mechanism; where superseded, the dated line at the section head
points back to the synthesis above.

## What we protect

- **Private keys at rest.** The recovery phrase (root of all keys) is encrypted
  with AES-256-GCM under a key stretched from the user's password with Argon2id
  (64 MiB, t=3). An attacker with a copy of `identity.enc` but not the password
  cannot recover keys without an expensive brute-force against Argon2id, bounded
  by password strength.
- **Tamper detection.** AES-GCM authenticates the ciphertext and the format
  header (as AAD); any modification or a wrong password fails to decrypt rather
  than yielding usable-looking garbage.
- **Zero-knowledge recovery.** Keys derive deterministically from the BIP39
  phrase (BIP39 seed → SLIP-0010). No server is involved and no key escrow
  exists — recovery is possible only with the phrase.
- **Identity integrity.** The account number commits to the full Ed25519 public
  key with a checksum (v3-onion shape), so it is collision-resistant and a
  mistyped account number is rejected rather than silently resolving to a
  different key.

## What we do NOT protect against (yet or ever)

- **A compromised endpoint.** Malware, a keylogger, or an attacker with access
  to the machine while the identity is unlocked can read keys from memory or
  capture the password. Local device security is out of scope.
- **Weak passwords.** Argon2id raises the cost per guess but cannot save a
  guessable password. Users choose their own password strength.
- **A lost recovery phrase.** By design there is no recovery path without it.
  This is the intended trade-off of zero-knowledge; the UI must make it explicit.
- **Network-layer adversaries / metadata.** No networking exists in Phase 1.
  Traffic analysis, onion-service deanonymization, and delivery/metadata
  protection are deferred to the Tor/Arti and protocol phases and will get their
  own section here.
- **Forward secrecy & message security.** Not yet applicable — no messaging.
  Phase 4 will address end-to-end message encryption (and whether/when to add a
  ratchet) with an updated threat model.

## Phase 2 — localhost HTTP server

Phase 2 adds a loopback HTTP server that hosts the UI and exposes unlock /
identity / lock endpoints. The realistic new adversary is **a malicious website
the user visits in the same browser**, which can make requests to
`127.0.0.1`. Defenses:

- **Loopback binding.** The server binds `127.0.0.1` only and refuses to serve
  on any non-loopback address. It is never reachable from the network.
- **Host allowlist (anti-DNS-rebinding).** A rebinding attack points a domain at
  `127.0.0.1` so the browser sends requests carrying `Host: evil.com`. Every
  request must have a loopback `Host` (`127.0.0.1` / `localhost` / `::1`) or it
  is rejected.
- **Same-origin, fail-closed (anti-CSRF).** State-changing endpoints (`unlock`,
  `lock`) require an `Origin` header that is present *and* a loopback origin on
  our own port. A missing `Origin` is rejected, not assumed same-origin. No CORS
  headers are ever sent, so a cross-origin page cannot read any response.
- **Bearer session token.** `unlock` returns a random 256-bit token held only in
  memory; `identity` and `lock` require it. The account number — a
  deanonymization signal — is only ever returned behind this token. A malicious
  page cannot read the token (unlock's response is opaque cross-origin; the
  token lives in same-origin memory, not a cookie), so it cannot reach the
  account number. The tokenless `status` endpoint deliberately excludes it.

- **No external calls, browser-enforced.** The control server sends a strict
  Content-Security-Policy (`default-src 'none'`, `connect-src 'self'`,
  `script-src 'self'`, no external `img`/`font`/`style` hosts). The UI ships
  only vendored, self-contained assets (e.g. `@material/web`), so the page never
  contacts a third party — and the CSP makes the browser *enforce* that: a
  regressed or tampered bundle physically cannot fetch/exfiltrate to another
  host. This upholds the local-first, zero-external-calls posture by mechanism,
  not just by audit.

Not defended in Phase 2 (unchanged from above): a local process/malware on the
machine, which can read loopback traffic or memory. The password travels over
loopback in plaintext but never leaves the machine. There was no idle timeout or
rate limiting at Phase 2 — deferred, not needed for the local single-user
milestone. Failed-unlock rate limiting later landed (Local security §4), and the
Android port adds a device-local capability token on the control listener (see
the Android section), because there loopback stops being a single-user boundary.

## Phase 3 — Tor onion service (Arti sidecar)

Phase 3 hosts the identity as a Tor v3 onion service so it is reachable over the
network without revealing an IP. Arti runs as a **child process** (no Go/FFI
binding exists yet); this is a desktop-only mechanism and is revisited for
Android, where the same `tor.OnionService` interface is implemented over Arti's
mobile library instead.

New exposure — **the onion identity key is written to disk in plaintext while
the service runs.** The onion service key is the *same* Ed25519 identity as the
account (its public key IS the .onion / account number), and Arti's keystore
requires it unencrypted. Consequences and mitigations:

- **Impersonation risk.** Anyone who can read the key file while the service is
  running can run an onion service under your address. This is a weaker
  guarantee than the password-encrypted `identity.enc`.
- **Ephemeral on disk.** The key is written on unlock (service start) and
  **deleted on lock and on shutdown**, so it is present only while unlocked and
  serving — not at rest between sessions.
- **Permissions.** The key file is `0600` and every Arti directory is `0700`,
  inside the app's private data dir; this also satisfies Arti's own fs-mistrust
  checks (we do not disable them).
- Still out of scope (unchanged): a local process/malware running as the user
  can read the key while it is live. Local-device compromise is not defended.

**The onion never exposes the control plane.** The private unlock UI/API
(`/api/unlock`, `/api/identity`, the session token) is served only on the
loopback *control* listener, which rejects any non-loopback `Host`. The onion
service forwards to a *separate* public listener that serves only peer-facing
endpoints (a reachability placeholder today; the Phase 4 messaging protocol
later). So a peer — or anyone on Tor — reaching the .onion cannot touch unlock,
the account's session, or the local UI; those require local loopback access.

What Phase 3 *does* now provide: network-level reachability and location hiding
via the onion service, and Tor's transport encryption to the service. It does
**not** yet provide end-to-end message encryption or metadata protection between
users — that is Phase 4, which will get its own section.

## Phase 4 — peer messaging (v1)

> **Superseded in part (2026-09-02).** Two v1 limits below no longer hold: **offline
> delivery now exists** (a mailbox server + friend-relay store-and-forward path
> landed in phase 5.1), and **wire-version tolerance now exists** (`sigContextFor`,
> `protoVerCurrent`). The confidentiality/authentication mechanics described here
> are still accurate. See the synthesis for the current metadata surface, which
> includes the mailbox and relay channels this section predates.

Phase 4 lets two identities exchange messages over Tor, on the onion-facing
listener. A message is sent by dialing the recipient's onion and running a short
handshake.

What v1 protects:

- **Confidentiality + integrity.** Messages are encrypted with
  XChaCha20-Poly1305 under a key from X25519 ECDH between the two identities' DH
  keys, with **per-direction** HKDF labels (so the A→B and B→A keys differ).
- **Sender authentication — the gap Tor leaves.** Dialing an onion authenticates
  the *recipient* (their Ed25519 identity) but never the *caller*. So the
  recipient issues a fresh **challenge nonce**, and the sender signs a binding
  of the nonce to their Ed25519 identity key. The recipient verifies it against
  the Ed25519 key the sender's account number commits to. This binds the
  sender's ephemeral-per-connection X25519 key to their real identity, proves
  freshness (nonce is one-time, 5-min TTL), and is replay-resistant.
- **Contacts-only.** The listener rejects messages from any account not in the
  contact list, and caps message size.
- **Encrypted at rest.** Contacts and message history are stored in
  `messages.enc`, AES-256-GCM encrypted under a key derived (HKDF) from the
  identity's BIP39 seed — so who you talk to and what you said are readable only
  after password unlock, protected as strongly as the identity. Wrong key /
  tampering fails authentication; the file is `0600`.
- **Impersonation resistance.** A forged `Sender` fails signature verification
  (covered by tests); a replayed message fails the one-time nonce check.

What v1 does **not** provide (documented, deferred):

- **No application-layer forward secrecy.** The X25519 keys are static, so
  compromise of an identity key exposes past messages *at the app layer*. Tor's
  rendezvous circuit already gives forward secrecy in transit; an app-layer
  ratchet is future work.
- **No offline delivery.** Both peers must be online; there is no store-and-
  forward. A message to an offline contact simply fails to send.
- **Metadata.** Tor hides network location; it does not hide that two onions
  communicated from someone positioned to correlate, nor timing.

## Phase 5 — profile lookup + friend requests

> **Superseded in part (2026-09-02).** The ungated profile card **no longer carries
> the mailbox URL** — that moved to the contact-gated `/p2p/contact-profile`
> channel, so a stranger holding your account number can no longer learn which
> relay you use. The card now additionally carries an **avatar hash**, with the
> bytes served from a separate ungated, rate-limited `AvatarPath`. The liveness +
> name oracle described below is unchanged. See the synthesis metadata section for
> the current per-surface breakdown.

Adding people now goes through a profile lookup and a friend-request handshake
instead of both sides manually adding each other.

- **Profile lookup is a liveness + name oracle.** `GET /p2p/profile` is ungated:
  anyone who knows your account number can dial your onion and learn your
  self-chosen display name and that you are *currently online*, without your
  consent and without appearing in your requests list. This is an accepted
  trade-off (they already hold your account number, and it powers the "confirm
  they're real before you send a request" step). If that online-status leak is
  unacceptable for a given deployment, serve the profile to accepted contacts
  only and carry the name in the request instead.
- **Friend requests are authenticated.** A request/accept is signed by the
  sender's Ed25519 key over a fresh one-time challenge nonce, so a stranger can
  ask to connect but cannot forge who they are. The accept is bound to a
  per-request id, so a stale accept cannot resurrect a contact you have since
  declined or re-requested.
- **Trust changes only after authentication.** An inbound message is verified
  (nonce → signature) *before* any status check or the pending_out→accepted
  upgrade, so an unauthenticated peer can never alter your contact state.
- **Messaging stays accepted-contacts-only.** Requests may arrive from strangers,
  but messages are accepted only from contacts you have accepted.
- **Anti-spam.** Inbound pending requests are de-duplicated per account and
  capped; display names are attacker-controlled, so they are length-capped and
  rendered as text (never HTML), and always shown alongside the account number.

## Local security §1 — PIN unlock

PIN unlock adds a second, device-local copy of the session material (`pin.enc`)
so the app can be reopened without retyping the password. It changes the local
attack surface, so it is spelled out here rather than treated as a UI feature.

**What is unchanged.** `identity.enc` remains encrypted under the password
alone, with the same Argon2id parameters. Nothing about the PIN weakens the file
an attacker is most likely to obtain (a leaked backup, a copy taken off a
machine). Enabling the PIN requires the full password even from an
already-unlocked session, so an unattended unlocked screen cannot be converted
into a 6-digit way back in.

**Structure.** A random 32-byte device key encrypts the mnemonic + passphrase;
the PIN, stretched with Argon2id at a deliberately higher time cost (t=8), then
mixed with a device-local secret via HKDF, encrypts the device key. The
indirection makes the attempt-cap wipe cheap and leaves room to move the device
key into an OS keychain or TPM later without changing the file format.

**Online guessing** is bounded: the first two wrong entries are free, then an
escalating delay (capped at 5 minutes), and the 10th consecutive failure deletes
`pin.enc`. The counter is persisted, so restarting the app does not restore
attempts, and it is HMAC'd under the device secret, so it cannot be reset with a
text editor. The wipe removes the shortcut only — never the identity.

**What this does NOT protect against.**

- **A copy of the whole data directory.** Someone who takes the directory can
  mount an offline attack on the PIN — no rate limit can apply to a copy. Users
  who consider whole-directory theft part of their threat model should not enable
  PIN unlock. Genuine hardware binding needs an OS keychain or TPM, which a
  pure-Go, gomobile-portable core cannot claim today.
- **Restoring an older backup of the PIN state file** to roll the attempt counter
  back. Defeating that needs monotonic state we do not have.
- **A clock rolled backwards**, which can skip a backoff window. The hard
  attempt cap still applies, which is the limit that actually matters.
- **Forensic recovery of the wiped blob.** `pin.enc` is overwritten with random
  bytes before unlinking, but on copy-on-write filesystems (btrfs, ZFS, APFS)
  and SSDs with wear levelling the overwrite may not touch the original blocks.
  This raises the bar; it is not a guarantee and must not be described as one.

## Local security §2 — duress code (silent decoy)

A second code entered at the ordinary unlock prompt destroys local data and
opens a decoy account instead of unlocking. It exists for one scenario: someone
is standing over you forcing you to unlock. The design doc recommends the
visible-wipe variant as easier to get right; the silent decoy was chosen
deliberately, so the bar is higher and the residuals below are the price.

**What it destroys.** `messages.enc` (contacts and history) first, then
`pin.enc`, then `device.json` — the sync-linking state, since a linked device
left in place advertises that other devices and other copies of the data exist.
Then the friend-relay blobs, then the Tor onion key material. The real
`identity.enc` is overwritten in place before the decoy replaces it, because the
threat is a coercer who takes the disk now and obtains the password later.

**Why the decoy is convincing.** After the trigger the app is running a
*genuine* account — a real identity, a real onion, every screen reachable —
not a simulated mode. There is no `if decoy` branch anywhere, so there is no
special code path to detect. The decoy is generated at setup rather than at
trigger time, so a duress unlock costs the same derivation a real one does and
returns the *same* account every time it is used. The data directory afterwards
is file-for-file identical to a genuinely fresh install, `relay/` included.

**Why `duress.enc` always exists.** A file that appeared only for users who
configured a panic code would announce, to anyone imaging the disk, that a panic
code exists — the one fact the feature must hide. Unconfigured, it holds a real
decoy identity sealed under a random 32-byte code that is never stored, so it is
inert and indistinguishable from a configured one. It is written through the
same code path as `identity.enc`, in the same envelope format, so the two cannot
be told apart by shape either. The app never displays whether a code is set,
for the same reason.

**Residual tells — the honest list.**

- **Timing.** A duress unlock performs additional cryptographic derivations
  compared to a normal unlock. An adversary with precise instrumentation and a
  baseline could detect the difference, though Tor's latency typically dominates
  the visible response time.
- **The account number changes.** Anyone who already knows your real address
  sees a different one afterwards. Nothing can fix this: the decoy has to be a
  different account.
- **Secure deletion is best-effort.** Overwriting before unlinking defeats
  casual recovery, not physical-media forensics on a copy-on-write filesystem or
  a wear-levelled SSD. What actually protects the wiped data is that it was
  encrypted at rest to begin with.
- **A crash inside the single rename** between scrubbing the real identity and
  installing the decoy leaves an unreadable identity file — the visible-wipe
  outcome, not a data leak.
- **Nothing on the trigger path logs**, deliberately: a terminal line reading
  "duress triggered" would be a worse tell than the error screen this variant
  exists to avoid. The cost is that a partially failed wipe is silent.
- **Setup shares a path with ordinary settings.** API paths that reveal security
  configuration now share a common endpoint with non-revealing actions, and the
  request body is not logged, so the log proves nothing either way.

Verified on live Tor: the trigger returns in ~0.1s with a decoy account, the
decoy's onion service publishes and is **reachable from another instance over
Tor** (`reachable: true`), the real account becomes unreachable, the real
password stops working, and the data directory is file-for-file what a fresh
install has. Entering the code a second time is an ordinary unlock of the same
decoy — no second wipe, no new account.

## Local security §3 — "delete for everyone"

Deliberately **not** a remote wipe. A genuine remote-wipe capability aimed at
other people's devices is dangerous regardless of who holds it (compromise of
one account becomes a wipe button for everyone it ever talked to), inverts "your
device, your data" for the recipient, and is unenforceable anyway. This is the
Signal model instead: one message, from the person who sent it, removed from the
recipient's view because their client chooses to honour the request.

**What is authenticated, and what that does not cover.** The request carries a
signed authorization binding it to the sender's identity and the specific
message, so it cannot be forged, replayed at a third party, or forwarded. But
the signature only proves *who is asking* — it says nothing about what they may
delete. The authorization that matters is on the recipient's side: a request may
only remove a message whose stored direction is inbound **from that same
sender**. Without that check a contact could compute the ID of a message *you*
sent *them* and delete your own copy of your own words.

**Messages now carry a wire ID.** The local `chatstore.MessageID` is a content
hash over direction, peer and local receipt time, so the two ends of a
conversation derive *different* values for the same message and it is unusable
on the wire. Messages therefore carry an explicit sender-assigned ID inside the
AEAD — confidential and authenticated with the text, not forgeable metadata
beside it. Messages predating this format decode as bare text with no ID; they
still deliver and sync, they simply cannot be deleted remotely.

**Deletions are tombstoned.** `Merge` never deletes, so without a tombstone a
message removed on one device would be resurrected by the next sync with a
device that still held it, silently undoing the deletion. Tombstones union
across devices and are re-applied after the message union. They also block
re-delivery of an already-deleted message arriving late via mailbox or relay.

**Time-limited** to one hour, enforced on both ends — and on the recipient's
side against *their own* record of when the message arrived, not a timestamp the
requester controls, so it cannot be used to reach back into old history.

**What it cannot do, stated in the UI in these words.** A modified client can
ignore the request. An offline recipient may never receive it (delivery is
best-effort direct; there is no retry queue). Anyone who already read or
screenshotted the message still has it. The confirmation dialog says "that is
not a guarantee" rather than implying the message is unrecoverable, and the
result reports honestly when the peer could not be reached.

## Local security §4 — failed-unlock guard + erase-after-N

The password unlock prompt now carries the same kind of attempt guard the PIN
shortcut always had, plus an opt-in policy to erase the account after too many
failures. It changes the local attack surface, so it is spelled out here.

**Backoff.** A persisted counter in `unlock_guard.json` applies the *same*
escalating delay as the PIN (`internal/unlockguard`): the first two wrong
passwords are free, then the wait doubles each attempt up to five minutes. It is
enforced *before* the Argon2id derivation runs, so a throttled attempt is
refused rather than merely delayed — real rate limiting, not a slow path in
front of an attempt that still executes. The counter is HMAC'd under the device
secret, so it cannot be reset with a text editor, and persisted, so restarting
the app does not restore attempts. This closes the "no rate limiting yet" gap
the Phase 2 note left open for the password path.

**Erase-after-N (opt-in, off by default).** When the user turns it on, the Nth
consecutive failed unlock runs the *same* wipe as lock-screen account removal —
`identity.enc`, `duress.enc`, messages, PIN, device, relay, Arti key, autostart
entry — and returns the app to onboarding. It is the coercion-and-brute-force
answer that sits alongside the duress code: the duress code is for *"unlock it
now,"* this is for *"I'll take the disk and guess later at the keyboard."* The
floor is three attempts and the default is ten; changing the setting requires
re-entering the full password, exactly like arming the PIN or the duress code,
so an unattended unlocked screen cannot be turned into a delayed self-destruct.

**Honest edges.**

- **Any failed unlock counts, not just a wrong password.** `identity.enc` is
  AES-256-GCM; a wrong password and a genuinely corrupt file both fail
  authentication identically, so a corrupt file counts toward the threshold. The
  UI says "any failed unlock counts" and, because the wipe is local, that the
  recovery phrase still restores the account — the erase is not data loss for
  anyone who kept their phrase.
- **A whole-directory copy defeats it, exactly as for the PIN counter.** Someone
  who can write the data directory can restore an older `unlock_guard.json` to
  roll the counter back, or corrupt it — which fails *safe*: an unauthenticated
  counter is treated as a clean slate with the erase policy **disabled**, never
  triggered. That is a deliberate choice (never erase on a policy we cannot
  verify) whose cost is that the same attacker can also zero the backoff. It is
  not a new capability: that attacker already holds `identity.enc` for an offline
  attack and can delete everything outright. The guard defends the
  attacker-at-the-keyboard-without-file-access case, the same one the PIN cap and
  duress code address.
- **The trigger path is silent.** The erase fires from inside `handleUnlock`,
  which is also the duress trigger path, so it logs nothing — a line reading
  "account erased" would be the tell the duress wipe truncates the run log to
  avoid. A partially failed wipe is therefore silent, the same trade the duress
  section accepts.
- **`unlock_guard.json` marks a used device.** It exists only after a failed
  unlock or once the policy is set, so both wipe paths remove it and a device
  that has never failed an unlock keeps a fresh-install-clean directory — the
  same fresh-install parity the missing-`relay/` and leftover-`duress.enc` bugs
  taught, and it is covered by the removal parity test.

## Lock-screen account removal

Someone who has lost both their password and their recovery phrase has no way
back into their account — that is the intended consequence of zero-knowledge —
but they must still be able to reclaim the device. `/api/forget-identity` is
therefore reachable **without any credential**, since the people who need it are
by definition unable to produce one.

**Why an uncredentialed destructive endpoint is acceptable here.** On desktop it
adds convenience, not capability: anyone who can click the button can already
delete the data directory. The mitigations are a typed `DELETE` confirmation
(so it cannot be a stray click on a locked device) and the standard origin
guard, which still fails closed — a malicious web page cannot wipe the account
just because no token is required.

**Where that equivalence weakens.** On the eventual Android build, clearing app
data means a trip through system Settings, so a button inside the app is a
genuinely easier drive-by path than what exists today. That is a Phase 7
consideration, not a reason to change the design now.

**It removes everything, and leaves no trace of what was there.** The same wipe
as the duress path (`messages.enc`, `pin.enc`, `device.json`, the relay blobs,
Arti key material) plus `identity.enc` and `duress.enc`, which the duress path
deliberately keeps. A fresh install carries no `duress.enc` until its first
unlock, so leaving one behind would make a removed device distinguishable from a
new one — the same class of bug as the missing `relay/` directory found earlier.
The resulting directory is compared against a genuinely fresh install in the
tests, because that comparison is what catches this.

**It is safe while unlocked.** Nothing stops the endpoint being called from a
lock screen in one tab while another holds an unlocked session, so it stops the
onion, clears the session and locks the vault first — otherwise the background
loops would keep dialling contacts for an account whose files are gone.

Having the recovery phrase means nothing is actually lost: removal lands on the
onboarding screen, where restoring from the phrase yields the same account
number. `handleRecover` deliberately still refuses to overwrite an existing
identity — routing through an explicit removal keeps recovery non-destructive.

## Desktop packaging (Wails window + tray)

This phase puts the existing server in a native window with a tray icon. It is a
different way to **display** the same server, and the security model is
deliberately unchanged: same loopback control listener, same separate
onion-facing listener, same host allowlist, same fail-closed origin guard, same
CSP, same session token. `cmd/server` is untouched and still works.

**Why none of those needed changing.** The webview is pointed at
`http://127.0.0.1:<port>` — the running server's real URL — rather than being
fed the UI through Wails' own asset scheme. The page therefore has a genuine
loopback origin, and the requests it makes carry exactly the `Origin` and `Host`
headers the guards already expect. This was verified on the packaged build, not
assumed: `window.location.origin` is the loopback origin, and a state-changing
POST from the page is accepted while the same POST with a foreign or absent
`Origin` is still refused.

Serving the UI from Wails' asset scheme would instead give the page a `wails://`
origin, which the origin guard rejects — and the only way to make that work is
to weaken the guard, taking the anti-CSRF property with it. That trade was
available and was not taken.

New exposure, and the honest version of it:

- **Closing the window does not lock the app.** That is the point of the tray —
  messages can only arrive while the app is running — but it means the process
  keeps the unlocked identity in memory, and keeps the unencrypted onion key in
  the Arti keystore, after the window disappears. Someone who assumes closing a
  window ends a session would be wrong. Mitigations: the tray's **Lock** item
  does exactly what `/api/lock` does, and the **first** time the window is
  closed the user is told the app is still running — a native notification at
  that moment, plus an in-app notice held until the window is looked at again.
  Neither message contains anything about the account.
- **Quit is the only exit, and it shuts down gracefully.** Quitting runs the
  same `Shutdown()` as Ctrl-C on `cmd/server`, synchronously, before the process
  exits — so the onion key is deleted on quit exactly as Phase 3 promises, and
  the data-directory lock is released. Verified on the packaged build by
  checking the key file is gone and that a relaunch immediately afterwards
  succeeds. (Implementation note: Wails routes its own quit through the
  close handler, so hiding the window on close without distinguishing a real
  quit produces a process that cannot be exited at all. It is a one-line
  distinction, and it is load-bearing.)
- **Start at login writes one file outside the data directory.** Turning the
  setting on writes `~/.config/autostart/tor-messenger.desktop`, naming the
  binary and the data directory. Everything else this app owns lives inside the
  data directory, so no existing wipe would have reached it — and a file called
  "Molepipe" surviving a **duress** wipe is that wipe announcing itself to
  exactly the person it is meant to hide from. Both wipe paths (duress and
  account removal) therefore delete it unconditionally, whether or not the app
  was launched from the desktop build, and that is covered by a test. The
  setting is off until deliberately turned on.
- **A third rendering engine.** The UI now also runs in WebKitGTK, alongside
  whatever browser the `cmd/server` path uses. It enforces the same CSP, and
  the packaged build is compiled with Wails' `production` tag so the webview
  inspector is not available; but it is additional attack surface, and the
  system WebKit's patch level is now part of this app's exposure.
- **A session-bus presence.** The tray is a StatusNotifierItem and the
  first-close notice is a `org.freedesktop.Notifications` call, both on the
  user's session bus. Any process on that bus can see that Molepipe is
  running and read the notice text; neither carries an account number, contact,
  or message. This is the same class of local-visibility as the process name
  itself, which was always visible.
- **`desktop.json`** in the data directory records only that the one-time notice
  has been shown — nothing about the account. It is nonetheless removed by both
  wipe paths, because it is created the first time the window is closed: a
  directory that still had it would be visibly a *used* directory, and the one
  the duress wipe presents is supposed to look untouched. Same class as the
  missing `relay/` directory and the leftover `duress.enc` found earlier, and
  caught the same way — by asking what a fresh install does *not* have.

Not defended, unchanged from earlier phases: a local process running as the user
can read loopback traffic, the unlocked identity in memory, and the onion key
while the app is unlocked. Running in the background lengthens the window during
which that is true — which is the cost of receiving messages at all, and is why
Lock is one click away in the tray.

## Android port (gomobile bind)

The Android build wraps the **same** server in a `WebView` instead of a browser
or a Wails window. `backend/mobile` is a thin gomobile binding — the mobile
counterpart of `cmd/server` — exposing `Start(dataDir)/Stop/URL/PublicAddr`. The
security model carries over the desktop pieces unchanged: same loopback control
listener, same separate onion-facing listener, same host allowlist, same
fail-closed origin guard, same CSP, same session token. The WebView is pointed at
the server's real `http://127.0.0.1:<port>` URL (not an `app://`/asset scheme),
so the page has a genuine loopback origin and its requests carry the `Origin` and
`Host` headers the guards accept — the same reasoning that kept the desktop
packaging from having to weaken any guard.

That reasoning is necessary but **not sufficient on Android**, and this is where
the desktop model needed extending. On a desktop, loopback is a single-user
boundary, so "any local process is out of scope" holds. On a phone it does not:
`127.0.0.1` is reachable by every installed app, and a native caller — unlike a
browser — forges `Host` and `Origin` at will, so the host allowlist and origin
guard (shaped for a malicious web *page*) do not separate apps. The defense that
does is a **device-local capability token** — see the first bullet below.

New exposure specific to Android, and the honest version of it:

- **Loopback is shared between apps, so the control plane needs a secret another
  app cannot forge.** On Android, loopback is shared between apps and native
  callers can forge HTTP headers — so browser-origin-based defenses are
  insufficient. A per-process **capability token** gates all control-plane
  endpoints. The backend mints a random secret at startup (`Server.controlToken`);
  the shell hands it to the first-party UI out-of-band in its bootstrap URL
  (`?ct=…`, delivered in-process to the WebView, never over the shared socket),
  and `controlGuard` requires it on every `/api/*` request (`X-Control-Token`,
  compared constant-time, empty token rejects — fail-closed). Static assets stay
  tokenless so the page can bootstrap; they ship in the APK and carry nothing an
  on-device app cannot already read. The UI reads the token once, caches it in
  `sessionStorage` (so an in-tab reload still works) and scrubs it from the
  address bar; a co-installed app never sees it. So on Android it is this token —
  not the forgeable `Host`/`Origin` headers — that separates apps, and the
  session token (proving *unlocked*) still gates authenticated endpoints on top.
  The desktop and Wails builds carry the same token for one code path; there it
  is belt-and-suspenders, since local processes are already out of scope.
- **The peer challenge jar is bounded.** `/p2p/challenge` on the onion-facing
  listener is unauthenticated (anyone on Tor may ask), and each call stored a
  nonce for 5 minutes with only expiry-based pruning — an uncapped
  memory-exhaustion vector, the same class the `/sync` body cap and
  `maxPublicInFlight` guard. The jar is now capped (`maxNonces`) with
  oldest-eviction, so a flood is bounded and a legitimate peer's fresh challenge
  still always succeeds. This applies on every platform, but matters most on the
  always-on phone node.
- **Android system log cannot be wiped by the application, so nothing
  account-bearing may reach it.** The application never writes account data to
  the platform log channel. A Go runtime *panic* still prints to stderr/logcat
  before the process dies; that path carries no account data by construction.
- **Platform backup is disabled by construction.** Android backup is disabled in
  the manifest (`allowBackup="false"`, `fullBackupContent="false"`) and
  `data_extraction_rules.xml` excludes every domain from both cloud-backup and
  device-transfer, preventing wiped data from surviving through platform backup
  channels.
- **The data directory must be supplied, never defaulted.** `identity.NewStore("")`
  falls back to a desktop OS config directory that does not exist under Android's
  per-app storage; `mobile.Start` rejects an empty `dataDir` outright, so the
  caller must pass `Context.getFilesDir()`. This is the "no desktop filesystem
  assumptions" constraint enforced at the one entry point.
- **Tor runs in-process via Arti, and the onion key never enters the JVM.** The
  Android onion service is `torhost`, a Rust shim over `arti-client` linked into
  the backend by cgo (`backend/internal/tor/artihost`), driven through the same
  `tor.OnionService` interface as the desktop sidecar. The architecture choice
  is load-bearing: because Go calls Rust over a C ABI rather than Kotlin calling
  Arti over JNI, the onion secret key is handed to native code as raw bytes and
  is never marshalled into a JVM `byte[]` (where it would be subject to GC
  copying and hard to zero). Key handling matches Phase 3: the key is inserted
  into Arti's on-disk keystore under the data dir only while the service runs
  (an in-memory keystore is not yet offered by arti-client), swept on start
  after a crash, and wiped on stop. The `.onion` published equals the account
  number, because the shim hosts under our pre-derived expanded key rather than
  letting Arti generate one. This is proven end to end on a device: arti
  bootstraps in-process, publishes the descriptor, and the service becomes
  reachable on the live Tor network. `newOnionService` still returns nil on
  non-Android builds (Tor-disabled, `cmd/server -no-tor` parity), which is what
  the host tests exercise.
- **fs-mistrust is disabled for Arti's directories on Android, and that is
  sound here.** On desktop, Arti uses `fs-mistrust` to refuse to run if its
  state/keystore directory is readable by other users — a real protection on a
  shared multi-user machine. Android's per-app storage does not fit that Unix
  ownership model (fs-mistrust would reject it outright, before any network
  activity), so the shim sets `dangerously_trust_everyone()`. The guarantee is
  not lost, it is provided by a different layer: the data directory is the app's
  private `filesDir`, created `0700` and owned by the app's own UID, and the
  Android application sandbox already prevents other apps from reading it. The
  threat fs-mistrust defends against on desktop (a different local user reading
  the key) does not exist between sandboxed Android apps.
- **The data-directory lock survives a process kill.** `datalock` uses `flock`,
  which the `unix` build tag covers on Android; the kernel drops it when the
  process dies. Android killing the app (task-swipe, OOM) therefore never leaves
  a stale lock that would brick the next launch — the failure mode a bare
  lock-file scheme would have had on a platform where abrupt kill is routine.

Not defended, unchanged from earlier phases and inherited here: a process running
**as the app's own UID** — the app itself compromised, or a debugger/root — can
read loopback traffic, the unlocked identity in memory, and the onion key while
unlocked. That is distinct from another *installed app* (a different UID), which
shares the loopback socket but is now held off the control plane by the
capability token above; the same-UID adversary is the one the token cannot help
against, and it is out of scope by the same logic as desktop endpoint compromise.
A foreground service lengthens the window during which that is true — the cost of
receiving messages — which is why Lock remains one action away.

**Exercised live, not only reasoned about (2026-08-23).** Three properties above
were checked on a running build rather than argued from the code:

- **The dial path works on-device.** On the emulator (fresh debug APK) the app
  friended and exchanged messages *both ways* with a host peer over the live Tor
  network; the emulator's first outbound dial took ~8 s to build a circuit and
  succeeded, exercising the cancellation-bounded `artihost` dial (the C dial now
  takes a `timeout_ms` derived from the caller's context deadline, so a hung
  circuit can no longer pin the calling thread past its budget). Driving the app
  for this used the WebView's own DevTools channel — debug builds are
  `debuggable`, so the control token never had to leave the page — which is a
  reminder that a **debug** APK exposes an in-process inspection surface a release
  build must not ship with.
- **Battery optimization does not kill the receiver.** Forced deep Doze
  (`deviceidle force-idle`) with the app on the exemption allowlist left the
  process alive and the foreground service still `isForeground` under the
  `specialUse` type, network- and wakelock-exempt. The app requests that
  exemption (`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`) precisely so an always-on
  onion is not deferred in idle. Not covered here: an OEM's own aggressive
  battery manager on a physical handset, which no allowlist entry fully binds.
  Note the deliberate non-feature: there is **no auto-start on boot**, and that is
  correct — after a reboot the vault is locked and the onion key derives from the
  *unlocked* identity, so the device hosts no onion and can receive nothing until
  the user opens the app and unlocks. A boot receiver would revive only a locked,
  hostless backend; reachability after reboot inherently requires the human.
- **Multi-device sync moves no plaintext to an unauthenticated party.** Pairing,
  device enrollment, state sync and image-blob backfill were run across two
  devices of one account over real Tor (on host instances, because the emulator
  already held a real account and one account per device is the rule). A second
  device enrolls only via the identity-key + device-key handshake, and the image
  bytes a second device is missing are pulled over `/sync/attachment` behind the
  *same* enrolled-device gate as the message history — verified byte-exact. The
  bytes are portable between a user's devices only because every device re-derives
  the one store key from the shared seed; a device that is not enrolled derives
  nothing and the endpoint refuses it.

## Assumptions

- The Go standard library crypto, `x/crypto` (Argon2id, Curve25519, SHA-3), and
  `go-bip39` are correct and unmodified.
- The OS RNG (`crypto/rand`) is a secure source of randomness.
- The user's OS enforces the `0600` file permissions on `identity.enc`.

## Non-standard choices worth auditing

- The X25519 agreement key reuses a SLIP-0010 Ed25519 leaf's 32 bytes as a
  Curve25519 scalar (clamped per RFC 7748). SLIP-0010 specifies that output as
  an Ed25519 seed; using it as an X25519 scalar is non-standard but sound, and
  is covered by a DH round-trip test. Signing and agreement use distinct
  derivation indices, so no single scalar is shared across both operations.
