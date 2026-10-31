# Audit — v2 Public-Key / Double-Ratchet Work + General Project Review

**Date:** 2026-09-18
**Scope:** the newly-added "refreshable public key" feature (signed prekeys, one-time
prekeys, X3DH session establishment, Double Ratchet) and a general pass over the
backend. Read-only audit; no code was changed.

**Method note:** `go build ./...` and `go vet ./...` are both clean, and
`go test ./internal/crypto ./internal/protocol` passes. **None of that is evidence
of health here** — the compiler and vet happily build dead packages, and the tests
that "pass" include a vacuous one (Finding 5b). The findings below come from tracing
call graphs and reading the code, not from the build.

---

## TL;DR — ranked

> **Scope decision (user, 2026-09-18):** there are no older peers in the wild — no
> deployed v1 accounts to stay compatible with. The whole fleet is rebuilt from this
> source together. That **nullifies the backward-compat impact of Finding 1** (see the
> re-rank note in that section); it is left here as a cosmetic/consistency item, not a
> live break. Findings 2–4 are unaffected.

| # | Severity | Finding |
|---|----------|---------|
| 1 | ~~HIGH — live~~ → **LOW (compat out of scope)** | `protoVerCurrent` was bumped to `2`, moving every handshake signature into the `"onion-chat/v2"` domain. With no v1 peers to talk to and a coordinated fleet rebuild, this is internally consistent and harmless. It remains a *cosmetic* problem: the constant advertises v2 while v2 is unwired (Finding 2), and the code's own comments still say "protoVerCurrent is still 1," so the file contradicts itself. |
| 2 | **HIGH — feature not delivered** | The entire v2 system — X3DH, Double Ratchet, signed/one-time prekeys, **and the key rotation the request was about** — is **not wired into the running app**. It compiles and has unit tests, but nothing in the shipping build ever calls it. Keys never rotate because nothing ever creates one. The live message path is still v1 static X25519. |
| 3 | **MEDIUM — doc integrity** | `docs/SECURITY_RATCHET.md` claims forward secrecy is "Protected Against (v2)" and shows a 16/16 "✅ Pass" test table. Both are false for the shipping build (FS is off; one of those tests is vacuous). A security doc that overstates guarantees is itself a risk — it's what lets this ship believing FS is on. |
| 4 | LOW–MED — latent | A cluster of real bugs **inside the unwired subsystem** (unbounded skip DoS, a vacuous test, a dead mutex with pointers escaping the lock, ratchet-boundary message loss, an X3DH spec deviation, a dropped `SessionID`). Not reachable today, but each becomes live the moment Finding 2 is addressed and the subsystem is wired. |

---

## Finding 1 — `protoVerCurrent = 2` (compat impact out of scope; now a consistency issue)

> **Re-rank (2026-09-18):** the user confirmed there are no older peers and the fleet is
> rebuilt together, so the cross-version break described below **cannot occur in
> practice** — every device is on the same v2 domain. Downgraded from HIGH-live to LOW.
> What remains is that the constant claims v2 is on while v2 is unwired (Finding 2), and
> the surrounding comments still say it's `1`. The original break analysis is kept below
> for the record and in case a v1 peer ever does appear.

`backend/internal/protocol/protocol.go:39`

```go
protoVerMin     uint16 = 1
protoVerCurrent uint16 = 2
```

`sigContextFor` is domain-separated by version (`protocol.go:529`):

```go
case 1: return []byte(sigContext)      // "onion-chat/v1"
case 2: return []byte("onion-chat/v2")
```

Every handshake blob is signed and verified under `sigContextFor(protoVerCurrent)`
— i.e. under `"onion-chat/v2"` right now:

- challenge — `client.go:67`, `protocol.go:325`
- message (v1 static path, the live one) — `protocol.go:377`, `client.go:257`, `client.go:304`
- friend-request / friend-accept — `client.go:203`, `client.go:220`
- contact-profile — `protocol.go:354`, `client.go:141`
- mailbox authenticator — `mailbox.go:58`

Only **profile-card** verification is version-tolerant — it tries every supported
version via `candidateVersions` (`client.go:110`, `client.go:122`). Nothing else does.

**Consequence.** A build with `protoVerCurrent = 2` and any peer still on a v1 build:
the profile card still verifies (tolerant fallback), so you can *see* the contact —
but the challenge handshake is signed v2 / verified v1 and **fails**, so messaging,
friend requests, contact-profile and offline mail all silently fail signature
verification. Within a fully-rebuilt fleet everything is self-consistent and works;
the break is strictly against not-yet-rebuilt peers.

**Why it reads as unintended.** The code describes a world where this constant is
still `1`:

- `protocol.go:534` — *"v2 signature domain, RESERVED. protoVerCurrent is still 1, so neither negotiateVersion nor candidateVersions ever yields 2 in production… The commit that ships a real v2 layout raises protoVerCurrent to make it reachable."*
- `protocol.go:567`, `chatstore.go:1054` — same "protoVerCurrent stays 1" assumption.

So the constant was raised, but (a) the comments were never updated, and (b) the
"real v2 layout" that was supposed to accompany the bump was never wired (Finding 2).
Net effect: the bump did **not** turn on the ratchet it was meant to protect, but it
**did** change the signature domain for every live operation — the worst of both.

**Fix options:**
- If v2 is not ready to ship (it isn't — see Finding 2): **set `protoVerCurrent` back to `1`.** v2 stays reserved and testable exactly as the comments describe. This is the correct action today.
- If a coordinated wire break is genuinely wanted, it must be deliberate and fleet-wide (the same rebuild the `sprightly-scribbling-patterson` plan already schedules for the avatar/mailbox change), the stale comments must be corrected, and the handshake-verify paths should adopt `candidateVersions`-style tolerance if any transition window is desired.

---

## Finding 2 — The v2 feature is built but not connected

This is the direct answer to *"a whole bunch of work was done with a new public key
feature that can be refreshed."* The work exists; nothing runs it.

**Proof (dependency graph of the shipping entrypoints, not a grep):**

```
$ go list -deps ./mobile/... ./cmd/... | grep -c internal/session
0
```

`internal/session` — the session manager and the prekey-lifecycle/rotation manager,
741 lines — is imported by **nothing** and has **no test files**. `internal/crypto`
*is* in the shipping deps, but only for its v1 primitives; the v2 functions in it are
called only by their own tests.

Every v2 entrypoint has no production caller (verified repo-wide, all build tags):

| Symbol | Location | Called by |
|--------|----------|-----------|
| `Peer.SetSessionManager` | `protocol.go:305` | nobody (so `p.sessionMgr` is always nil) |
| `Peer.ReceiveRatchet` | `protocol.go:406` | nobody (incoming v2 messages are never dispatched) |
| `SendMessageV2` | `client.go:270` | nobody (the live send path is `protocol.SendMessage`, `outbox.go:170`) |
| `X3DHInitiate` / `X3DHRespond` | `prekey.go:163/225` | tests only |
| `Manager.GetResponderSession` etc. | `session/manager.go` | tests only (package unimported) |
| `AddSignedPrekey` / `GetCurrentSignedPrekey` / `DeleteExpiredSignedPrekeys` | `chatstore.go:652/640/688` | wired only into the unimported `session` package |
| `PrekeyBundlePath` | `protocol.go:84` | defined as a path constant; **no HTTP route serves it** (not registered in `internal/api`) |

A structural tell confirms the two halves were never meant to meet: the concrete
`session.Manager.GetOrCreateSession(key SessionKey, rootSecret []byte, …)` has a
different signature from the `protocol.SessionManager.GetOrCreateSession(account string)`
interface it would have to satisfy — `session.Manager` does not implement the
interface the protocol layer expects.

**Consequence.** The "refreshable public key" never refreshes — no signed prekey is
ever generated, published, rotated, or retired in the running app, because the
lifecycle manager that would do it is never instantiated. There is no forward secrecy
in the shipping build; messaging is still v1 static-static X25519 (`Receive` /
`SendMessage`).

**This is a feature-completeness gap, not an exploit.** The remaining crypto findings
(Section 5) are latent because of it.

---

## Finding 3 — `docs/SECURITY_RATCHET.md` overstates what ships

- §13 lists **"Passive interception of messages (forward secrecy)"** under *Protected
  Against (v2)*. False for the shipping build — v2 is unwired (Finding 2), so there is
  no forward secrecy.
- §15 is a 16-row table, every row **"✅ Pass."** At least one ("Skipped key limit —
  MAX_SKIP enforcement") tests nothing (Finding 5b), and the doc's §6/§10 claim
  "MAX_SKIP limit (1000) prevents resource exhaustion" — which the code does not do
  (Finding 5a).
- §1 / §5 domain strings (`"onion-chat/v2"`) are consistent with the code, but the doc
  presents the whole v2 stack as operational. It should state plainly that v2 is
  **implemented but not yet wired**, and that FS is not active.

Recommend a header banner: *"Status: v2 designed and unit-tested; NOT wired into the
running build. Live crypto is v1 static X25519."*

---

## Section 5 — Latent findings inside the unwired v2 subsystem

Each is real code, currently unreachable (Finding 2). Flagged because the intent is
clearly to wire this up, and every one becomes live the moment that happens.

### 5a — `MaxSkip` / `MaxSkipKeys` are never enforced → remote DoS
`ratchet.go:230` `AdvanceReceivingChain`:

```go
for i := s.RecvCounter; i < msgNum; i++ {   // msgNum is attacker-controlled uint32
    ck, mk, _ := kdfCK(s.ReceivingChain[:])
    s.SkippedKeys[id] = mk
}
```

`msgNum` comes off the wire. There is no `msgNum - RecvCounter > MaxSkip` check and no
cap on `len(SkippedKeys)`. A single message with `msgNum` near 2³² drives ~4 billion
HMAC iterations and unbounded map growth. `MaxSkip = 1000` / `MaxSkipKeys = 10000`
(`ratchet.go:17-18`) are defined and **referenced only by a test** — dead constants.
**Fix:** reject when the gap exceeds `MaxSkip`, and cap total stored skipped keys at
`MaxSkipKeys`, before the loop.

### 5b — The "MAX_SKIP enforcement" test is vacuous
`comprehensive_test.go:216`:

```go
for i := 0; i <= MaxSkip; i++ {
    ...
    _, err := receiver.AdvanceReceivingChain(uint32(i))  // called for EVERY i, in order
    if i > MaxSkip && err == nil { t.Fatalf(...) }        // i never exceeds MaxSkip → dead branch
}
```

Two independent defects: (1) the loop bound is `i <= MaxSkip`, so `i > MaxSkip` is
never true and the enforcement assertion is unreachable; (2) it calls
`AdvanceReceivingChain(i)` for every sequential `i`, so `RecvCounter` advances by one
each time and **nothing is ever skipped** — it tests the in-order path, not skipping.
This is the row the security doc reports as "✅ Pass." **Fix:** advance to
`RecvCounter = 0`, then attempt a single receive at `msgNum = MaxSkip + 1` and assert
it errors.

### 5c — `RatchetSession.mu` is dead; session pointers escape the manager lock
`RatchetSession` carries a `mu sync.Mutex` (`ratchet.go`) that **no method ever
locks**. The manager's `RWMutex` only guards the maps: `GetSession` /
`GetOrCreateSession` return the `*RatchetSession` and release the lock, after which
callers mutate `ReceivingChain` / `RecvCounter` / `SkippedKeys` with no lock held
(`protocol.go:434`, `client.go`). Worse, `Manager.SaveAll` (`manager.go:217`) iterates
a session's `SkippedKeys` map under only an `RLock` while a concurrent receive could be
writing it — a classic concurrent-map read/write panic. Two messages from one peer
processed concurrently race the same session. **Fix:** either lock `RatchetSession.mu`
inside every ratchet method, or have the manager expose encrypt/decrypt methods that
hold a per-session lock for the whole operation (don't hand out the raw pointer).

### 5d — `DHRatchet` loses the previous chain's messages
`ratchet.go:177`. On a DH-ratchet step the Signal spec first skips (and stores) the
remaining message keys of the *current* receiving chain up to `header.PN`, then resets.
This implementation jumps straight to deriving the new receiving chain and sets
`RecvCounter = 0`, never harvesting the old chain and never reading the header's
`PrevChainLen`/PN. Any straggler from the previous chain that arrives after the ratchet
step is undecryptable → message loss on out-of-order delivery across a ratchet
boundary. **Fix:** implement `SkipMessageKeys(until: header.PN)` on the old receiving
chain before the DH step, per Signal §3.5.

### 5e — X3DH omits the `F = 0xFF…` prefix (spec deviation, minor)
`deriveX3DHSecret` (`prekey.go:~276`) feeds the raw DH concatenation into
`hkdf.New(sha256.New, dhOutputs, nil, info)`. Signal's X3DH prepends 32 `0xFF` bytes to
the DH inputs for domain separation / curve compatibility. Not exploitable here (both
ends derive identically), but it diverges from the spec the doc claims to follow.
`info` binding and nil salt (→ HKDF's internal zero salt) are otherwise fine.

### 5f — `SessionState` drops `SessionID` on persist/reload
`crypto.RatchetSession` has a `SessionID` that is mixed into `HeaderBytes`
(`ratchet.go:40`) and therefore into AAD binding. `session.SessionState` (`manager.go:21`)
has **no `SessionID` field**, and `sessionToState` / `stateToSession` never copy it — a
reloaded session comes back with a zero `SessionID`. If that binding is load-bearing,
messages won't verify across a restart. **Fix:** persist `SessionID`.

### 5g — `internal/session` has zero tests
`go test ./internal/session` → `[no test files]`. The 741-line package that would own
rotation, grace-period deletion, and skipped-key persistence is entirely untested.

---

## Section 6 — General project notes (non-crypto)

- **Build health:** `go build ./...`, `go vet ./...` clean; `go test` green across
  `crypto`, `protocol`, and the wider tree that was exercised. (Reminder: this does not
  cover the dead packages' correctness — see method note.)
- **v1 live path looks sound:** `Receive` (`protocol.go:366`) keeps the right order —
  consume nonce → verify signature → status gate → decrypt → deliver — so an
  unauthenticated sender can neither be delivered nor mutate trust state. The
  mailbox/ID domain pinning (`mailbox.go:idBlob` pinned to v1, only the authenticator
  version-aware) is a genuinely careful design and should be preserved.
- **Comment/const drift is the through-line.** Finding 1 and the stale
  `protoVerCurrent` comments (protocol.go:534/567, chatstore.go:1054) all stem from a
  constant being changed without its documentation. Worth a sweep.
- **Dead code:** `internal/session/*` (741 lines) and the v2 entrypoints in
  `protocol`/`client`/`crypto` are unreferenced. Either wire them (the intended path)
  or move them behind a clearly-marked `experimental`/`wip` boundary so they can't be
  mistaken for shipping code.

---

## Recommended triage order

1. **Now:** add the status banner to `SECURITY_RATCHET.md` (Finding 3) so no one relies
   on forward secrecy that isn't running. (Finding 1 no longer needs an urgent revert —
   compat is out of scope — but either finish wiring v2 or fix the stale
   `protoVerCurrent`/comment contradiction so the file stops lying about its own state.)
3. **Before wiring v2 (Finding 2):** fix 5a (DoS bound), 5b (real skip test), 5c
   (locking), 5d (ratchet-boundary skip), 5f (persist `SessionID`); add tests to
   `internal/session` (5g). Wire the prekey lifecycle + `PrekeyBundlePath` route + the
   `ReceiveRatchet`/`SendMessageV2` dispatch, and reconcile the `SessionManager`
   interface signature mismatch. Treat the eventual `protoVerCurrent` bump as the
   deliberate, fleet-wide coordinated break it needs to be.
4. **Cleanup:** 5e (X3DH prefix), comment sweep.
