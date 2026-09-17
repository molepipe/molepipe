# Molepipe mailbox server

A small, self-hostable **store-and-forward mailbox** for Molepipe. When one of
your contacts is offline, a message can be dropped here and picked up later —
without ever exposing message content to the person running the box.

It is **optional**. Direct delivery over Tor is always tried first; a mailbox is
only used as a fallback. Most people won't run one; some will — for themselves,
or as a shared box for a household or small group.

## What it is (and isn't)

- **Multi-tenant, zero-knowledge.** One box serves many accounts. Each account's
  mail lives in its own namespace, keyed by its account number (public key).
  There is no registration and no login — tenancy is just "this key checked in."
- **It cannot read your mail.** Blobs are end-to-end encrypted with the
  recipient's key before they ever reach the server. The mailbox stores opaque
  bytes and holds no identity or decryption key of its own. The binary provably
  never links the client's identity/keystore code.
- **What the operator *can* see** (documented honestly): the account numbers of
  who dropped off and who picked up, and connection timing. **Not** message
  content. This is why running *your own* box is the strongest option, and using
  someone else's is a deliberate trust decision — like choosing an email host.

## Lifecycle

1. **Check-in** — your client periodically proves ownership of your account
   (signs a server-issued nonce) to enable your mailbox. A drop-off for an
   account that never checked in is refused, so the box can't become an open
   dead-drop.
2. **Drop-off** — a sender who can't reach you directly POSTs an encrypted
   envelope addressed to your account number.
3. **Pickup** — your client, on coming online, authenticates and downloads
   anything waiting, then decrypts locally.
4. **Delete-on-pickup** — after a successful decrypt your client deletes the
   blob. A `forget-me` request purges all state for an account; anything left
   behind expires on its own via TTL.

## Hosting model

You can run the box either way — the client always connects **through Tor**, so
users never reveal their IP to you regardless:

- **Clearnet (default, easiest):** binds an ordinary `host:port`. Put it behind
  any hosting/TLS you like (a $5 VPS, a domain). No Tor setup required from you.
- **Onion (`MAILBOX_ONION=1`):** the box exposes its *own* Tor onion service, so
  its location is hidden too. Requires an `arti` binary in the container.

## Running

```sh
# From the backend/ module root:
docker build -f cmd/mailbox/Dockerfile -t molepipe/mailbox .

# Clearnet on :8443, data in a named volume:
docker run -d --name mailbox -p 8443:8443 -v mailbox-data:/data molepipe/mailbox
```

Then share the box's address (`host:port` or `.onion`) with the people who will
use it; they paste it into Molepipe as their mailbox.

## Configuration (env vars)

| Variable | Default | Meaning |
|---|---|---|
| `MAILBOX_DATA_DIR` | `/data` | Where blobs and state are stored |
| `MAILBOX_ADDR` | `:8443` | Clearnet bind address |
| `MAILBOX_ONION` | (unset) | Set to any value to run as an onion service |
| `MAILBOX_ARTI` | `arti` | Path to the arti binary (onion mode) |
| `MAILBOX_MAX_MESSAGES` | `500` | Max queued messages per account |
| `MAILBOX_MAX_BYTES` | `20971520` | Max queued bytes per account (20 MiB) |
| `MAILBOX_MAX_MESSAGE_BYTES` | `32768` | Max size of a single blob (32 KiB) |
| `MAILBOX_BLOB_TTL_DAYS` | `14` | Retention for an undelivered blob |
| `MAILBOX_IDLE_TTL_DAYS` | `30` | Retention for a silent (unused) tenancy |
| `MAILBOX_OVERRIDES_FILE` | (unset) | JSON `{account: caps}` per-account overrides |

Caps are **defaults you set**; you can grant individual tenants more headroom via
`MAILBOX_OVERRIDES_FILE` without raising the limit for everyone. Example:

```json
{
  "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid": {
    "MaxMessages": 5000,
    "MaxBytes": 209715200
  }
}
```

### Allowing images (offline photo delivery)

By default the per-blob cap (`MAILBOX_MAX_MESSAGE_BYTES`, 32 KiB) is sized for
text, so **images are not accepted** — a photo sent to an offline contact just
waits until they are back online. That default is deliberate: it stops anyone
filling a box with multi-MB images.

If you run a box for yourself (or people you trust) and want offline **photos**
to arrive, raise the per-blob cap to fit a sealed image. Molepipe images are
capped at 3 MiB before encryption; a sealed image envelope is ~5.5 MiB, so:

```sh
MAILBOX_MAX_MESSAGE_BYTES=6291456   # 6 MiB — enough for one image envelope
MAILBOX_MAX_BYTES=104857600         # raise the per-account total to match (100 MiB)
```

Senders detect this automatically: an image is dropped at a box only if that box
accepts its size, so nothing changes for boxes left at the default.

**Security note — this widens the DoS surface.** A drop-off body must be read in
full before its signature can be checked, so a larger per-blob cap means larger
unauthenticated reads. The server bounds this itself (read/write timeouts and a
concurrent-request ceiling), but a box exposed to real load — especially an
image-enabled one — should also sit behind a reverse proxy with connection and
rate limits. Raise the cap only as far as the images you actually want require;
per-account overrides (above) let you grant image headroom to specific tenants
without opening every box.
