# Recovery — what your phrase restores, and what it doesn't

Read this once before you rely on the app for anything you'd hate to lose. It is
short on purpose.

## The one thing to keep safe

Your **recovery phrase** (the list of words shown when you created your account)
is the only thing that can bring your account back. There is no "reset password"
email, no support account, no server that has a copy — by design. Anyone who has
the phrase *is* you; anyone without it, including us, cannot get in. Write it
down and keep it somewhere physical.

## What the phrase brings back — and what it doesn't

Recovering from your phrase on a new device restores your **identity**: your
account number, your address, your keys. It does **not**, on its own, bring back
your **messages, contacts, and groups**.

That is because this is a peer-to-peer app: your conversations live on your own
devices, not on a server we could restore them from. So recovery comes in two
shapes:

- **Phrase + another device you still have signed in** → **full restore.** The
  recovered device links to your existing device and syncs everything back:
  contacts, chats, groups, your profile picture. This is the normal case.
- **Phrase + no surviving device** → **identity back, history gone.** You get
  your account and address back and can start talking again, but past messages,
  your contact list, and your groups are not recoverable. Nobody can recover them
  — that's the flip side of no server holding your data.

## What this means in practice

- If you use more than one device, keep at least one signed in. That is your
  backup.
- If this is your only device, understand that losing it (with no phrase) loses
  everything, and losing it (with the phrase) gets your account back but not your
  history.
- A recovered device comes back as a **secondary** and pulls its data from a
  device you already have. That is deliberate — it avoids two devices fighting
  over your address on the network. Once synced, it behaves like any other device.

## The deliberate trade-off

We could make recovery restore everything by keeping a copy of your data on a
server. We don't, because that copy would be exactly the thing an attacker,
a subpoena, or a breach would go after. The cost of that choice is the paragraph
above: keep your phrase, and keep a second device if your history matters to you.
