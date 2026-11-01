# Fake accounts (Play Store screenshot prep)

15 Big-Lez-character accounts that chat with the main account on the Medium
Phone emulator. All account state lives on the host under `/tmp/molepipe/fake-accounts/`
(one data dir per character, running headless `molepipe-server` + arti sidecar).

## Layout

- `names.txt` — the character names
- `images/` — source photos for avatars + in-chat images
- `start-accounts.sh` — start all (or named) host instances, refresh harness.json
- `stop-accounts.sh` — stop all host instances + arti sidecars
- `/tmp/molepipe/fake-accounts/<Name>/` — data dir (identity.enc, messages.enc, harness.json)
- `/tmp/molepipe/fake-accounts/avatars/` — cropped ≤64KiB avatars + mapping.json
- `/tmp/molepipe/fake-accounts/chat-imgs/` — compressed copies sent in chats
- `/tmp/molepipe/fake-accounts/state.json` — friend/message progress (resume marker)
- `/tmp/molepipe/fake-accounts/run.log` — orchestrator log

## Tooling (in /tmp/molepipe/tooling/)

- `mp.py` — account driver (host instances + the Android main account via CDP)
- `conversations.py` — the dialogue scripts (edit + re-run run.py to change)
- `run.py` — orchestrator: seed → friend-request → conversations (idempotent,
  resumes from state.json). Strictly one message in flight per pair — the
  ratchet session corrupts when two first-handshakes race.
- `cdp.js` — Chrome DevTools Protocol helper for the WebView on the emulator

## Main account

The current account on the Medium_Phone emulator (emulator-5554),
`3nl2hb36vugonuk4mn5peqljiyc54kgx2sglds7dnryisetlhiekh6ad`. Its UI is driven
via WebView DevTools (debug build) — the control token never leaves the device.

## Notes

- Message timestamps are "now" (the API cannot backdate).
- All characters friend-requested the main account; conversations are 6-8
  messages each with subtle Big Lez flavour and 1 photo with a generic reaction.
- Password for every fake account: `Molepipe!Fake2026` (see /tmp/molepipe/tooling/mp.py)
- Recovery phrases are printed by run.py/create and stored in each data dir's
  identity.enc; if you need one, re-create is not possible — back up the data dirs.
