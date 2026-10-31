# Changelog

All notable changes to Molepipe are documented here.

## [Unreleased]

### UI/UX Polish
- Connection pill tells the two directions apart. For the whole time your address is publishing you can already send messages, but nobody can reach you yet — and the pill said only "Publishing…", which hides that sending works, while "Online" would claim a reachability you don't have. It now splits into two legs, Send ✓ and Receive with a spinner, for exactly that window, then collapses back to a single "Online" once both agree. The You tab spells out the same thing in full with elapsed minutes, so a slow publish reads as slow rather than broken, and diagnostics now carry Tor's own word for what the service is doing — a first publish still in flight and one retrying after failed uploads are no longer reported identically
- Status pill anchored to far right of header — aligns with search icon on Chats tab, stands alone at 16dp margin on You/Requests tabs; no pill shown inside chat threads (green dot next to contact name is the indicator)
- PIN keypad standardisation — new "Shuffle PIN keypad" toggle in Security settings (default ON); when OFF, uses standard 1–9 layout (1,2,3 / 4,5,6 / 7,8,9) to restore muscle memory; when ON, randomises positions to prevent shoulder-surfing
- Remove Account relocated to a distinct "Danger Zone" card at the very bottom of the Security tab — grey-toned card with red header label, sits below Log out to prevent accidental taps; button style changed to smaller outlined variant
- QR code redesigned — removed giant inline QR and "Show large" text link; replaced with two side-by-side buttons under the onion address: Copy (Filled) and QR Code (Tonal); tapping QR Code opens the fullscreen black viewer directly
- Reaction chips enlarged — 32dp height, 16dp horizontal padding, M3 Assist Chip style with white background and subtle shadow for better visibility and touch targets
- Image skeleton loaders — animated shimmer placeholder shown while images load, preventing layout shift
- Mailbox setup button — pencil icon replaced with prominent Filled Button labelled "Set up mailbox" with mailbox icon
- Share my code button — changed from easy-to-miss text link to Outlined Button with share icon on Requests empty state
- Diagnostics sheet — body text changed from monospace to standard sans-serif font; Copy All button changed to full-width Filled Button at bottom of sheet
- Password input fields — height increased to 56dp for better touch targets
- Send button disabled state — visually fades out when message box is empty, preventing empty sends
- Live profile preview in New Chat — shows account preview card (avatar + truncated address) when typing a valid .onion address; subtle help text shown when field is empty
- Keyboard no longer hides the latest messages — opening the soft keyboard in a chat re-pins the list to the newest message if you were already at the bottom

### Added
- Nicknames for contacts — give someone your own name for them from their profile pane (the pencil beside their name), and that is what you see everywhere: the chat list, the chat header, search, the group member list, the share and forward pickers, and the system notification that wakes your phone. It is private to you and your own linked devices, never sent to the person you named, and it survives them renaming themselves — their published name still owns their profile, the nickname just shadows it, and the pane keeps showing their real name underneath so you can always tell who you renamed. Clear the field to remove it
- Native Tor diagnostics are mirrored into the run log — the onion-service status transitions, descriptor-upload failures and start errors previously lived only in a 400-line in-memory ring, readable solely through the app's own diagnostics sheet, so a log pulled off a device showed none of them. They now land in the same file as the backend's own lines, in order, with a repeated message re-reported as its count doubles rather than once per retry. The file is inside the app's data directory, so an account removal and a duress wipe still erase it
- The Tor log now says what the onion service itself is doing. Arti reports its state through `tracing`, which the Android shim never subscribed to, so the app could only see one bit — "reachable" or not — and a phone that had three live introduction points but could not upload its descriptor looked identical to one still starting up. Every status transition is now logged with the error behind it, including the HSDir upload failure chain, and repeated lines are collapsed with a count so a retry flood can no longer push the useful history out of the ring
- Friend code replaces the account number on the Profile tab — a shareable code (still copyable, still a QR) that carries a single-use invitation token, with a "New code" button to mint a fresh one and an "Auto-refresh after use" toggle: on, each code works once and a new one appears automatically; off, the code stays shareable and reusable until you refresh it
- Pull down on the chats or requests list to refresh, and a refresh button in the header on desktop — forces an immediate full reload (and a mailbox fetch) instead of waiting for the next poll, for when something looks stuck
- Duress code wizard — three-step modal (explain → password → set code) with red accent, replacing the inline form
- Erase-threshold segmented buttons (5 / 10 / 15 / 20) replace the freeform number input
- Empty-state CTAs on the Chats tab: "Add someone", "Scan QR", and "Paste account" buttons when there are no conversations
- Security hub header with shield icon; "Remove account" moved into the Security pane
- Battery-exemption explanatory dialog — shows a plain-language "Keep connections alive?" prompt before firing the system Doze intent
- Arti-client dormant-mode toggle — when the app backgrounds, proactive Tor tasks are suspended to conserve CPU and battery
- Network binding on the foreground service — prevents Doze from silently revoking network access on OEM-tweaked builds
- Faster Tor startup — Tor client is pre-warmed during password entry so the first unlock is near-instant
- Notify-only update check over Tor — fetches a signed release manifest from a self-hosted .onion, verifies it against a pinned key, and reports whether a newer build exists
- Onboarding recovery-phrase verification — after saving the 24-word phrase, a checkpoint asks for a few words at random positions before continuing
- Password-strength hint on the create-account screen (advisory only; never blocks creation)
- Extended "New chat" floating action button (was an unlabelled icon)
- Recovery phrase now shown as a numbered two-column grid for easier transcription
- Requests tab empty state now offers "Add someone" and "Share my code" actions
- Optional PIN step right after an account is first created or recovered
- "Password vs PIN" helper on the create screen and a "What is a mailbox?" explainer on the You tab
- "Show large" — a fullscreen view of your own account number with its QR, on the You tab
- New Chat screen now leads with prominent Scan QR / Paste buttons above the account-number field

### Fixed
- Choosing a PIN during setup now actually turns it on. The setup wizard asks for a PIN near the end, and that step could never succeed: enabling PIN unlock is one of the operations that needs an unlocked session, and the wizard holds no session until its final "Start messaging" button performs the first unlock — two steps later. So everyone who set a PIN during onboarding was told "Could not turn on PIN unlock." and then arrived in the app with PIN unlock off. There was not even a real reason to show them: a request with no session is refused in plain text rather than as a message a screen can display, so the wizard fell back to its own generic wording, which is why the failure looked like a server problem rather than a step in the wrong order. The step now validates the PIN where it is typed — its length and the confirm match, which is everything that can honestly be checked at that point — and the PIN is applied immediately after the unlock that ends setup, the first moment it can be. Choosing "Not now" still leaves PIN unlock off, and if applying it ever fails for a genuine reason the app now says so and names where to set it, instead of leaving a PIN you asked for quietly turned off
- Unlocking no longer throws away an address that is already published. Every unlock tore the onion service down and re-published it, even when the service running at that moment was already the right one for the account being unlocked — which discards the introduction points it had established and both sets of directory uploads, to arrive back at exactly the same .onion. A device log caught the full cost: a service that had been published and serving for 41 hours was shut down 3 seconds after a PIN unlock and took 25 seconds to rebuild the identical descriptor, and on a phone-grade connection the same rebuild runs 90 seconds or more. This matters far more often than a reboot does, because the app's own lock screen reappears whenever the window is recreated — swipe the app away and reopen it and you are asked for your PIN again even though nothing was ever torn down. An unlock that finds the account's service already published now simply keeps it, and is reachable immediately instead of after a republish. It is keyed on which service is published, not merely on whether one is: a duress code, a restore and a device pairing each open a different identity in the same session, and those must still replace what is published rather than inherit it
- A session that times out now ends the way using Log out ends it. Reaching the idle or absolute session limit only discarded the in-memory keys: the onion service stayed published, the background loops and the publish watchdog went on running against an empty session, and no teardown was scheduled. Two consequences, both visible in a device log. The onion key is supposed to be wiped when a session ends — that is what the wipe on teardown is for — and because no teardown ever ran, one device was still publishing its address 41 hours after its session had ended. And since a timeout scheduled nothing, the next unlock could not take the quick path that reuses a still-published service and paid a full re-publish instead. A timeout now runs the same teardown an explicit Log out does, which both bounds how long the key outlives the session and leaves the next unlock on the fast path
- Status goes green when peers can actually reach you, not minutes later. Arti says nothing about a descriptor publish until its whole batch of directory uploads resolves, and a single directory that never answers holds that up for its full five-minute timeout even when the other uploads landed in seconds. Measured on hardware: a contact was fetching our profile over the onion 43 seconds after the publish began, and every ~40 seconds after that, while the app went on reporting "nobody can reach you" for 5m20s — 4m37s of the wait was the status lagging, not the service. A request arriving on the onion-facing listener is now taken as what it is (a peer found our descriptor and completed a rendezvous) and reports us reachable straight away, OR'd with Arti's own signal so it can only ever be early, never wrong. Tor's own state is still reported verbatim alongside it, so the lag stays visible in diagnostics. Once a peer has reached you the status holds, rather than expiring on a timer: your address does not stop being published because the contact who dialled you closed their app, and letting it lapse would drop the status back to "publishing" a minute later with nothing having changed. The same holds once Tor itself reports success: an intro point failing mid-session, which happens routinely, sets Tor re-establishing one and used to turn the status red on a service that was still published and still reachable. The status is dropped only where it genuinely stops being true — whenever the service is torn down or re-published, and when Tor reports the service has shut down or given up. A first-ever publish, where nobody knows your address yet, still waits for Arti — there is nothing to observe
- Onion address publishes faster on a phone-grade connection. Tor fits a curve to its own circuit build times and abandons any build slower than the 80th percentile of that fit — a sensible default on a home link, where the 80th percentile is comfortably above typical. On a measured phone it was not: over a thousand samples the fitted deadline came out at 2.86 seconds, which only 70.8% of builds beat, so roughly three in ten circuits that would have worked were thrown away. Publishing the address needs several uploads to directories, each over its own circuit, so those losses compounded into an eight-minute wait — one run reported fourteen consecutive upload attempts all failing with "circuit took too long to build". The estimator also censors its own measurements, since a build that is abandoned is never recorded, which keeps a deadline that is already too short from ever growing. Molepipe now asks for the 95th percentile instead: a 3.49-second deadline that 94.2% of the same builds beat, with the adaptive fit still doing the measuring
- The connection watchdog no longer restarts an onion service that is in the middle of publishing. It used to decide from a stopwatch plus one piece of evidence — whether a peer had recently reached us — which on a first connection cannot exist yet, so a publish that was merely slow was indistinguishable from a failed one. On a phone whose network made roughly a third of Tor circuit builds time out, a restart discarded fourteen in-flight uploads and four minutes of work, and the connection then took another six and a half minutes to come up. It now asks Tor directly whether the publisher is still working and only restarts where restarting is the remedy — the service having actually given up — with a thirty-minute ceiling so one that never finishes is still recovered
- Onion service no longer torn down while it is working — the publish watchdog treated Arti's "not fully reachable" status as proof that descriptor publication had stuck and restarted the service, which drops the intro points and descriptor-signing keys and forces a cold re-publish. Inbound peer traffic now vetoes the restart: a request arriving over Tor means a peer found our descriptor, so the service is left alone. On an affected device this showed up as repeated "stuck, restart attempt" cycles and friend requests, accepts and messages failing to reach anyone
- A slow onion start is no longer mistaken for a stuck one — the watchdog gave the first descriptor publication 90 seconds and then restarted the service, twice, before abandoning it. Nothing has ever reached the app at that point, so the inbound-traffic veto cannot help, and each restart drops the intro points and signing keys and makes the next publish colder still. The first attempt now gets four minutes and each restart doubles that, so a merely slow cold start is given the room to finish; a genuinely stuck one is still restarted. On an affected phone this was the difference between coming online and sitting unreachable until the app was relaunched
- Accepting a friend request now tells the requester — the requester's status flipped from "Requested" silently, so nothing announced that the other side had approved it. The device that sent the request now raises a system notification (Android and iOS) and an in-app message when the accept lands, and tapping it opens the new conversation
- Android run log carries timestamps again, in the device's own zone — gomobile zeroes the log flags (logcat stamps its own), which left the in-app log file with no times at all and made event order unrecoverable when diagnosing a delivery problem. The shell now also hands the backend its time zone, because Go's runtime reports UTC on mobile whatever the device is set to; lines carry the UTC offset so a log read on another machine is still unambiguous

### Security
- Friend requests now require a current friend code — a bare account number on its own can no longer add you, and refreshing your code immediately revokes the previous one, so a leaked or over-shared code can be cut off with a single tap
- Panic recovery middleware on both HTTP listeners — prevents a single handler panic from crashing the server
- Update check is fail-closed by construction: a missing/forged/wrong-channel manifest is treated as "no update"

### Changed
- Run log no longer buried under the app's own polling — the web UI refreshes eight endpoints every 2.5s, which was three quarters of every line in the log and swamped the peer traffic the log is read for. Routine loopback GETs that returned promptly are now rolled up into one periodic count; anything that failed, mutated state or dragged past 250ms is still logged in full, and the onion-facing listener logs every peer request as before
- Adding someone now goes through their friend code end to end — the New Chat field, paste, and QR scan all accept a friend code, and the typing preview recognises one; adding a group co-member by their bare account number is no longer offered (share a friend code instead)
- Accessibility: icon buttons and the reaction picker now meet the 48dp minimum touch target
- Body font bumped to 0.95rem; nav items enforce 48dp minimum height; segmented buttons enforce 40dp minimum height
- Settings (You tab) reorganised into Profile / Preferences / Devices / Security sub-tabs
- Per-message actions (Reply / React / Copy / Forward / Delete) are now an M3 modal bottom sheet
- "Copy" on the account card is now a primary (filled) button; body line-height raised to 1.5
- Subtle haptic tick when sending a message and when locking (no-op where the platform has no vibrator)
- Colour palette regenerated with deeper indigo seeds
- Improved foreground service reliability for Tor onion service persistence
- Accessible copy rewrites: "permanently destroy" → "wipe this device" (restorable); "no other copy" → reassuring recovery phrase copy
- Faster Tor connection and contact presence detection

## [0.1.0]

### Phase 1 — Identity & Crypto Core
- BIP39 recovery phrase generation (24 words)
- Ed25519 + X25519 key derivation via SLIP-0010
- AES-256-GCM encrypted identity storage (Argon2id KDF)
- Account number (v3 onion address format)

### Phase 2 — Localhost HTTP Server
- Local HTTP server with embedded Material 3 UI
- Password unlock with session management
- Host allowlist and origin guard (anti-DNS-rebinding, anti-CSRF)
- Content Security Policy enforcing no external calls

### Phase 3 — Tor Onion Service
- Arti Tor sidecar for onion-service hosting
- Onion key derivation (matches desktop keypair)
- Peer-facing listener on separate port (onion traffic isolation)
- Startup key sweep (crash-safe key cleanup)

### Phase 4 — Peer Messaging
- End-to-end encrypted messaging over Tor (v1 protocol)
- Encrypted contact and message persistence
- Contact list with online/offline status
- Chat UI with Material 3 design

### Phase 5 — Profile & Social
- Profile lookup and friend requests
- QR code and copy for account sharing
- Account creation and recovery from UI
- App shell with bottom navigation

### Phase 5.1 — Multi-Device
- Device pairing and enrollment
- Multi-device sync (contacts, messages, profile)
- Per-device keypair with role management (primary/secondary)
- Relay forwarding for offline peers

### Phase 6 — Group Messaging
- Encrypted group creation and messaging
- Group reactions and reply-with-context
- Group image sharing with content-addressed storage
- Group image backup with per-account byte budget
- Group invite system (tap-to-invite + account-number flow)

### Phase 7 — Desktop Packaging
- Wails v2 native window with system tray
- Self-contained release tarball with Arti binary
- Auto-detect desktop/browser fallback launcher
- XDG autostart integration
- PIN shortcut with brute-force protection
- Duress code (panic-code wipe)
- Erase-after-N failed unlocks
- Delete-for-everyone
- Lock screen with background persistence
