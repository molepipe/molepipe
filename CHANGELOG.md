# Changelog

All notable changes to Molepipe are documented here.

## [Unreleased]

### UI/UX Polish
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

### Security
- Panic recovery middleware on both HTTP listeners — prevents a single handler panic from crashing the server
- Update check is fail-closed by construction: a missing/forged/wrong-channel manifest is treated as "no update"

### Changed
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
