# Molepipe UI/UX Audit — Screenshot Walkthrough

Captured 2026-10-17 on Android 16 emulator (1080×2400), debug build of `org.molepipe.molepipe` (`app-debug.apk`). Full journey: fresh install → account creation → friend request → two-way messaging → lock/security states. Recipient peer: "My phone" (real device SM-S948B). **Also a full landscape (horizontal) pass** — see `landscape/` section below.

## Onboarding

| File | State |
|---|---|
| `01-welcome.png` | Welcome screen — Create / Recover / Link choices |
| `02-recover-form.png` | "I already have a recovery phrase" form (mnemonic + new password) |
| `03-link-device-form.png` | "Link to another device" form (pairing code + phrase + password) |
| `04-privacy-step.png` | Privacy explainer (step 1 of numbered wizard) |
| `05-password-step-empty.png` | Password creation step, empty |
| `05b-password-filled-valid.png` | Password + confirm filled, requirements met, button enabled |
| `06-password-validation-error.png` | Weak password ("weak") — requirements list shows unmet items (red) |
| `06b-password-mismatch-error.png` | Password mismatch — inline error "Passwords do not match."; **create button stays disabled until valid** |
| `07-profile-step-empty.png` | Profile step (display name + avatar), empty |
| `07b-profile-name-filled.png` | Display name "UI Audit Bot" entered |
| `08-recovery-phrase.png` | 24-word recovery phrase grid |
| `08b-phrase-copy-toast.png` | After tapping Copy (toast feedback) |
| `09-confirm-phrase-modal.png` | "Did you save your phrase?" confirmation modal (blocks continue) |
| `09-contacts-explainer.png` | Contacts explainer ("How people reach you") |
| `10-contacts-explainer.png` | Contacts explainer (duplicate frame from adjacent capture) |
| `11-security-explainer.png` | Security explainer (PIN/duress pitch) |
| `12-notify-explainer.png` | Notifications explainer |
| `13-pin-step-empty.png` | PIN setup step, empty (optional) |
| `13b-pin-filled.png` | New PIN + confirm filled (6-digit) |
| `13c-pin-enable-error.png` | **BUG:** "Could not turn on PIN unlock." — wizard PIN step calls `POST /api/security` which requires a session token; no session exists mid-onboarding. PIN cannot be set from the wizard. |
| `14-done-step.png` | "You're all set" done step + donation pitch |

## First run / system

| File | State |
|---|---|
| `48-android-notification-permission-dialog.png` | Android 13+ system dialog: "Allow Molepipe to send you notifications?" (ALLOW / DON'T ALLOW) |
| `49-after-permission-grant.png` | Immediately after ALLOW |
| `15-unlocked-chats-empty.png` | First unlock — Chats tab empty state ("Add someone", "Scan QR", "Create group", "Paste account") |

## You tab (settings)

| File | State |
|---|---|
| `16-you-tab-top.png` | You tab first paint |
| `16-you-profile.png` | You › Profile (avatar, display name, account card, Tor status, one-time code switch) |
| `17-you-preferences.png` | You › Preferences |
| `18-you-devices.png` | You › Devices (pairing / multi-device) |
| `19-you-security.png` | You › Security (PIN, recovery phrase, duress, wipe policy, log out, remove account) |
| `20-account-qr-fullscreen.png` | Fullscreen account QR + mp1 invite code, "Tap anywhere to close" |
| `21-new-code-refresh.png` | After "New code" refresh — invite token rotated |
| `22-pin-setup-dialog-filled.png` | PIN setup dialog from You › Security (password + new PIN + confirm) — **this path works** |
| `23-pin-enabled.png` | PIN state: "On — this device unlocks with your PIN, or your password" |
| `24-tor-pill-connecting.png` | Tor status pill mid-bootstrap: "Send / Receive" split state ("You can send now. Your address is still publishing…") |

## Add friend + friend request

| File | State |
|---|---|
| `25-add-screen.png` | Add screen (person mode), empty friend-code field |
| `26-friend-code-pasted-preview.png` | mp1 code pasted — live preview shows initials + truncated account |
| `27-lookup-loading.png` | "Looking up…" in-progress state (Tor dial, ~80s cold) |
| `28-lookup-result-card.png` | Lookup result: "My phone · 4otogyw4…snknid" + Send friend request |
| `29-request-sent.png` | After send (Add screen context) |
| `29-chats-request-sent-waiting.png` | Chats list: "Request sent · waiting for them to accept" + Cancel |
| `30-after-accept-chats.png` | After peer accepted — contact "My phone" appears |

## Messaging

| File | State |
|---|---|
| `31-chat-empty-state.png` | Opened chat, no messages: "Say hello — you both need to be online." |
| `32-compose-text-typed.png` | Message typed in composer |
| `33-message-sent.png` | Just sent — "Sending…" status |
| `34-message-delivered.png` | Delivered (outgoing bubble, timestamp) |
| `34-chat-both-directions.png` | Both directions: my message + peer reply "Yo" |
| `35-second-message.png` | Second outgoing message, "Sending…" |
| `36-chat-with-history.png` | Full conversation (2 out, 1 in) |
| `37-compose-focus-keyboard.png` | Composer focused (keyboard state) |
| `38-message-context-menu.png` | Long-press message menu + reaction bar (👍 ❤️ 😂 😮 😢 😡 +) — Reply / Copy text / Forward / Select / Delete for me / Delete for everyone |
| `46-final-chat-state.png` | Chat after full session |
| `51-chat-history-after-relog.png` | History restored after lock/unlock cycle |

## Image attach + viewer / zoom

| File | State |
|---|---|
| `52-image-sent-or-error.png` | First attach attempt via CDP file path — "Couldn't read that image." (WebView cannot read `/sdcard/...` paths set through DevTools) |
| `53-image-in-chat.png` | Outgoing image bubble (canvas-generated PNG injected via DataTransfer), "Sending…" |
| `54-image-delivered.png` | (same frame while still sending) |
| `54b-image-not-delivered.png` | **BUG:** "Not delivered — couldn't send · tap to retry" — image send failed while text messages to the same peer succeed and Tor pill is Online. Reproduced with 96KB and 2.6KB PNGs. |
| `55-image-viewer-open.png` | Tap on (failed) outgoing image opens fullscreen viewer — even for undelivered images |
| `56-image-viewer-zoomed-double-tap.png` | Double-tap zoom → `scale(2.5)` centered on tap point |
| `57-image-viewer-pinch-zoom.png` | Two-finger pinch → `scale(2.875)` |
| `58-image-viewer-zoomed-panned.png` | Single-finger pan while zoomed (translate applied, scale held) |
| `59-incoming-image-viewer.png` | Viewer on peer's incoming photo (fit, scale 1) |
| `60-incoming-image-zoomed.png` | Incoming photo double-tap zoomed |
| `61-image-viewer-actions-bar.png` | Viewer action bar: Download / Share / Forward + close ✕ |
| `62-image-retry-result.png` | Tap-to-retry on failed image — still "Not delivered" |
| `63-small-image-send.png` | Second (2.6KB) image send attempt, "Sending…" |
| `64-small-image-result.png` | Second attempt also fails — "Not delivered — couldn't send · tap to retry" |

## Requests tab / group mode

| File | State |
|---|---|
| `39-requests-tab-empty.png` | Requests tab empty: "No requests" + Add someone / Share my code |
| `47-add-group-mode.png` | Add screen, "New group" mode (group name + Create group) |

## Lock / security states

| File | State |
|---|---|
| `40-lock-screen-pin-pad.png` | Lock screen, scrambled numeric PIN keypad (Android) |
| `41-wrong-pin-error.png` | Wrong PIN: "Incorrect PIN. 7 attempts left before PIN unlock is removed." — keypad re-scrambles |
| `42-forgot-pin-password-form.png` | "Forgot PIN? Use password" → password unlock form |
| `43-forgot-password-modal.png` | "Forgot your password?" destructive modal — Cancel / Remove account from this device (**cancelled, not confirmed**) |
| `44-unlocked-again.png` | Successfully unlocked again via correct PIN |
| `45-remove-account-modal.png` | You › Security › Remove account modal — "Erase this account from this device?…" (**cancelled, not confirmed**) |
| `50-final-unlocked-with-contact.png` | Unlocked state with contact list after session restart |

## Notes for auditors

1. **Wizard PIN bug (`13c`)** — Onboarding's PIN step is non-functional; `POST /api/security` is session-gated and no session exists until unlock. Users must set PIN later via You › Security (`22`–`23`). Error copy is also vague ("Could not turn on PIN unlock.") with no cause.
2. **Create button gating** — The Create account button remains disabled until password rules pass and both fields match; the mismatch error only appears if submit is forced (`06b`). Live UX: button-disabled may be clearer than the late inline error.
3. **Lookup latency** — Cold Tor lookup of a peer onion took ~80s with only "Looking up…" and a disabled button; no progress indicator or cancel. Tor pill stayed in "publishing" the whole time.
4. **Scrambled PIN pad** — Digits shuffle on each failed attempt (`40`→`41`); attempt countdown is shown in the error string. Good for shoulder-surfing defense; countdown-in-error may be missed.
5. **Destructive confirmations** — Both "Forgot password?" and "Remove account" use clear consequence copy + Cancel; neither was confirmed during this audit.
6. **Notification permission** — System dialog fires on first service start (`48`); web Notification API is not used on Android (native shell notifications instead). You › Preferences shows notifications as "Managed in Android settings".
7. **Friend request lifecycle** — Sent state (`29-chats-…`) is explicit with Cancel; accepted contact lands in Chats with "No messages yet" empty chat state (`30`→`31`).
8. **Context menu** — Long-press reveals reply/react/menu; menu covers forward and both delete scopes (`38`).
9. **Image send flaky, not portrait-specific (`54b`, `62`, `64` vs `portrait-retest/`)** — First portrait pass: outgoing photos failed with "Not delivered — couldn't send · tap to retry" (96KB and 2.6KB) while text delivered. Landscape pass and a later portrait retest (`ui-audit/portrait-retest/`) both delivered 95KB and 5KB images with no changes. Treat as intermittent `/api/messages/image` delivery failure, not an orientation bug. Repro: chat open + Tor Online, canvas-generated PNG via DataTransfer on `#image-input`.
10. **Viewer opens on failed images (`55`)** — Tapping an undelivered image still opens the full viewer with Download/Share/Forward actions; may confuse users into thinking it sent.
11. **Zoom UX (`56`–`60`, `portrait-retest/04–06`, `landscape/L37–L40`)** — Double-tap toggles 1× ↔ 2.5×; pinch clamps to 5×; pan only when scale > 1; backdrop tap at fit closes. No visible zoom level indicator or double-tap hint. Landscape short stage hits the 5× cap faster.

## Landscape (horizontal) pass — `landscape/`

Second full pass with the emulator rotated to landscape (2400×1080 → **915×412 CSS px**, `devicePixelRatio` 2.625). This crosses the app's **900px wide-layout breakpoint**: bottom nav stays, but the detail pane sits beside the list (two-pane) instead of covering it. Fresh account (prior `identity.enc` was lost mid-session — see method note). Same password/PIN/name as portrait run.

| File | State |
|---|---|
| `L01-welcome.png` | Welcome — wide/two-pane empty shell |
| `L02-recover-form.png` | Recover form in landscape |
| `L03-link-device-form.png` | Link-device form in landscape |
| `L04-privacy-step.png` | Privacy explainer |
| `L05-password-step-empty.png` | Password step empty |
| `L05b-password-filled-valid.png` | Valid password, button enabled |
| `L06-password-validation-error.png` | Weak password requirements |
| `L06b-password-mismatch-error.png` | Password mismatch error |
| `L07-profile-step-empty.png` | Profile step empty |
| `L07b-profile-name-filled.png` | Display name filled |
| `L08-recovery-phrase.png` | 24-word phrase (landscape grid) |
| `L08b-phrase-copy-toast.png` | Copy feedback |
| `L09-confirm-phrase-modal.png` | "Did you save your phrase?" modal |
| `L10-contacts-explainer.png` | Contacts explainer |
| `L11-security-explainer.png` | Security explainer |
| `L12-notify-explainer.png` | Notify explainer |
| `L13-pin-step-empty.png` | Wizard PIN step empty |
| `L13b-pin-filled.png` | Wizard PIN filled |
| `L13c-pin-enable-error.png` | Wizard PIN still fails (same session bug) |
| `L14-done-step.png` | Done step |
| `L15-unlocked-chats-empty.png` | First unlock — **two-pane wide layout** (list + placeholder detail) |
| `L16-you-profile.png` | You › Profile, wide |
| `L17-you-preferences.png` | You › Preferences, wide |
| `L18-you-devices.png` | You › Devices, wide |
| `L19-you-security.png` | You › Security, wide |
| `L20-account-qr-fullscreen.png` | Fullscreen QR in landscape |
| `L21-new-code-refresh.png` | Invite code rotated |
| `L22-pin-setup-dialog-filled.png` | PIN setup dialog (You › Security path) |
| `L23-pin-enabled.png` | PIN On |
| `L24-tor-pill-status.png` | Tor pill (was already Online on this pass) |
| `L25-add-screen.png` | Add screen, person mode, wide |
| `L26-friend-code-pasted-preview.png` | mp1 code + live preview |
| `L27-lookup-loading.png` | Lookup loading (fast this time — peer cache/warm) |
| `L28-lookup-result-card.png` | Lookup result "My phone" |
| `L29-chats-request-sent-waiting.png` | Request sent · waiting |
| `L30-after-accept-chats.png` | After accept |
| `L31-chat-empty-state.png` | Empty chat, wide (chat in detail pane) |
| `L32-compose-text-typed.png` | Composer with text |
| `L33-message-sent.png` | Sending… |
| `L34-message-delivered.png` | Delivered + peer "Yo" + peer image arrived |
| `L35-image-sent.png` | Outgoing image sending |
| `L36-image-result.png` | **Both images delivered** (out + in) |
| `L37-image-viewer-open.png` | Viewer on sent image, landscape fit |
| `L38-image-viewer-double-tap-zoom.png` | Double-tap → scale(2.5) |
| `L39-image-viewer-pinch-zoom.png` | Pinch → scale(5) (max clamp; landscape stage is short so pinch hits cap fast) |
| `L40-image-viewer-zoomed-panned.png` | Pan while zoomed |
| `L41-image-viewer-actions-bar.png` | Download / Share / Forward bar |
| `L42-incoming-image-viewer.png` | Viewer on peer image |
| `L43-incoming-image-zoomed.png` | Peer image zoomed |
| `L44-lock-screen-pin-pad.png` | Lock screen, scrambled PIN pad, landscape |
| `L45-wrong-pin-error.png` | Incorrect PIN + attempts left |
| `L46-forgot-pin-password-form.png` | Use password form |
| `L47-add-group-mode.png` | Add screen, New group mode, wide |
| `L48-forgot-password-modal.png` | Forgot-password destructive modal (**cancelled**) |
| `L49-unlocked-again.png` | Unlocked again via correct PIN |

### Landscape-specific observations

- **Wide layout at ~915px CSS** — `min-width: 900px` two-pane kicks in; bottom nav remains. Detail placeholder sits next to the list on empty chats (`L15`). Worth auditing empty-detail affordance.
- **Image send worked in landscape** (`L35`–`L36`) — opposite of the first portrait failures. A later portrait retest also worked (see below); failures look intermittent, not orientation-related.
- **Pinch hits 5× cap quickly** (`L39`) — short landscape stage + wide starting scale makes max-zoom easy; pan range feels constrained by height.
- **Wizard PIN bug unchanged** (`L13c`) — still session-gated.
- **Lookup much faster** on second pass (`L27`–`L28`) — warm peer/guard vs first cold dial.

## Portrait retest (image send) — `portrait-retest/`

After the landscape pass, emulator rotated back to portrait (412×915, narrow layout) on the same landscape-pass account/session. Purpose: retest the flaky image-send finding.

| File | State |
|---|---|
| `00-chat-before-image.png` | Chat open in portrait, history intact, Tor Online |
| `01-image-sending.png` | 95KB canvas PNG dispatched, "Sending…" |
| `02-image-result.png` | **Delivered** — outgoing bubble, no "Not delivered" |
| `03-second-image-result.png` | Second 5KB image also **delivered** |
| `04-image-viewer-open.png` | Viewer on successful sent image, portrait fit |
| `05-image-viewer-double-tap-zoom.png` | Double-tap → scale(2.5) |
| `06-image-viewer-pinch-zoom.png` | Pinch → scale(5) |

**Conclusion:** image send succeeded 2/2 in this retest (and 1/1 in landscape), vs 0/2 in the first portrait pass. Finding #9 updated to "flaky / intermittent" rather than broken.

### Method (landscape pass)

- Rotation: `adb shell settings put system user_rotation 1` (ROTATION_90), accelerometer rotation off.
- Prior portrait session's `identity.enc` disappeared from app storage between passes (backend still reported `has_identity: false`); landscape pass started from a clean create. Not fully diagnosed — flag if reproducible.
- Screenshots under `ui-audit/landscape/`; portrait set unchanged in `ui-audit/` root.

## Method

- Driven via Chrome DevTools Protocol (`WebView.setWebContentsDebuggingEnabled` in debug builds) + `adb exec-out screencap` for full-frame captures (includes system status/nav bars).
- Account: password `Audit2026!pass`, PIN `135790`, display name "UI Audit Bot". Peer code: `mp1:4otogyw4luposazk4es4nagkuf5ccldh5iukgn5ixbmzxtsixcsnknid:…` (token redacted here; was live during capture).
- No destructive actions confirmed; no production data touched; emulator app data is throwaway.
