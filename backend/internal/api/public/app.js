"use strict";

// Session token lives in memory only (not localStorage) so it disappears when
// the tab closes. Theme prefs are non-sensitive and do use localStorage.
//
// On the Android shell it is additionally mirrored into the shell's own
// process-scoped holder, because there the tab gets rebuilt for reasons nobody
// thinks of as closing it (any configuration change outside MainActivity's
// configChanges list destroys the Activity and its WebView), and the new page
// would ask for the PIN again while the vault was still unlocked. That holder
// is memory-only too and dies with the process, which is both when the tab is
// really gone and when the vault's keys are zeroed — so this keeps the rule
// above rather than relaxing it. See ShellSession.kt.
let sessionToken = null;

// setSessionToken is the only way the token should be written: it keeps the
// Android holder in step, including on the clearing paths (lock, wipe, 401).
function setSessionToken(tok) {
  sessionToken = tok || null;
  try { window.AndroidShell?.setSessionToken?.(sessionToken || ""); } catch (_) {}
}
let myName = "";
let myMailbox = "";
let myBackupBytes = 0; // group-image backup budget in bytes (0 = off)
// myMediaAutoSave is the GLOBAL default for copying received photos into the
// phone's gallery. A per-contact override (contact.media_auto_save) wins over
// it; see effectiveMediaAutoSave. Mirrors Profile.MediaAutoSave on the backend.
let myMediaAutoSave = false;
let myAvatarHash = ""; // sha256 of my own avatar image (""=none); rendered via /api/avatar
let contacts = [];   // [{account, name, status}]
let requests = [];   // [{account, name}]
let messages = [];   // [{direction, peer, text, at, group_id?, author?, author_name?}]
let groups = [];        // [{id, name, role, can_invite, member_count, unread, policy}]
let groupInvites = [];  // [{group, name, inviter, inviter_name, status}]
let groupMembers = [];  // members of the group whose info pane is open
let groupInfoCtx = {};  // {my_role, i_can_invite, policy, name} for that pane
let currentPeer = null;
let currentGroup = null;  // group id when a group chat is open
let chatKind = null;      // 'contact' | 'group' while detailContent === "chat"
let selfAccount = null;    // our own account number — marks our own reaction chips
let torReady = false;      // our descriptor is published — peers can reach us (inbound)
let torSendable = false;   // outbound circuits are up — we can dial peers to send
let torConnectingSince = 0; // wall-clock ms we entered a not-yet-sendable state; 0 = sendable/disabled
let torBootstrapFrac = 0;  // 0.0–1.0 from the backend
let torHsState = "";       // "bootstrapping"|"publishing"|"running"|"unknown"|""
let torServiceState = "";  // what the onion service itself reports: "bootstrapping"|"degraded-unreachable"|"running"|"recovering"|... ; "" where the backend can't ask
let torPublishSince = 0;   // wall-clock ms we became send-only (sendable, not yet reachable); 0 = not in that window
const TOR_STALLED_MS = 45000; // connecting longer than this => "still connecting, check your network"
let torStallHint = "";     // last Arti log line, fetched on first stall detection
let appVersionInfo = null;  // cached /api/version (build metadata for the diagnostics snapshot)
let deviceRoleText = "";    // "primary"|"secondary" cached from loadDevices, for diagnostics
let lookupResult = null;
let currentTab = "chats";
let detailContent = null; // null | "chat" | "add" | "group-info"
let currentAddMode = "person"; // "person" | "group" — tracks the add-screen toggle
let prevRequestCount = 0;
let prevGroupInviteCount = 0;
let notifSeenAt = 0;      // epoch ms of the newest inbound message we've already surfaced
let notifsOn = false;     // desktop notifications enabled (permission granted + toggled on)
let pinEnabled = false;   // this device has a PIN unlock shortcut set up
let shufflePin = true;    // shuffle PIN keypad digits (default: true for backward compat)

// The desktop shell navigates here with ?shell=desktop. It only changes how the
// frame is drawn: in a browser tab #app is a phone-like card floating on a dim
// backdrop, which inside a native window is a second set of rounded corners
// nested in the window manager's own. Set before first paint, and on <html> so
// CSS alone can act on it.
const shellParam = new URLSearchParams(location.search).get("shell");
if (shellParam) {
  document.documentElement.dataset.shell = shellParam;
}
const isAndroid = document.documentElement.dataset.shell === "android" || /android/i.test(navigator.userAgent);

// Control-listener capability token. The shell/browser boots us at ?ct=<token>;
// on Android 127.0.0.1 is shared with every other app, so this secret — which a
// co-installed app cannot read — is what authorizes our /api calls (the Host and
// Origin headers it also checks are forgeable by a native caller). We read it
// once, cache it in sessionStorage so an in-tab reload keeps working, then scrub
// it from the address bar so it is never shown, bookmarked or copied. It shares
// the session token's lifetime: gone when the tab/WebView closes.
let controlToken = "";

// scrubQueryParam removes one query param from the address bar without a reload,
// so a token in the launch URL is never shown, bookmarked or copied.
function scrubQueryParam(name) {
  try {
    const clean = new URL(location.href);
    clean.searchParams.delete(name);
    history.replaceState(null, "", clean.pathname + clean.search + clean.hash);
  } catch (_) {}
}

try {
  // Cached (survives an in-tab reload), or the direct token an embedded-webview
  // shell (Wails/Android) hands us in the URL. The browser entry point instead
  // uses a single-use ?x= exchange token, traded for the real one at boot
  // (exchangeControlToken) so the durable secret never enters browser history.
  const fromUrl = new URLSearchParams(location.search).get("ct");
  if (fromUrl) {
    controlToken = fromUrl;
    try { sessionStorage.setItem("ct", fromUrl); } catch (_) {}
    scrubQueryParam("ct");
  } else {
    try { controlToken = sessionStorage.getItem("ct") || ""; } catch (_) {}
  }
} catch (_) {}

// exchangeControlToken trades a one-time ?x= bootstrap token for the durable
// control token (the cmd/server browser entry point). A no-op when we already
// have a token (cache or ?ct=) or there is no ?x=. The token is spent server-side
// on first use, so the copy left in history / autocomplete cannot be replayed.
async function exchangeControlToken() {
  if (controlToken) return;
  let x = "";
  try { x = new URLSearchParams(location.search).get("x") || ""; } catch (_) { return; }
  if (!x) return;
  try {
    const res = await fetch("/control-token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ x }),
    });
    if (res.ok) {
      const b = await res.json();
      if (b && b.token) {
        controlToken = b.token;
        try { sessionStorage.setItem("ct", controlToken); } catch (_) {}
      }
    }
  } catch (_) {}
  scrubQueryParam("x");
}

const $ = (id) => document.getElementById(id);
const TABS = { chats: "Chats", requests: "Requests", you: "You" };
const ACCENTS = [
  ["violet", "#6C4AB6"], ["indigo", "#3F51B5"], ["teal", "#008C8C"],
  ["green", "#2E7D32"], ["rose", "#C2185B"], ["amber", "#B4690E"],
];

// ---------- theme ----------
function applyAccent(name) {
  document.documentElement.setAttribute("data-accent", name);
  try { localStorage.setItem("accent", name); } catch (_) {}
  document.querySelectorAll(".swatch").forEach((s) => s.classList.toggle("active", s.dataset.accent === name));
}
// The effective light/dark of the UI right now: an explicit data-theme wins,
// otherwise we follow the OS preference (the "system" mode).
function effectiveDark() {
  const t = document.documentElement.getAttribute("data-theme");
  if (t === "dark") return true;
  if (t === "light") return false;
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}
// On the Android shell, hand the effective theme to the native side so it can
// flip the status-bar / navigation-bar icon contrast to stay legible. No-op in
// the browser/desktop builds, where window.AndroidShell is undefined.
function syncSystemBars() {
  try { window.AndroidShell?.setBarAppearance(!effectiveDark()); } catch (_) {}
}
function applyMode(mode) {
  if (mode === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", mode);
  try { localStorage.setItem("mode", mode); } catch (_) {}
  document.querySelectorAll(".mode-btn").forEach((b) => b.classList.toggle("active", b.dataset.mode === mode));
  syncSystemBars();
}
// ---- Dynamic Color (Material You), Android 12+ only ----
// The native shell exposes the device's wallpaper-derived tonal palettes; we map
// those five ramps onto the full M3 role set for a "dynamic" accent. The
// role->[palette, lightTone, darkTone] table below was DERIVED from the
// generator's own output (tools/gen-theme.mjs), not guessed — so a dynamic
// palette lands on exactly the tones the baked accents use. Android exposes 13
// discrete tones, so a couple of adjacent surface levels coincide; that's the
// honest limit of consuming ready ramps rather than re-running the algorithm.
let DYN_RAMPS = null; // { a1:{tone:hex}, a2, a3, n1, n2 } or null when unsupported
const DYN_ROLES = {
  "primary": ["a1", 40, 80], "on-primary": ["a1", 100, 20],
  "primary-container": ["a1", 90, 30], "on-primary-container": ["a1", 30, 90],
  "inverse-primary": ["a1", 80, 40],
  "secondary": ["a2", 40, 80], "on-secondary": ["a2", 100, 20],
  "secondary-container": ["a2", 90, 30], "on-secondary-container": ["a2", 30, 90],
  "tertiary": ["a3", 40, 80], "on-tertiary": ["a3", 100, 20],
  "tertiary-container": ["a3", 90, 30], "on-tertiary-container": ["a3", 30, 90],
  "background": ["n1", 99, 10], "on-background": ["n1", 10, 90],
  "surface": ["n1", 99, 10], "on-surface": ["n1", 10, 90],
  "surface-variant": ["n2", 90, 30], "on-surface-variant": ["n2", 30, 80],
  "outline": ["n2", 50, 60], "outline-variant": ["n2", 80, 30],
  "inverse-surface": ["n1", 20, 90], "inverse-on-surface": ["n1", 95, 20],
  "surface-dim": ["n1", 90, 10], "surface-bright": ["n1", 99, 20],
  "surface-container-lowest": ["n1", 100, 0], "surface-container-low": ["n1", 95, 10],
  "surface-container": ["n1", 95, 10], "surface-container-high": ["n1", 90, 20],
  "surface-container-highest": ["n1", 90, 20],
};
// Error + shadow/scrim aren't wallpaper-derived. Include them (M3's fixed values)
// so the dynamic block is a COMPLETE role set — data-accent="dynamic" stops the
// default :root rules from supplying anything.
const DYN_CONST_LIGHT = {
  "error": "#ba1a1a", "on-error": "#ffffff", "error-container": "#ffdad6",
  "on-error-container": "#93000a", "shadow": "#000000", "scrim": "#000000",
};
const DYN_CONST_DARK = {
  "error": "#ffb4ab", "on-error": "#690005", "error-container": "#93000a",
  "on-error-container": "#ffdad6", "shadow": "#000000", "scrim": "#000000",
};
function dynSupported() {
  if (DYN_RAMPS) return true;
  try {
    const raw = window.AndroidShell?.systemPalette?.();
    if (!raw) return false;
    const p = JSON.parse(raw);
    if (!p || !p.a1 || !p.n1) return false;
    DYN_RAMPS = p;
    return true;
  } catch (_) { return false; }
}
function dynPick(pal, tone) {
  const ramp = DYN_RAMPS[pal] || {};
  if (ramp[tone]) return ramp[tone];
  const tones = Object.keys(ramp).map(Number);
  if (!tones.length) return "#000000";
  let best = tones[0];
  for (const t of tones) if (Math.abs(t - tone) < Math.abs(best - tone)) best = t;
  return ramp[best];
}
function dynBlock(dark) {
  const consts = dark ? DYN_CONST_DARK : DYN_CONST_LIGHT;
  let out = "";
  for (const role in DYN_ROLES) {
    const [pal, lt, dt] = DYN_ROLES[role];
    out += `--md-sys-color-${role}:${dynPick(pal, dark ? dt : lt)};`;
  }
  for (const role in consts) out += `--md-sys-color-${role}:${consts[role]};`;
  return out;
}
// Build (or refresh) the <style> that defines the dynamic accent, mirroring the
// generator's light / dark-media / dark-attr selector shape so it responds to the
// theme toggle exactly like the baked accents. Returns false when unsupported.
function buildDynamicStyle() {
  if (!dynSupported()) return false;
  const css =
    `:root[data-accent="dynamic"],:root[data-accent="dynamic"][data-theme="light"]{${dynBlock(false)}}` +
    `@media (prefers-color-scheme:dark){:root[data-accent="dynamic"]:not([data-theme="light"]){${dynBlock(true)}}}` +
    `:root[data-accent="dynamic"][data-theme="dark"]{${dynBlock(true)}}`;
  let el = $("dynamic-accent");
  if (!el) { el = document.createElement("style"); el.id = "dynamic-accent"; document.head.appendChild(el); }
  el.textContent = css;
  return true;
}
function buildSwatches() {
  const box = $("accent-swatches");
  box.innerHTML = "";
  // Dynamic (wallpaper) swatch first — only when the native bridge actually
  // reports a palette, so desktop / pre-12 never get a dead control.
  if (buildDynamicStyle()) {
    const d = document.createElement("button");
    d.className = "swatch swatch-dynamic";
    d.dataset.accent = "dynamic";
    // Fixed tone 40 (not theme-adaptive): a stable saturated colour identity like
    // the six baked swatches. Theme-following tones (80 in dark) would make a pale
    // face under a pale primary ring with an invisible white check.
    d.style.background =
      `conic-gradient(from 210deg, ${dynPick("a1", 40)}, ` +
      `${dynPick("a3", 40)}, ${dynPick("a2", 40)}, ${dynPick("a1", 40)})`;
    d.setAttribute("aria-label", "Dynamic — from your wallpaper");
    d.title = "Dynamic (from wallpaper)";
    d.addEventListener("click", () => applyAccent("dynamic"));
    box.append(d);
  }
  for (const [name, color] of ACCENTS) {
    const b = document.createElement("button");
    b.className = "swatch";
    b.dataset.accent = name;
    b.style.background = color;
    b.setAttribute("aria-label", name);
    b.addEventListener("click", () => applyAccent(name));
    box.append(b);
  }
}
function initTheme() {
  buildSwatches();
  let accent = "violet", mode = "system";
  try {
    accent = localStorage.getItem("accent") || accent;
    mode = localStorage.getItem("mode") || mode;
    const savedShuffle = localStorage.getItem("shufflePin");
    if (savedShuffle !== null) shufflePin = savedShuffle === "1";
  } catch (_) {}
  // A "dynamic" accent saved on a device that no longer offers it (desktop, or
  // Android < 12) would leave data-accent set with no matching CSS block; fall
  // back to the default so the app never renders with an empty role set.
  if (accent === "dynamic" && !dynSupported()) accent = "violet";
  applyAccent(accent);
  applyMode(mode);
  document.querySelectorAll(".mode-btn").forEach((b) => b.addEventListener("click", () => applyMode(b.dataset.mode)));
  // When following the OS ("system" mode), re-sync the bar icons if the device
  // flips light/dark while the app is open.
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", syncSystemBars);
}

// ---------- api ----------
// Every call carries a timeout (Tor lookups can legitimately take ~80s cold;
// anything beyond that gets an AbortError the caller can surface as "still
// working / try again" instead of a button stuck on "Looking up…" forever).
const API_TIMEOUT_MS = 95000;
async function api(path, options = {}) {
  const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
  if (controlToken) headers["X-Control-Token"] = controlToken;
  if (sessionToken) headers["Authorization"] = "Bearer " + sessionToken;
  const timeoutMs = options.timeoutMs || API_TIMEOUT_MS;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(path, Object.assign({}, options, { headers, signal: ctrl.signal }));
    let body = {};
    try { body = await res.json(); } catch (_) {}
    return { ok: res.ok, status: res.status, body };
  } catch (e) {
    if (e && e.name === "AbortError") {
      return { ok: false, status: 0, body: { error: "The network is very slow — try again?" }, timedOut: true };
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

// ---------- confirm dialog ----------
// A promise-based modal confirmation. Every consequential action awaits this, so
// the warning is always an explicit popup the user must acknowledge — replacing
// the native window.confirm and the old "text that quietly expands below". Pass
// danger:true to paint the confirm button in the error colour for destructive
// actions. Resolves true on confirm, false on cancel / backdrop / Escape.
let confirmResolver = null;
let confirmReturnFocus = null;
function confirmDialog({ title, message, confirmLabel = "Confirm", cancelLabel = "Cancel", danger = false }) {
  const modal = $("confirm-modal");
  $("confirm-title").textContent = title;
  $("confirm-message").textContent = message;
  const ok = $("confirm-ok");
  const cancel = $("confirm-cancel");
  ok.textContent = confirmLabel;
  // An empty cancelLabel turns the dialog into a plain acknowledgement (OK only).
  cancel.hidden = !cancelLabel;
  cancel.textContent = cancelLabel || "";
  ok.classList.toggle("danger-fill", danger);
  // Non-danger confirms must not wear error tones — the class (not a permanent
  // inline style) is the single source of the button's colour.
  modal.hidden = false;
  confirmReturnFocus = document.activeElement;
  setTimeout(() => (cancel.hidden ? ok : cancel).focus(), 0);
  return new Promise((resolve) => {
    confirmResolver = (result) => {
      modal.hidden = true;
      confirmResolver = null;
      if (confirmReturnFocus && confirmReturnFocus.focus) {
        try { confirmReturnFocus.focus(); } catch (_) {}
      }
      confirmReturnFocus = null;
      resolve(result);
    };
  });
}
// confirmOpen lets the global Escape/back handler intercept an open dialog.
function confirmOpen() { return confirmResolver !== null; }
$("confirm-ok").addEventListener("click", () => confirmResolver && confirmResolver(true));
$("confirm-cancel").addEventListener("click", () => confirmResolver && confirmResolver(false));
$("confirm-modal").addEventListener("click", (e) => { if (e.target === $("confirm-modal") && confirmResolver) confirmResolver(false); });
$("confirm-modal").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && confirmResolver) { e.preventDefault(); confirmResolver(true); }
});

// editDialog: reusable modal for editing settings fields. Returns a Promise
// resolving with { password?, ...fieldValues } or null if cancelled.
//   title      — dialog heading
//   fields     — [{ id, label, type, inputmode?, value?, required? }]
//   values     — pre-filled values (for editing existing data)
//   passwordFirst — if true, prepends a password field (for PIN setup, etc.)
let editDialogResolver = null;
let editDialogReturnFocus = null;
function editDialog({ title, fields = [], values = {}, passwordFirst = false, confirmLabel = "Save", errorMessage = "" }) {
  $("edit-dialog-title").textContent = title;
  const wrap = $("edit-dialog-fields");
  wrap.innerHTML = "";
  const inputs = {};
  // Password field (optional, shown first)
  if (passwordFirst) {
    const pw = document.createElement("md-outlined-text-field");
    pw.setAttribute("label", "Your password");
    pw.setAttribute("type", "password");
    pw.setAttribute("autocomplete", "current-password");
    pw.style.width = "100%";
    wrap.append(pw);
    inputs._password = pw;
  }
  // Edit fields
  for (const f of fields) {
    const el = document.createElement("md-outlined-text-field");
    el.setAttribute("label", f.label);
    el.setAttribute("type", f.type || "text");
    if (f.inputmode) el.setAttribute("inputmode", f.inputmode);
    el.style.width = "100%";
    if (values[f.id] != null) el.value = values[f.id];
    wrap.append(el);
    inputs[f.id] = el;
  }
  // Error element — static text (never an editable field). Callers pass
  // errorMessage to reopen the dialog with a failure reason while keeping the
  // user's context, instead of closing and re-opening as a fake text input.
  const errEl = document.createElement("p");
  errEl.className = "label error";
  errEl.setAttribute("role", "alert");
  errEl.textContent = errorMessage || "";
  errEl.hidden = !errorMessage;
  wrap.append(errEl);
  $("edit-dialog-save").textContent = confirmLabel;
  $("edit-dialog").hidden = false;
  $("bottomnav").hidden = true;
  editDialogReturnFocus = document.activeElement;
  // Focus first field
  setTimeout(() => { const first = wrap.querySelector("md-outlined-text-field"); if (first) first.focus(); }, 50);
  return new Promise((resolve) => {
    editDialogResolver = (result) => {
      $("edit-dialog").hidden = true;
      // Restore bottom nav (may have been hidden for the dialog overlay).
      const isWideD = window.matchMedia("(min-width: 900px)").matches;
      $("bottomnav").hidden = detailContent !== null && !isWideD;
      editDialogResolver = null;
      if (editDialogReturnFocus && editDialogReturnFocus.focus) {
        try { editDialogReturnFocus.focus(); } catch (_) {}
      }
      editDialogReturnFocus = null;
      if (result === false) { resolve(null); return; }
      // Collect values
      const out = {};
      if (passwordFirst) out.password = inputs._password.value;
      for (const f of fields) out[f.id] = inputs[f.id].value;
      resolve(out);
    };
  });
}
$("edit-dialog-cancel").addEventListener("click", () => editDialogResolver && editDialogResolver(false));
$("edit-dialog-save").addEventListener("click", () => editDialogResolver && editDialogResolver(true));
$("edit-dialog").addEventListener("click", (e) => { if (e.target === $("edit-dialog")) editDialogResolver && editDialogResolver(false); });
$("edit-dialog").addEventListener("keydown", (e) => {
  if (e.key === "Escape") { editDialogResolver && editDialogResolver(false); }
  if (e.key === "Enter" && !e.target.closest("textarea")) { e.preventDefault(); editDialogResolver && editDialogResolver(true); }
});

// A plain acknowledgement popup (single button) for "?" helpers and "Learn
// more" explainers — reuses the confirm modal's OK-only mode (empty cancel).
function infoDialog(title, message) {
  return confirmDialog({ title, message, confirmLabel: "Got it", cancelLabel: "" });
}
// Shared Tab trap for the hand-rolled modals (Material Web's md-dialog would
// give this for free; for the div-dialogs we wire it once). Cycles focus
// within the card so keyboard/switch users can't tab into the page behind.
function trapModalFocus(card, e) {
  if (e.key !== "Tab") return;
  const nodes = [...card.querySelectorAll(
    'button:not([disabled]), [href], input:not([disabled]), select, textarea, md-text-button, md-filled-button, md-filled-tonal-button, md-outlined-button, md-outlined-text-field, md-filled-text-field'
  )].filter((el) => !el.hidden && el.offsetParent !== null);
  if (!nodes.length) return;
  const first = nodes[0], last = nodes[nodes.length - 1];
  if (e.shiftKey && (document.activeElement === first || document.activeElement === card)) {
    e.preventDefault(); last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault(); first.focus();
  }
}
$("confirm-modal")?.querySelector(".modal-card")?.addEventListener("keydown", (e) => trapModalFocus(e.currentTarget, e));
$("edit-dialog")?.querySelector(".modal-card")?.addEventListener("keydown", (e) => trapModalFocus(e.currentTarget, e));
// Subtle haptic tick where the platform has a vibrator; a silent no-op on
// desktop and in the headless harness. Guarded exactly like the long-press site.
function haptic(ms = 10) {
  try { navigator.vibrate && navigator.vibrate(ms); } catch (_) {}
}

const shortAccount = (a) => (a.length > 18 ? a.slice(0, 8) + "…" + a.slice(-6) : a);
// contactLabel is the ONE rule for how a contact is named anywhere in the UI: the
// user's private nickname wins over the name the peer publishes for themselves,
// which in turn beats a shortened account number. Every surface showing a human
// name must come through here — read `.name` directly and that surface silently
// ignores the nickname, which is worse than not having the feature (a chat list
// and a notification disagreeing about who is messaging you). The Go side holds
// the same rule in contactDisplayNameLocked() for the labels it produces, since
// system notifications and group-author names never pass through this file.
function contactLabel(c, fallback) {
  if (!c) return fallback || "";
  // Rows that reach us from the server without a nickname field (a relay holder, a
  // group roster entry) are still resolved against the live contact list, so the
  // nickname applies to them too.
  const live = c.account ? contacts.find((x) => x.account === c.account) : null;
  return c.nickname || (live && live.nickname) || c.name || (live && live.name) ||
    fallback || (c.account ? shortAccount(c.account) : "");
}
function contactName(account) {
  return contactLabel(contacts.find((c) => c.account === account), shortAccount(account));
}
function fmtTime(at) {
  const d = new Date(at);
  if (isNaN(d)) return "";
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  const time = d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  if (sameDay) return time;
  const dayMs = 86400000;
  const yesterday = new Date(now.getTime() - dayMs).toDateString() === d.toDateString();
  if (yesterday) return "Yesterday " + time;
  return d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + time;
}
function unreadFor(account) {
  const c = contacts.find((c) => c.account === account);
  return c && c.unread ? c.unread : 0;
}
function totalUnread() {
  const c = contacts.reduce((n, c) => n + (c.status === "accepted" ? (c.unread || 0) : 0), 0);
  const g = groups.reduce((n, gr) => n + (gr.unread || 0), 0);
  return c + g;
}
function lastMsgPreview(account) {
  const msgs = messages.filter((m) => m.peer === account);
  if (msgs.length === 0) return "";
  const m = msgs[msgs.length - 1];
  const raw = m.kind === "image" ? "📷 Photo" : m.text;
  const t = raw.length > 38 ? raw.slice(0, 38) + "…" : raw;
  return (m.direction === "out" ? "You: " : "") + t;
}

// ---------- groups ----------
function groupMsgs(gid) { return messages.filter((m) => m.group_id === gid); }
function lastGroupMsgAt(gid) { const ms = groupMsgs(gid); return ms.length ? ms[ms.length - 1].at : null; }
function groupById(gid) { return groups.find((g) => g.id === gid); }
function groupName(gid) { const g = groupById(gid); return g ? g.name : "Group"; }
function msgAuthorName(m) { return m.direction === "out" ? "You" : (m.author_name || shortAccount(m.author || "")); }
function lastGroupPreview(gid) {
  const ms = groupMsgs(gid);
  if (ms.length === 0) return "";
  const m = ms[ms.length - 1];
  const t = m.text.length > 30 ? m.text.slice(0, 30) + "…" : m.text;
  return msgAuthorName(m) + ": " + t;
}
function groupUnread(gid) { const g = groupById(gid); return g && g.unread ? g.unread : 0; }

// ---------- top-level screens ----------
const screens = { none: $("view-none"), locked: $("view-locked"), unlocked: $("view-unlocked"), loading: $("loading") };
function show(name) {
  for (const [k, el] of Object.entries(screens)) el.hidden = k !== name;
  // Entering onboarding: (re)start the wizard, resuming any saved pre-account step.
  if (name === "none") wizInit();
}

async function refresh() {
  let res;
  try {
    res = await api("/api/status");
  } catch (_) {
    // fetch() rejects only on a network-level failure (backend down or gone).
    // Without this the boot screen spun "Loading…" forever with no way out.
    if (!$("loading").hidden) return showLoadingError("Couldn't reach the Molepipe backend.");
    showToast("Couldn't reach the Molepipe backend.");
    return;
  }
  const { ok, status, body } = res;
  // A 403 here means the control listener rejected us: our capability token is
  // missing or stale (e.g. a browser tab reopened from history after the token
  // was scrubbed, or the backend restarted with a fresh token). No API call can
  // succeed until the page is reloaded from the app, so say so plainly instead
  // of silently failing every request. Not reachable on the Android/desktop
  // shells, which always (re)load us at ?ct=<token>.
  if (!ok && status === 403) return showControlTokenError();
  if (!body.has_identity) return show("none");
  if (sessionToken && body.unlocked) return showUnlocked();
  pinEnabled = !!body.pin_enabled;
  showLockScreen();
}

// showLoadingError parks the boot screen on a plain failure message with a
// Retry button. Without it, anything that stopped the boot chain left the page
// on the silent infinite "Loading…" placeholder — indistinguishable from a
// broken script, with nothing to try.
function showLoadingError(message) {
  const msg = $("loading-msg");
  if (msg) msg.textContent = message;
  const retry = $("loading-retry");
  if (retry) retry.hidden = false;
  show("loading");
}

// showControlTokenError parks the app on a clear "reopen me from the app"
// message. Used when we boot without a usable control token (see refresh).
// No Retry: a spent or missing token can only be fixed by relaunching.
function showControlTokenError() {
  const msg = $("loading-msg");
  if (msg) msg.textContent = "This page must be opened from the Molepipe app. Please relaunch the app to continue.";
  const retry = $("loading-retry");
  if (retry) retry.hidden = true;
  show("loading");
}

// showLockScreen picks which credential to ask for. The PIN pad leads when this
// device has a shortcut, but the password form is never more than one tap away
// — it is the real secret and must always be usable.
function showLockScreen() {
  showPinEntry(pinEnabled);
  show("locked");
}
let pinBuffer = "";

function updatePinDots() {
  // Dots are created/destroyed to match the buffer length rather than filling a
  // fixed row — no placeholders means the resting screen and the PIN's length
  // are never shown. Each new dot animates in (see .pin-dot in style.css).
  const container = $("pin-dots");
  if (!container) return;
  const want = pinBuffer.length;
  while (container.childElementCount < want) {
    const dot = document.createElement("span");
    dot.className = "pin-dot";
    container.appendChild(dot);
  }
  while (container.childElementCount > want) {
    container.lastElementChild.remove();
  }
}

function scrambleArray(arr) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function renderPinKeypad() {
  const grid = $("pin-keypad-grid");
  if (!grid) return;
  grid.innerHTML = "";
  const digits = shufflePin ? scrambleArray([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]) : [1, 2, 3, 4, 5, 6, 7, 8, 9, 0];

  for (let i = 0; i < 9; i++) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "keypad-btn";
    btn.dataset.num = digits[i];
    btn.textContent = digits[i];
    grid.appendChild(btn);
  }

  const backBtn = document.createElement("button");
  backBtn.type = "button";
  backBtn.className = "keypad-btn keypad-btn-action";
  backBtn.dataset.action = "back";
  backBtn.setAttribute("aria-label", "Backspace");
  backBtn.innerHTML = '<svg class="icon"><use href="#ic-backspace"/></svg>';
  grid.appendChild(backBtn);

  const lastNumBtn = document.createElement("button");
  lastNumBtn.type = "button";
  lastNumBtn.className = "keypad-btn";
  lastNumBtn.dataset.num = digits[9];
  lastNumBtn.textContent = digits[9];
  grid.appendChild(lastNumBtn);

  const subBtn = document.createElement("button");
  subBtn.type = "button";
  subBtn.className = "keypad-btn keypad-btn-action";
  subBtn.dataset.action = "submit";
  subBtn.setAttribute("aria-label", "Submit PIN");
  subBtn.innerHTML = '<svg class="icon"><use href="#ic-check"/></svg>';
  grid.appendChild(subBtn);
}

function showPinEntry(usePin) {
  $("pin-form").hidden = !usePin;
  $("unlock-form").hidden = usePin;
  $("use-pin-btn").hidden = !pinEnabled;
  const sub = $("lock-subtitle");
  if (sub) sub.textContent = usePin ? "Enter your PIN to unlock" : "Enter your password to unlock";
  $("pin-error").hidden = true;
  const pinLeft = $("pin-attempts"); if (pinLeft) pinLeft.hidden = true;
  $("unlock-error").hidden = true;
  $("pin").value = "";
  $("password").value = "";
  pinBuffer = "";
  if (usePin && isAndroid) {
    $("pin-desktop-view").hidden = true;
    $("pin-keypad-view").hidden = false;
    updatePinDots();
    renderPinKeypad();
  } else {
    $("pin-desktop-view").hidden = false;
    $("pin-keypad-view").hidden = true;
    if (usePin) setTimeout(() => $("pin").focus(), 0);
    else setTimeout(() => $("password").focus(), 0);
  }
}

// Render a shareable friend code with the parts people actually verify picked out.
//
// A friend code is either a bare 56-char base32 account number or the versioned
// "mp1:<account>:<token>" form (protocol.EncodeInviteCode). Neither carries a
// ".onion" suffix — AccountNumber() is the bare base32; only OnionAddress()
// appends the TLD.
//
// The head/tail emphasis exists for one job: the only check anyone performs on
// an opaque high-entropy string is comparing its first and last few chars
// against a known-good copy, so the eye is pointed straight at those. That has
// to emphasize the ACCOUNT's endpoints — the account is the durable identity.
// Emphasizing the endpoints of the whole code instead picks out the constant
// "mp1:" prefix (identical for every user, so it verifies nothing) and the tail
// of the one-time token (rotates on every refresh, so it verifies nothing
// either), while burying the account's real endpoints in the dimmed middle.
//
// The account is chunked into groups of 4 (the Signal-safety-number treatment)
// so the eye can track position while comparing, and the first and last GROUP
// carry the emphasis — same job as before, now aligned to the chunk boundaries.
//
// The token is dimmed as a trailing field rather than chunked: it is ephemeral
// and nobody compares it. The raw code is stashed in dataset.full; the Copy and
// QR handlers read ONLY that, so this visual markup can't corrupt what ships.
function renderFriendCode(el, full) {
  el.dataset.full = full;
  el.textContent = "";
  const add = (text, cls) => {
    if (!text) return;
    const s = document.createElement("span");
    s.className = cls; s.textContent = text; el.appendChild(s);
  };
  // Split on the real delimiters. Account numbers and the base64url token
  // alphabet contain no ':', so the colon is unambiguous (see
  // protocol.ParseInviteCode, which splits the same way).
  let account = full, prefix = "", token = "";
  const parts = full.split(":");
  if (parts.length === 3 && parts[0]) {
    [prefix, account, token] = parts;
  }
  add(prefix && prefix + ":", "addr-scheme");
  // Chunk the account into groups of 4. The groups are separate elements with
  // no separator CHARACTER between them — the gap is flex spacing in CSS — so
  // concatenating the spans still reproduces the code byte for byte, and a
  // manual text selection doesn't pick up spaces that aren't in the real code.
  // Wrapping then happens at group boundaries instead of mid-group.
  const groups = account.match(/.{1,4}/g) || [];
  groups.forEach((g, i) => {
    const edge = groups.length > 2 && (i === 0 || i === groups.length - 1);
    add(g, "addr-grp " + (edge ? "addr-hi" : "addr-mid"));
  });
  add(token && ":" + token, "addr-token");
}

async function showUnlocked() {
  const { ok, body } = await api("/api/identity");
  if (!ok) { setSessionToken(null); return show("locked"); }
  // #account now shows the shareable friend code (loaded by loadInviteCode), not
  // the raw account number — the account alone is no longer addable.
  selfAccount = body.account_number;
  updateTor(body);
  show("unlocked");
  setTab("chats");
  await Promise.all([loadProfile(), loadContacts(), loadGroups(), loadRequests(), loadGroupInvites(), loadMessages(), loadDesktop(), loadInviteCode()]);
  poll();
  // Only now — with a session, and the contact list loaded — collect anything
  // shared into us from another app. See consumeSharedImage.
  consumeSharedImage();
}

// ---------- navigation ----------
// showDetail controls the detail pane (chat / add / group-info / placeholder).
// On mobile the detail pane overlays the sidebar; on desktop it's the right pane.
function showDetail(kind) {
  detailContent = kind;
  // Wide layout: with the You/Requests tabs active and no chat open, render
  // full-width instead of squeezing settings into the master column beside a
  // stale "Select a conversation" placeholder (which sat pixel-identical across
  // every settings screen in the landscape audit). The Chats tab keeps the
  // placeholder — there the detail pane is a legitimate chat picker.
  if ($("shell")) {
    const wideSolo = window.matchMedia("(min-width: 900px)").matches && kind === null && currentTab !== "chats";
    $("shell").classList.toggle("wide-solo", wideSolo);
  }
  $("detail-placeholder").hidden = kind !== null;
  $("chat-screen").hidden = kind !== "chat";
  $("add-screen").hidden = kind !== "add";
  $("group-info").hidden = kind !== "group-info";
  $("contact-info").hidden = kind !== "contact-info";
  $("chat-menu").hidden = true;
  $("group-menu").hidden = true;
  // The overflow menu is a contact menu for a 1:1 chat and a group menu for a
  // group chat; only the relevant one is reachable.
  $("chat-menu-btn").hidden = kind !== "chat";
  $("back-btn").hidden = kind === null;
  $("shell").classList.toggle("detail-open", kind !== null);
  // Marks the header as a control: in a 1:1 chat the name/avatar opens the
  // friend profile (see ciHeaderTap), so the cursor must say so.
  $("shell").classList.toggle("chat-contact", kind === "chat" && chatKind === "contact");
  // Hide bottom nav when a detail pane overlays the sidebar (mobile only;
  // on desktop the two panes sit side-by-side and bottomnav is always visible).
  const isWide = window.matchMedia("(min-width: 900px)").matches;
  $("bottomnav").hidden = kind !== null && !isWide;
  $("detail-title").textContent =
    kind === "chat" ? (chatKind === "group" ? groupName(currentGroup) : contactName(currentPeer)) :
    kind === "add" ? (currentAddMode === "group" ? "New group" : "Message someone") :
    kind === "group-info" ? "Group info" :
    kind === "contact-info" ? contactName(currentPeer) : "";
  // Chat header avatar: only for a 1:1 contact chat (groups keep their icon badge
  // in the list; the header just shows the name). Renders from the local cache.
  const da = $("detail-avatar");
  if (da) {
    da.innerHTML = "";
    if (kind === "chat" && chatKind === "contact" && currentPeer) {
      const c = contacts.find((x) => x.account === currentPeer);
      da.append(avatarNode(c && c.avatar_hash, contactName(currentPeer), null));
      da.hidden = false;
    } else {
      da.hidden = true;
    }
  }
  updateChatPresence();
}
function setTab(tab) {
  currentTab = tab;
  // In the side-by-side (wide) layout the left sidebar's tabs and the right
  // detail pane are independent, so switching tabs — including to "You"
  // (settings) — must NOT close a chat open on the right. In the narrow/overlay
  // layout the tabs are full screens, so collapse the detail overlay to reveal
  // the selected tab. Only an open chat is preserved; other panes reset.
  const wide = window.matchMedia("(min-width: 900px)").matches;
  if (!(wide && detailContent === "chat")) { leaveChatRead(); showDetail(null); }
  // FAB shows on Chats only, and only when the empty state isn't already
  // offering the same actions.
  $("fab-add").hidden = tab !== "chats" || !$("no-contacts").hidden;
  $("search-btn").hidden = tab !== "chats";
  if ($("header-gap")) $("header-gap").hidden = tab !== "chats";
  $("sidebar-title").textContent = TABS[tab];
  for (const t of ["chats", "requests", "you"]) $("tab-" + t).hidden = t !== tab;
  document.querySelectorAll(".navitem").forEach((n) => n.classList.toggle("active", n.dataset.tab === tab));
  if (tab === "you") { showYouPane(youPane); loadDevices(); loadPinState(); loadWipeState(); loadInviteCode(); }
}
// You-tab sub-navigation: show one pane's wrappers, hide the rest. Toggles a
// class (not `hidden`), so cards keep their own hidden state within a pane.
// The last-shown pane is remembered so returning to the You tab lands where the
// user left off (a deep-link like "Share my code" overrides it explicitly).
let youPane = "profile";
function showYouPane(pane) {
  youPane = pane;
  document.querySelectorAll("#tab-you .you-tab").forEach((t) => {
    const on = t.dataset.pane === pane;
    t.classList.toggle("active", on);
    t.setAttribute("aria-selected", on ? "true" : "false");
  });
  document.querySelectorAll("#tab-you [data-you-pane]").forEach((el) => el.classList.toggle("pane-on", el.dataset.youPane === pane));
}
document.querySelectorAll("#tab-you .you-tabs .you-tab").forEach((t) => t.addEventListener("click", () => showYouPane(t.dataset.pane)));
function openChat(account) {
  currentPeer = account;
  currentGroup = null;
  chatKind = "contact";
  clearReply();
  showDetail("chat");
  $("send-error").hidden = true;
  $("attach-btn").hidden = false; // photos are 1:1 only for now
  renderMessages(true); // opening a chat always lands at the newest message
  reflectSendState();
  updateChatPresence();
  // On desktop, focusing the box lets you type straight away. On the phone that
  // would pop the soft keyboard the moment a chat opens — before you've even
  // read it — so leave the box unfocused and let a tap raise the keyboard.
  if (!isAndroid) $("compose-text").focus();
  markRead(account);
}
function openGroup(gid) {
  currentGroup = gid;
  currentPeer = null;
  chatKind = "group";
  clearReply();
  showDetail("chat");
  $("send-error").hidden = true;
  $("attach-btn").hidden = false; // group photos: blurry preview fans out, full on demand
  renderMessages(true); // opening a chat always lands at the newest message
  reflectSendState();
  if (!isAndroid) $("compose-text").focus();
  markGroupRead(gid);
}
async function markGroupRead(gid) {
  const g = groupById(gid);
  if (!g || !g.unread) return;
  g.unread = 0;            // clear locally for instant feedback
  renderContacts();
  await api("/api/groups/read", { method: "POST", body: JSON.stringify({ group: gid }) });
}
async function markRead(account) {
  const c = contacts.find((c) => c.account === account);
  if (!c || !c.unread) return;
  c.unread = 0;               // clear locally for instant feedback
  renderContacts();
  await api("/api/read", { method: "POST", body: JSON.stringify({ account }) });
}
// markReadNow/markGroupReadNow post unconditionally (no local-unread guard), for
// messages that arrive WHILE the chat is open and focused: the server-side unread
// has just been incremented but our local copy may not have caught up this poll,
// so the guard in markRead would skip the POST and leave a phantom badge until
// you re-enter the chat.
function markReadNow(account) {
  const c = contacts.find((c) => c.account === account);
  if (c) c.unread = 0;
  renderContacts();
  api("/api/read", { method: "POST", body: JSON.stringify({ account }) });
}
function markGroupReadNow(gid) {
  const g = groupById(gid);
  if (g) g.unread = 0;
  renderContacts();
  api("/api/groups/read", { method: "POST", body: JSON.stringify({ group: gid }) });
}
// reconcileOpenChatRead keeps the open+focused chat marked read on EVERY poll.
// markReadNow (from maybeNotify) fires only once, for a "fresh" message; but
// loadContacts overwrites our local unread with the server's on every poll, so if
// the server's unread hasn't dropped yet a phantom badge reappears and nothing
// re-clears it while you sit in the chat — the "exit, enter, exit again" bug. Run
// after each poll's loads: if the open chat still shows unread, re-post the read.
function reconcileOpenChatRead() {
  if (detailContent !== "chat" || document.visibilityState !== "visible") return;
  if (chatKind === "group" && currentGroup) {
    const g = groupById(currentGroup);
    if (g && g.unread) markGroupReadNow(currentGroup);
  } else if (chatKind === "contact" && currentPeer) {
    const c = contacts.find((c) => c.account === currentPeer);
    if (c && c.unread) markReadNow(currentPeer);
  }
}
// leaveChatRead posts a final read for the chat we're leaving (back button OR a
// tab switch that collapses it), so a message that arrived while it was open —
// already marked read locally — cannot re-badge on the next poll if our earlier
// /api/read hadn't landed server-side yet. See item 4.
function leaveChatRead() {
  if (detailContent !== "chat") return;
  if (chatKind === "group" && currentGroup) markGroupReadNow(currentGroup);
  else if (chatKind === "contact" && currentPeer) markReadNow(currentPeer);
}
function openAdd() {
  $("find-form").reset && $("find-form").reset();
  $("find-result").hidden = true;
  $("find-error").hidden = true;
  $("find-preview").hidden = true;
  $("find-help-text").hidden = false;
  $("group-create-error").hidden = true;
  lookupResult = null;
  showDetail("add");
  setAddMode("person");
  // Offer camera scanning only where it's actually available (a WebView with a
  // camera + our vendored decoder); otherwise the paste field stands alone.
  $("scan-btn").hidden = !scanSupported();
}
// setAddMode switches the add screen between finding a person and creating a group.
function setAddMode(mode) {
  currentAddMode = mode;
  const person = mode !== "group";
  $("find-form").hidden = !person;
  $("group-create-form").hidden = person;
  document.querySelectorAll("#add-toggle .seg").forEach((s) => s.classList.toggle("active", s.dataset.add === mode));
  // Update header title to match the active mode.
  if (detailContent === "add") $("detail-title").textContent = person ? "Message someone" : "New group";
  if (person) $("find-account").focus(); else $("group-name-input").focus();
}
async function openGroupInfo() {
  showDetail("group-info");
  $("edit-dialog").hidden = true;
  $("group-invite-form").hidden = true;
  await loadGroupMembers();
}
async function loadGroupMembers() {
  if (!currentGroup) return;
  const { ok, body } = await api("/api/groups/members?group=" + encodeURIComponent(currentGroup));
  if (!ok) return;
  groupMembers = body.members || [];
  groupInfoCtx = { my_role: body.my_role, i_can_invite: body.i_can_invite, policy: body.policy, name: body.name };
  renderGroupInfo();
}
function backAction() {
  // Group-info is a sub-screen of an open chat: back returns to it.
  if (detailContent === "group-info") { showDetail("chat"); return; }
  if (detailContent === "contact-info") { showDetail("chat"); return; }
  leaveChatRead(); // final read before we drop the chat, so it can't re-badge (item 4)
  currentPeer = null;
  currentGroup = null;
  chatKind = null;
  showDetail(null);
}

// ---------- data ----------
// " (2m)" once the send-only window has lasted long enough to be worth saying.
// Below a minute the number would just be noise — publishing that fast is the
// normal case and needs no explanation.
function publishElapsedSuffix() {
  if (torPublishSince === 0) return "";
  const mins = Math.floor((Date.now() - torPublishSince) / 60000);
  return mins >= 1 ? " (" + mins + "m)" : "";
}
function updateTor(body) {
  torReady = !!(body.tor_enabled && body.tor_ready);
  // Older backends don't report tor_sendable; fall back to tor_ready so the
  // button isn't wedged on a mismatched pair. Newer backends set it true as
  // soon as outbound circuits are up — before the descriptor is published.
  const prevSendable = torSendable;
  torSendable = !!(body.tor_enabled && (body.tor_sendable ?? body.tor_ready));
  torBootstrapFrac = body.tor_bootstrap_frac ?? 0;
  torHsState = body.tor_hs_state ?? "";
  torServiceState = body.tor_service_state ?? "";
  // Clock for the send-only window, kept the same way as torConnectingSince:
  // wall clock, because a backgrounded webview freezes timers and would
  // under-count. Starts when we first become sendable-but-not-reachable and
  // clears the moment either side of that changes.
  if (torSendable && !torReady) {
    if (torPublishSince === 0) torPublishSince = Date.now();
  } else {
    torPublishSince = 0;
  }
  // Track HOW LONG we've been connecting by wall clock (Date.now), not a poll
  // count: a backgrounded webview freezes timers and would under-count. Start the
  // clock when we ENTER a connecting state — on a fresh load already connecting
  // (no clock yet), or on any sendable true->false drop so a mid-session drop
  // gets a fresh clock instead of inheriting a stale "stalled" verdict — and
  // clear it the moment we're sendable again.
  if (body.tor_enabled && !torSendable) {
    if (prevSendable || torConnectingSince === 0) torConnectingSince = Date.now();
  } else {
    torConnectingSince = 0;
  }

  // --- tor-status text (You tab) ---
  const el = $("tor-status");
  if (el) {
    if (!body.tor_enabled) el.textContent = "Onion service: disabled";
    else if (body.tor_ready) el.textContent = "Onion service: online \u2014 send \u2713 receive \u2713";
    // Bootstrapped enough to send, but our address isn't on the network yet. The
    // header pill only has room for two words per direction; this is where the
    // whole story goes, elapsed time included, because "publishing\u2026" with no
    // number is what makes a slow publish feel broken rather than slow.
    else if (torSendable) el.textContent = "Onion service: send \u2713 receive \u2014 publishing your address" + publishElapsedSuffix() + "; you can message people now, their replies arrive once it's published";
    // Still no outbound circuits. Distinguish "just started" from "stuck" by
    // elapsed wall-clock time — honestly time-derived, not a real progress %,
    // since the backend exposes only two booleans (no bootstrap percentage).
    else if (torConnectingSince > 0 && Date.now() - torConnectingSince > TOR_STALLED_MS) {
      const hint = torStallHint ? " \u2014 last: " + torStallHint : "";
      el.textContent = "Onion service: still connecting \u2014 check your internet connection" + hint;
    }
    else el.textContent = "Onion service: connecting to Tor\u2026";
  }

  // Fetch the last log line once when a stall is first detected
  if (torConnectingSince > 0 && Date.now() - torConnectingSince > TOR_STALLED_MS && !torStallHint) {
    api("/api/tor-log").then(r => {
      if (r.ok && r.body && r.body.lines && r.body.lines.length > 0) {
        torStallHint = r.body.lines[r.body.lines.length - 1];
      }
    }).catch(() => {});
  }
  // Clear the hint when we recover
  if (torSendable || !torConnectingSince) torStallHint = "";

  // --- tor pill (sidebar header) ---
  const pill = $("tor-pill");
  if (pill) {
    let state, label, split = false;
    if (!body.tor_enabled) {
      state = "offline"; label = "Offline";
    } else if (torHsState === "running") {
      state = "online"; label = "Online";
    } else if (torHsState === "publishing") {
      // The one state where the two directions disagree: we can send, nobody can
      // reach us yet. Show both legs rather than picking a word that misreports
      // one of them — "Online" would claim reachability we don't have, and
      // "Publishing\u2026" hides that sending already works. Collapses back to a
      // single "Online" above, as soon as both agree.
      state = "connecting"; split = true;
    } else if (torHsState === "bootstrapping") {
      state = "connecting";
      // Descriptive labels based on bootstrap fraction ranges
      const pct = Math.round(torBootstrapFrac * 100);
      if (torBootstrapFrac <= 0) {
        label = "Connecting\u2026";
      } else if (torBootstrapFrac < 0.1) {
        label = "Connecting to Tor\u2026";
      } else if (torBootstrapFrac < 0.3) {
        label = "Fetching directory\u2026 " + pct + "%";
      } else if (torBootstrapFrac < 0.6) {
        label = "Building circuits\u2026 " + pct + "%";
      } else if (torBootstrapFrac < 0.9) {
        label = "Almost ready\u2026 " + pct + "%";
      } else {
        label = "Finalizing\u2026 " + pct + "%";
      }
    } else if (torConnectingSince > 0 && Date.now() - torConnectingSince > TOR_STALLED_MS) {
      state = "stalled"; label = "Stalled";
    } else {
      state = "connecting"; label = "Connecting\u2026";
    }
    pill.className = "tor-pill " + state + (split ? " split" : "");
    // Exactly one of the two renderings is live at a time: single icon + word, or
    // the two direction legs.
    const iconEl = pill.querySelector(".pill-icon");
    const labelEl = pill.querySelector(".pill-label");
    const splitEl = pill.querySelector(".pill-split");
    if (iconEl) iconEl.hidden = split;
    if (labelEl) {
      labelEl.hidden = split;
      if (!split) labelEl.textContent = label;
    }
    if (splitEl) {
      splitEl.hidden = !split;
      if (split) {
        const legs = splitEl.querySelectorAll(".pill-leg");
        if (legs.length === 2) {
          legs[0].classList.remove("waiting");
          legs[1].classList.add("waiting");
          // Deliberately no elapsed count on the leg itself. The six minutes
          // this window lasts on hardware is mostly arti waiting out HsDirs
          // that never answer, and the service is very likely reachable well
          // before the status flips — so a prominent ticking "Receive 5m"
          // would be shouting about a wait that is partly fictional. The
          // number stays on the hover title and the You tab, where it reads
          // as "how long we have been in this state" rather than a promise.
          legs[0].setAttribute("aria-label", "Sending: ready");
          // The service's own word for what it is doing, where we have it:
          // "recovering" or "degraded-unreachable" after a failed upload reads
          // very differently from a first publish still in progress.
          const detail = torServiceState && torServiceState !== "unknown" ? " (" + torServiceState + ")" : "";
          legs[1].setAttribute("aria-label", "Receiving: publishing your address" + publishElapsedSuffix() + detail);
        }
      }
    }
    pill.title = split
      ? "You can send now. Your address is still publishing" + publishElapsedSuffix() + ", so people can't reach you yet."
      : "";
    // Progress bar: set width from bootstrap fraction for determinate states
    const barFill = pill.querySelector(".pill-bar-fill");
    if (barFill) {
      if (state === "online" || state === "offline" || state === "stalled") {
        barFill.style.width = "0%";
        barFill.style.animation = "none";
      } else if (torBootstrapFrac > 0 && torBootstrapFrac < 1) {
        barFill.style.animation = "none";
        barFill.style.transform = "none";
        barFill.style.width = Math.round(torBootstrapFrac * 100) + "%";
      } else {
        barFill.style.width = "";
        barFill.style.animation = "";
        barFill.style.transform = "";
      }
    }
  }

  reflectSendState();
}
function reflectSendState() {
  if (detailContent !== "chat") return;
  // Send needs only OUTBOUND circuits (we dial the recipient), not our own
  // descriptor being published — so gate on sendable, not ready.
  // Also disable when compose box is empty.
  $("send-btn").disabled = !torSendable || !$("compose-text").value.trim();
}

let pollTimer = null;
// refreshAll pulls one full snapshot of everything on screen. Both the 2.5s
// poll and the manual refresh (pull-down / desktop button) go through here, so
// a manual refresh is exactly a tick that happened early. Returns false when
// the session is gone, which tells the caller not to keep polling.
async function refreshAll() {
  if (!sessionToken) return false;
  const { ok, status, body } = await api("/api/identity");
  // The session can be ended from outside this page: another tab locking, or
  // the desktop build's tray "Lock". Left unhandled, polling would stop and
  // the window would keep showing a conversation list for an account that is
  // locked and offline — so fall back to the lock screen when the token dies.
  if (status === 401) { setSessionToken(null); showLockScreen(); return false; }
  if (!ok) return false;
  updateTor(body);
  await Promise.all([loadProfile(), loadContacts(), loadGroups(), loadRequests(), loadGroupInvites(), loadMessages(), loadDesktop()]);
  // Keep the displayed friend code fresh while the user is looking at it: under
  // auto-refresh a redemption rotates the token server-side, so a stale code on
  // screen would otherwise be shared and rejected. Only while the profile pane is
  // actually visible, to avoid regenerating a QR every tick.
  if (currentTab === "you" && youPane === "profile") loadInviteCode();
  reconcileOpenChatRead(); // after all loads, so contacts/groups are the fresh server copy
  return true;
}
function poll() {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(async () => {
    if (!(await refreshAll())) return;
    poll();
  }, 2500);
}

// ---- manual refresh (pull-down on touch, button on desktop) ----
// The poll already reloads everything every 2.5s, so this is not about getting
// data sooner — it is the gesture people reach for when something looks stuck
// (a request that still says "Requested", a message that hasn't arrived). It
// also kicks the backend's own fetches: /api/identity and /api/messages are
// what drive a mailbox sweep, so an early tick is a real retry, not just a
// repaint. Shown for at least a moment so the pull visibly did something.
let refreshing = false;
const PTR_SPIN_MIN_MS = 500;
async function manualRefresh() {
  if (refreshing || !sessionToken) return;
  refreshing = true;
  setPtr(56, true, true);
  const btn = $("refresh-btn");
  if (btn) { btn.disabled = true; btn.classList.add("spinning"); }
  const started = Date.now();
  try {
    await refreshAll();
  } finally {
    const left = PTR_SPIN_MIN_MS - (Date.now() - started);
    if (left > 0) await new Promise((r) => setTimeout(r, left));
    refreshing = false;
    setPtr(0, false, false);
    if (btn) { btn.disabled = false; btn.classList.remove("spinning"); }
    poll(); // restart the cadence from now, so the next tick is a full interval away
  }
}

// setPtr places the pull-to-refresh indicator. `dist` is how far down it has
// been dragged (0 parks it back above the top edge), `armed` highlights it once
// the release threshold is passed, `spin` runs it while the refresh is in
// flight. `settling` turns the CSS transition on for anything that is not a
// finger-driven move, so the snap back is animated but the drag is not.
function setPtr(dist, armed, spin) {
  const el = $("ptr");
  if (!el) return;
  const dragging = dist > 0 && !spin;
  el.classList.toggle("settling", !dragging);
  el.classList.toggle("armed", !!armed);
  el.classList.toggle("spinning", !!spin);
  el.style.transform = dist > 0 ? `translateY(${dist - 44}px)` : "translateY(-44px)";
  el.style.opacity = dist > 0 ? String(Math.min(1, dist / 48)) : "0";
}

// enablePullToRefresh wires the gesture on one scrollable tab. Only starts when
// the list is already scrolled to the top, so it never fights a normal scroll.
function enablePullToRefresh(scroller) {
  if (!scroller) return;
  const TRIGGER = 64, MAX = 96, DAMP = 0.5;
  let startY = 0, pulling = false, dist = 0;
  scroller.addEventListener("touchstart", (e) => {
    if (refreshing || e.touches.length !== 1 || scroller.scrollTop > 0) { pulling = false; return; }
    startY = e.touches[0].clientY; pulling = true; dist = 0;
  }, { passive: true });
  scroller.addEventListener("touchmove", (e) => {
    if (!pulling) return;
    const dy = e.touches[0].clientY - startY;
    // Finger went up, or the list scrolled under us: this is a scroll, not a pull.
    if (dy <= 0 || scroller.scrollTop > 0) {
      pulling = false;
      if (dist > 0) { dist = 0; setPtr(0, false, false); }
      return;
    }
    dist = Math.min(dy * DAMP, MAX);
    setPtr(dist, dist >= TRIGGER, false);
    if (e.cancelable) e.preventDefault(); // we own this gesture now
  }, { passive: false });
  const release = () => {
    if (!pulling) return;
    pulling = false;
    const fire = dist >= TRIGGER;
    dist = 0;
    if (fire) manualRefresh(); else setPtr(0, false, false);
  };
  scroller.addEventListener("touchend", release);
  scroller.addEventListener("touchcancel", release);
}
enablePullToRefresh($("tab-chats"));
enablePullToRefresh($("tab-requests"));
$("refresh-btn").addEventListener("click", manualRefresh);

async function loadProfile() {
  const { ok, body } = await api("/api/profile");
  if (!ok) return;
  myName = body.display_name || "";
  $("display-name-text").textContent = myName || "(not set)";
  myAvatarHash = body.avatar_hash || "";
  renderMyAvatar();
  myMailbox = body.mailbox_url || "";
  const ms = $("mailbox-state");
  if (ms) ms.textContent = myMailbox ? myMailbox : "Not set — messages only arrive when you're online";
  myBackupBytes = body.group_image_backup_bytes || 0;
  myMediaAutoSave = !!body.media_auto_save;
  renderBackupState();
  syncMediaSaveSection();
}

// renderMyAvatar paints the settings avatar from my own hash (cache-busted so a
// just-changed picture updates immediately rather than showing the cached image
// at the old hash — the hash IS the version, so a new hash is a new URL anyway,
// but this also refreshes after a Remove+re-add to the same bytes).
//
// It also retargets the button, which does two different things: with no picture
// set it opens the file picker (badge: pencil, "Add"), and with one set it opens
// the picture fullscreen (badge: magnifier, "View"), where Edit and Remove live.
// Remove used to sit beside the avatar as its own button; it moved into the
// viewer so the picture itself is the only control on this row.
function renderMyAvatar() {
  const box = $("my-avatar");
  if (box) { box.innerHTML = ""; box.append(avatarNode(myAvatarHash, myName, null)); }
  const badge = $("avatar-badge-icon");
  if (badge) badge.setAttribute("href", myAvatarHash ? "#ic-zoom-in" : "#ic-edit");
  const btn = $("avatar-btn");
  if (btn) btn.setAttribute("aria-label", myAvatarHash ? "View profile picture" : "Add a profile picture");
}

// AVATAR_CAP_BYTES mirrors the backend's protocol.MaxAvatarBytes (64 KiB). The
// crop below almost always lands well under it; the loop drops quality if not.
const AVATAR_CAP_BYTES = 64 * 1024;

// encodeAvatar turns the cropped canvas into a small JPEG under the cap, backing
// quality off until it fits. All image work happens here in the client — the Go
// backend never decodes images (it's gomobile-portable), it only validates the
// type and size and stores the bytes.
async function encodeAvatar(canvas) {
  const toBlob = (q) => new Promise((res) => canvas.toBlob(res, "image/jpeg", q));
  let q = 0.85, blob = await toBlob(q);
  while (blob && blob.size > AVATAR_CAP_BYTES && q > 0.3) { q -= 0.15; blob = await toBlob(q); }
  if (!blob || blob.size > AVATAR_CAP_BYTES) throw new Error("That image is too large, even compressed.");
  return blob;
}

// ---- profile-picture crop editor -------------------------------------------
// The geometry model, kept deliberately small: `stage` is the side of the square
// preview, `baseScale` the scale at which the image exactly COVERS it, `zoom`
// (>= 1) multiplies that, and (tx, ty) is the image's top-left in stage
// coordinates. avatarCropApply clamps (tx, ty) to the covering range, so the
// crop can never contain blank space and the save path needs no edge cases.
//
// Every measurement and the final draw use the SAME <img> element, never a
// separate createImageBitmap: an EXIF-rotated photo would otherwise be measured
// upright and drawn sideways, and the crop would not be what the user framed.
const AVATAR_ZOOM_MAX = 4;
const avatarCrop = { stage: 0, natW: 0, natH: 0, baseScale: 1, zoom: 1, tx: 0, ty: 0 };
let avatarCropResolve = null;  // settles the promise openAvatarCropper returned
let avatarCropURL = null;      // object URL of the source file; revoked on close
const avatarCropPointers = new Map();
let avatarCropPinch = null;    // {dist, zoom, cx, cy} captured when the 2nd finger lands
let avatarCropDownAt = null;   // where the gesture started (tap vs pan)
let avatarCropMulti = false;   // was this gesture ever a pinch? (suppresses double-tap)
let avatarCropLastTap = 0;

function avatarCropApply() {
  const s = avatarCrop.baseScale * avatarCrop.zoom;
  const w = avatarCrop.natW * s, h = avatarCrop.natH * s;
  avatarCrop.tx = Math.min(0, Math.max(avatarCrop.stage - w, avatarCrop.tx));
  avatarCrop.ty = Math.min(0, Math.max(avatarCrop.stage - h, avatarCrop.ty));
  $("avatar-crop-img").style.transform =
    `translate(${avatarCrop.tx}px, ${avatarCrop.ty}px) scale(${s})`;
}
// avatarCropZoomTo zooms about a focal point in STAGE coordinates, holding that
// point still under the finger. Keeping the focal point fixed is the whole trick:
// zooming about the origin instead would slide the subject out of the circle.
function avatarCropZoomTo(zoom, fx, fy) {
  const next = Math.min(AVATAR_ZOOM_MAX, Math.max(1, zoom));
  const ratio = next / avatarCrop.zoom;
  avatarCrop.tx = fx - (fx - avatarCrop.tx) * ratio;
  avatarCrop.ty = fy - (fy - avatarCrop.ty) * ratio;
  avatarCrop.zoom = next;
  $("avatar-crop-zoom").value = String(next);
  avatarCropApply();
}
// avatarCropRemeasure re-reads the stage width after a relayout (rotation, a
// resized window) and rescales the transform to match. Without it `stage` keeps
// the width it had at open: avatarCropApply would clamp against stale bounds and
// — worse — avatarCropResult would compute `side` from the old width, so the
// SAVED crop would differ from the one the circle showed. Scaling tx/ty by the
// same factor as baseScale leaves both sx = -tx/s and side = stage/s unchanged,
// so the framing survives the resize exactly.
function avatarCropRemeasure() {
  const w = $("avatar-crop-stage").clientWidth;
  if ($("avatar-crop").hidden || !w || !avatarCrop.natW || w === avatarCrop.stage) return;
  const k = w / avatarCrop.stage;
  avatarCrop.tx *= k; avatarCrop.ty *= k;
  avatarCrop.stage = w;
  avatarCrop.baseScale = w / Math.min(avatarCrop.natW, avatarCrop.natH);
  avatarCropApply();
}
function avatarCropStagePoint(e) {
  const r = $("avatar-crop-stage").getBoundingClientRect();
  return { x: e.clientX - r.left, y: e.clientY - r.top };
}

// openAvatarCropper shows the editor for a picked file and resolves to the
// cropped JPEG Blob, or to null if the user cancelled. Callers treat null as
// "nothing to do" — not an error — so Cancel leaves the old picture alone.
function openAvatarCropper(file) {
  return new Promise((resolve) => {
    avatarCropResolve = resolve;
    const img = $("avatar-crop-img");
    const err = $("avatar-crop-error"); err.hidden = true;
    avatarCropPointers.clear(); avatarCropPinch = null;
    if (avatarCropURL) URL.revokeObjectURL(avatarCropURL);
    avatarCropURL = URL.createObjectURL(file);
    img.onerror = () => { closeAvatarCropper(null); showToast("Couldn't read that image."); };
    img.onload = () => {
      // The stage has no width until the modal is visible, which is why the
      // modal is unhidden BEFORE the src is assigned.
      avatarCrop.stage = $("avatar-crop-stage").clientWidth || 320;
      avatarCrop.natW = img.naturalWidth; avatarCrop.natH = img.naturalHeight;
      if (!avatarCrop.natW || !avatarCrop.natH) { closeAvatarCropper(null); showToast("Couldn't read that image."); return; }
      // Lay the image out at its natural size so scale() means what it says.
      img.style.width = avatarCrop.natW + "px";
      img.style.height = avatarCrop.natH + "px";
      avatarCrop.baseScale = avatarCrop.stage / Math.min(avatarCrop.natW, avatarCrop.natH);
      avatarCrop.zoom = 1;
      // Start centred — the same framing the old blind centre-crop produced, so
      // a user who just taps Save gets what they used to get.
      avatarCrop.tx = (avatarCrop.stage - avatarCrop.natW * avatarCrop.baseScale) / 2;
      avatarCrop.ty = (avatarCrop.stage - avatarCrop.natH * avatarCrop.baseScale) / 2;
      $("avatar-crop-zoom").value = "1";
      avatarCropApply();
    };
    $("avatar-crop").hidden = false;
    img.src = avatarCropURL;
    setTimeout(() => { try { $("avatar-crop-save").focus(); } catch (_) {} }, 0);
  });
}
function closeAvatarCropper(blob) {
  $("avatar-crop").hidden = true;
  const img = $("avatar-crop-img");
  img.onload = null; img.onerror = null;
  img.removeAttribute("src"); img.style.transform = "";
  if (avatarCropURL) { URL.revokeObjectURL(avatarCropURL); avatarCropURL = null; }
  avatarCropPointers.clear(); avatarCropPinch = null;
  avatarCropMulti = false; avatarCropDownAt = null; avatarCropLastTap = 0;
  const resolve = avatarCropResolve; avatarCropResolve = null;
  if (resolve) resolve(blob || null);
}
// avatarCropResult rasterises the circle's bounding square at save time. The
// source rect is the stage square mapped back through the live transform, so
// what the circle showed is exactly what gets stored.
async function avatarCropResult() {
  const s = avatarCrop.baseScale * avatarCrop.zoom;
  const side = avatarCrop.stage / s;                       // in source pixels
  const sx = -avatarCrop.tx / s, sy = -avatarCrop.ty / s;
  const dim = Math.max(1, Math.min(256, Math.round(side))); // never upscale
  const canvas = document.createElement("canvas");
  canvas.width = dim; canvas.height = dim;
  const ctx = canvas.getContext("2d");
  ctx.imageSmoothingQuality = "high";
  ctx.drawImage($("avatar-crop-img"), sx, sy, side, side, 0, 0, dim, dim);
  return encodeAvatar(canvas);
}

$("avatar-crop-cancel").addEventListener("click", () => closeAvatarCropper(null));
$("avatar-crop").addEventListener("click", (e) => { if (e.target.id === "avatar-crop") closeAvatarCropper(null); });
$("avatar-crop-save").addEventListener("click", async () => {
  const btn = $("avatar-crop-save"); btn.setAttribute("disabled", "");
  try {
    const blob = await avatarCropResult();
    closeAvatarCropper(blob);
  } catch (ex) {
    const err = $("avatar-crop-error");
    err.textContent = ex.message || "Couldn't use that image.";
    err.hidden = false;
  } finally { btn.removeAttribute("disabled"); }
});
$("avatar-crop-zoom").addEventListener("input", (e) => {
  const c = avatarCrop.stage / 2; // the slider has no finger to track: use the centre
  avatarCropZoomTo(parseFloat(e.target.value) || 1, c, c);
});
(() => {
  const stage = $("avatar-crop-stage");
  stage.addEventListener("pointerdown", (e) => {
    stage.setPointerCapture(e.pointerId);
    const at = avatarCropStagePoint(e);
    avatarCropPointers.set(e.pointerId, at);
    if (avatarCropPointers.size === 1) avatarCropDownAt = at;
    if (avatarCropPointers.size === 2) {
      avatarCropMulti = true;
      const [a, b] = [...avatarCropPointers.values()];
      avatarCropPinch = {
        dist: Math.hypot(a.x - b.x, a.y - b.y) || 1, zoom: avatarCrop.zoom,
        cx: (a.x + b.x) / 2, cy: (a.y + b.y) / 2,
      };
    }
  });
  stage.addEventListener("pointermove", (e) => {
    const prev = avatarCropPointers.get(e.pointerId);
    if (!prev) return;
    const now = avatarCropStagePoint(e);
    avatarCropPointers.set(e.pointerId, now);
    if (avatarCropPointers.size >= 2 && avatarCropPinch) {
      const [a, b] = [...avatarCropPointers.values()];
      const dist = Math.hypot(a.x - b.x, a.y - b.y) || 1;
      avatarCropZoomTo(avatarCropPinch.zoom * (dist / avatarCropPinch.dist), avatarCropPinch.cx, avatarCropPinch.cy);
      return;
    }
    avatarCrop.tx += now.x - prev.x;
    avatarCrop.ty += now.y - prev.y;
    avatarCropApply();
  });
  const release = (e) => {
    avatarCropPointers.delete(e.pointerId);
    if (avatarCropPointers.size < 2) avatarCropPinch = null;
    if (avatarCropPointers.size === 0) {
      // Double-tap to toggle zoom, hand-rolled the same way the image viewer
      // does it (ivLastTap) rather than via dblclick, which this WebView does
      // not fire reliably for touch. A gesture that was ever a pinch, or that
      // moved, is a pan — not a tap.
      const p = avatarCropStagePoint(e);
      const moved = avatarCropDownAt && Math.hypot(p.x - avatarCropDownAt.x, p.y - avatarCropDownAt.y) > 10;
      const now = Date.now();
      if (!avatarCropMulti && !moved && now - avatarCropLastTap < 300) {
        avatarCropZoomTo(avatarCrop.zoom > 1 ? 1 : 2, p.x, p.y);
        avatarCropLastTap = 0;
      } else if (!avatarCropMulti && !moved) {
        avatarCropLastTap = now;
      }
      avatarCropMulti = false;
    }
  };
  stage.addEventListener("pointerup", release);
  stage.addEventListener("pointercancel", release);
  if (window.ResizeObserver) new ResizeObserver(avatarCropRemeasure).observe(stage);
  stage.addEventListener("wheel", (e) => {
    e.preventDefault();
    const p = avatarCropStagePoint(e);
    avatarCropZoomTo(avatarCrop.zoom * (e.deltaY < 0 ? 1.12 : 1 / 1.12), p.x, p.y);
  }, { passive: false });
})();


// One MB in bytes, used to convert the byte budget the server stores to and from
// the MB the settings field shows.
const MB = 1024 * 1024;

function renderBackupState() {
  const el = $("gib-state");
  if (!el) return;
  if (myBackupBytes > 0) {
    el.textContent = "On — up to " + Math.round(myBackupBytes / MB) + " MB in your mailbox";
  } else {
    el.textContent = "Off";
  }
}
async function loadContacts() {
  const { ok, body } = await api("/api/contacts");
  if (!ok) return;
  contacts = body.contacts || [];
  announceAccepts();
  renderContacts();
}

// Contact statuses as of the previous load, so a flip can be spotted.
// A request the user sent sits at "pending_out" until the other side's accept
// reaches us, and that arrival is the only moment it is ever announced —
// nothing re-sends it later. Without this the row just quietly stops saying
// "Requested", which the user has no reason to be looking at.
let seenStatus = new Map();
function announceAccepts() {
  const fresh = [];
  const next = new Map();
  for (const c of contacts) {
    next.set(c.account, c.status);
    // pending_out → accepted is exactly "they said yes": either their accept
    // landed, or we each requested the other and it resolved as mutual.
    if (seenStatus.get(c.account) === "pending_out" && c.status === "accepted") fresh.push(c);
  }
  const firstLoad = seenStatus.size === 0;
  seenStatus = next;
  if (firstLoad) return; // the state we started with is not news
  for (const c of fresh) {
    const name = contactLabel(c);
    const open = () => { setTab("chats"); openChat(c.account); };
    showToast(name + " accepted your friend request", open);
    // Same guard order as maybeNotify: notifsOn is false where the Notification
    // API isn't there (the Android shell posts its own system notification for
    // this, from the backend's friend-accept hook).
    if (!notifsOn || Notification.permission !== "granted") continue;
    try {
      const n = new Notification(name, { body: "accepted your friend request", tag: "accept-" + c.account });
      n.onclick = () => { window.focus(); open(); };
    } catch (_) {}
  }
}

// showToast drops a Material-3-style snackbar over the bottom of the screen.
// One visible at a time (newest replaces with a crossfade); tapping it runs
// onTap (and dismisses); it disappears on its own either way. `action` renders
// a labeled M3 action button beside the text.
let toastCurrent = null;
function showToast(text, onTap, opts = {}) {
  if (toastCurrent) { toastCurrent.remove(); toastCurrent = null; }
  const el = document.createElement("div");
  el.className = "toast";
  el.setAttribute("role", "status");
  const label = document.createElement("span");
  label.textContent = text;
  el.append(label);
  if (opts.action) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "toast-action";
    btn.textContent = opts.action;
    btn.addEventListener("click", () => { el.remove(); toastCurrent = null; opts.onAction && opts.onAction(); });
    el.append(btn);
  }
  if (onTap) {
    el.classList.add("tappable");
    el.addEventListener("click", () => { el.remove(); toastCurrent = null; onTap(); });
  }
  document.body.append(el);
  toastCurrent = el;
  const life = opts.duration || 6000;
  setTimeout(() => {
    if (el !== toastCurrent) return;
    el.classList.add("leaving");
    setTimeout(() => { el.remove(); if (toastCurrent === el) toastCurrent = null; }, 250);
  }, life);
}
async function loadGroups() {
  const { ok, body } = await api("/api/groups");
  if (!ok) return;
  groups = body.groups || [];
  renderContacts();
  if (detailContent === "group-info") renderGroupInfo();
  if (detailContent === "contact-info") renderContactInfo();
}
async function loadGroupInvites() {
  const { ok, body } = await api("/api/groups/invites");
  if (!ok) return;
  groupInvites = body.invites || [];
  renderGroupInvites();
}
async function loadRequests() {
  const { ok, body } = await api("/api/friend-requests");
  if (!ok) return;
  requests = body.requests || [];
  renderRequests();
}
async function loadMessages() {
  const { ok, body } = await api("/api/messages");
  if (!ok) return;
  const prevSeen = notifSeenAt;
  messages = body.messages || [];
  pruneImageURLs();
  maybeNotify(prevSeen);
  if (detailContent === "chat") renderMessages();
  if (detailContent === "contact-info") renderContactInfo();
  // Fire-and-forget: copying a photo into the gallery must never delay the
  // chat render or block the poll loop behind a slow MediaStore write.
  autoSaveNewMedia();
}

// pruneImageURLs revokes and drops cached blob: URLs for images that are no
// longer in the message list — i.e. deleted (locally or by the sender). This
// matters in this app's threat model: it stops decrypted image bytes lingering
// in memory after the user (or the sender) deleted the photo.
function pruneImageURLs() {
  if (imageURLs.size === 0) return;
  // Keep every live blob key: a 1:1 image caches under the row id, a group image
  // under its thumb_id and (once downloaded) attach_id. Missing those here would
  // revoke and re-fetch group images on every poll.
  const ids = new Set();
  for (const m of messages) {
    ids.add(m.id);
    if (m.thumb_id) ids.add(m.thumb_id);
    if (m.attach_id) ids.add(m.attach_id);
  }
  for (const [id, url] of imageURLs) {
    if (!ids.has(id)) { URL.revokeObjectURL(url); imageURLs.delete(id); }
  }
}
// maybeNotify surfaces a desktop notification for inbound messages newer than
// the last one we've shown — but not for the chat that's currently open and
// focused (you're already reading it), and never on the very first load.
function maybeNotify(prevSeen) {
  let newest = prevSeen;
  const fresh = [];
  for (const m of messages) {
    if (m.direction !== "in") continue;
    const t = new Date(m.at).getTime();
    if (t > newest) newest = t;
    if (prevSeen > 0 && t > prevSeen) fresh.push(m);
  }
  notifSeenAt = Math.max(notifSeenAt, newest);
  if (prevSeen === 0 || fresh.length === 0) return;
  if (!notifsOn || Notification.permission !== "granted") return;
  for (const m of fresh) {
    if (m.group_id) {
      const openFocused = detailContent === "chat" && chatKind === "group" && m.group_id === currentGroup && document.visibilityState === "visible";
      if (openFocused) { markGroupReadNow(m.group_id); continue; } // reading it now — don't let a badge accrue
      try {
        const n = new Notification(groupName(m.group_id), { body: (m.author_name || "") + ": " + m.text, tag: m.group_id });
        n.onclick = () => { window.focus(); setTab("chats"); openGroup(m.group_id); };
      } catch (_) {}
      continue;
    }
    const chatOpenAndFocused = detailContent === "chat" && chatKind === "contact" && m.peer === currentPeer && document.visibilityState === "visible";
    if (chatOpenAndFocused) { markReadNow(m.peer); continue; } // reading it now — don't let a badge accrue
    try {
      const n = new Notification(contactName(m.peer), { body: m.kind === "image" ? "📷 Photo" : m.text, tag: m.peer });
      n.onclick = () => { window.focus(); setTab("chats"); openChat(m.peer); };
    } catch (_) {}
  }
}

function lastMsgAt(account) {
  const msgs = messages.filter((m) => m.peer === account);
  return msgs.length ? msgs[msgs.length - 1].at : null;
}
const PRESENCE_LABEL = {
  online: "Online",
  mailbox: "Offline · will deliver via mailbox",
  offline: "Offline",
  unknown: "Checking…",
};
function presenceDot(state) {
  const s = state || "unknown";
  const dot = document.createElement("span");
  dot.className = "presence-dot presence-" + s;
  dot.title = PRESENCE_LABEL[s] || "";
  dot.setAttribute("aria-label", dot.title);
  return dot;
}
function presenceFor(account) {
  const c = contacts.find((c) => c.account === account);
  return (c && c.presence) || "unknown";
}

// initialsOf derives a 1–2 letter monogram for the fallback avatar (no picture,
// or the bytes not cached yet). Falls back to "?" for an empty name.
function initialsOf(name) {
  const s = (name || "").trim();
  if (!s) return "?";
  const parts = s.split(/\s+/);
  const a = parts[0][0] || "";
  const b = parts.length > 1 ? (parts[parts.length - 1][0] || "") : "";
  return (a + b).toUpperCase();
}

// The local /api/avatar endpoint is auth-gated (Bearer session token), which a
// plain <img src> can't carry — so bytes are fetched with an authenticated
// request and handed to the <img> as an object URL. Content-addressed, so a hash
// maps to exactly one blob: a hit is cached permanently (for the tab's lifetime).
// A miss (bytes not on this device yet — the presence sweep may fetch them soon)
// is remembered only briefly so renders don't hammer 404s every poll, but DOES
// retry, so a contact's face appears once its bytes land. In-flight requests are
// deduped so many list rows sharing an avatar make one request.
const avatarURLCache = new Map();   // hash -> objectURL (permanent hits)
const avatarInflight = new Map();   // hash -> Promise (dedupe)
const avatarMissAt = new Map();     // hash -> ms timestamp of last miss
const AVATAR_RETRY_MS = 15000;
async function avatarObjectURL(hash) {
  if (!hash) return null;
  const hit = avatarURLCache.get(hash);
  if (hit) return hit;
  const inflight = avatarInflight.get(hash);
  if (inflight) return inflight;
  const missAt = avatarMissAt.get(hash);
  if (missAt && Date.now() - missAt < AVATAR_RETRY_MS) return null; // recently absent; back off
  const p = (async () => {
    try {
      const headers = {};
      if (controlToken) headers["X-Control-Token"] = controlToken;
      if (sessionToken) headers["Authorization"] = "Bearer " + sessionToken;
      const res = await fetch("/api/avatar?h=" + encodeURIComponent(hash), { headers });
      if (!res.ok) { avatarMissAt.set(hash, Date.now()); return null; }
      const url = URL.createObjectURL(await res.blob());
      avatarURLCache.set(hash, url);
      avatarMissAt.delete(hash);
      return url;
    } catch (_) { avatarMissAt.set(hash, Date.now()); return null; }
    finally { avatarInflight.delete(hash); }
  })();
  avatarInflight.set(hash, p);
  return p;
}

// avatarNode builds a circular avatar synchronously (initials monogram first, so
// the list paints instantly and never blocks on I/O), then swaps in the cached
// picture once its bytes resolve. It NEVER triggers a Tor dial — the bytes come
// only from this device's local cache (populated by the presence sweep and the
// add-time lookup). With presence set it overlays a small corner status dot.
function avatarNode(hash, name, presence) {
  const wrap = document.createElement("span");
  wrap.className = "avatar-wrap";
  const av = document.createElement("span");
  av.className = "avatar avatar-initials";
  av.textContent = initialsOf(name);
  if (hash) {
    avatarObjectURL(hash).then((url) => {
      if (!url || !wrap.isConnected) return; // absent bytes → keep initials
      const img = document.createElement("img");
      img.alt = "";
      img.src = url;
      av.textContent = "";
      av.classList.remove("avatar-initials");
      av.append(img);
    });
  }
  wrap.append(av);
  if (presence) {
    const dot = document.createElement("span");
    dot.className = "presence-corner presence-" + (presence || "unknown");
    dot.title = PRESENCE_LABEL[presence] || "";
    wrap.append(dot);
  }
  return wrap;
}
function updateChatPresence() {
  const el = $("detail-presence");
  if (!el) return;
  // Groups have no single presence; only 1:1 chats show a presence line.
  if (detailContent !== "chat" || chatKind !== "contact" || !currentPeer) { el.hidden = true; return; }
  const state = presenceFor(currentPeer);
  el.textContent = "";
  el.append(presenceDot(state), " " + (PRESENCE_LABEL[state] || ""));
  el.className = "detail-presence presence-text-" + state;
  el.hidden = false;
}
// Contacts arrive from the API in Go map order, which is randomised on every
// request — rendering that directly made the list reshuffle on each poll. Order
// deterministically here: most-recently-active chat first, then a stable account
// tiebreak so contacts with equal (or no) activity never swap places.
// orderedConversations merges 1:1 contacts and groups into one recency-sorted
// list. Each entry is {kind, key, at} so the render can branch. Map iteration
// order is randomised per poll, so the stable key tiebreak keeps equal-activity
// rows from swapping places.
function orderedConversations() {
  const items = [];
  for (const c of contacts) {
    if (c.status !== "accepted" && c.status !== "pending_out") continue;
    items.push({ kind: "contact", c, key: c.account, at: lastMsgAt(c.account) });
  }
  for (const g of groups) {
    items.push({ kind: "group", g, key: g.id, at: lastGroupMsgAt(g.id) });
  }
  items.sort((a, b) => {
    const na = a.at ? new Date(a.at).getTime() : 0;
    const nb = b.at ? new Date(b.at).getTime() : 0;
    if (na !== nb) return nb - na;
    return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
  });
  return items;
}

function renderGroupItem(g) {
  const item = document.createElement("md-list-item");
  item.setAttribute("type", "button");
  item.dataset.group = g.id;
  // Leading avatar goes in md-list-item's own `start` slot, not inside the
  // headline text. Inlined into the headline it pushed the name across while
  // the supporting text stayed at the left edge, so the two lines of a row
  // didn't share a text column — the M3 list item aligns them.
  const badge = document.createElement("span");
  badge.setAttribute("slot", "start");
  badge.className = "group-avatar";
  badge.innerHTML = '<svg class="icon"><use href="#ic-group"/></svg>';
  const head = document.createElement("div");
  head.setAttribute("slot", "headline");
  head.textContent = g.name || "Group";
  const sub = document.createElement("div");
  sub.setAttribute("slot", "supporting-text");
  sub.textContent = lastGroupPreview(g.id) || (g.member_count + (g.member_count === 1 ? " member" : " members"));
  item.append(badge, head, sub);
  const at = lastGroupMsgAt(g.id);
  const meta = document.createElement("div");
  meta.setAttribute("slot", "trailing-supporting-text");
  meta.className = "list-meta";
  if (at) { const t = document.createElement("span"); t.className = "list-time"; t.textContent = fmtTime(at); meta.append(t); }
  if (g.unread) { const b = document.createElement("span"); b.className = "badge unread-badge"; b.textContent = g.unread; meta.append(b); }
  item.append(meta);
  if (g.unread) item.classList.add("has-unread");
  return item;
}

function renderContacts() {
  const list = $("contacts-list");
  list.innerHTML = "";
  for (const conv of orderedConversations()) {
    if (conv.kind === "group") { list.append(renderGroupItem(conv.g)); continue; }
    const c = conv.c;
    const accepted = c.status === "accepted";
    const item = document.createElement("md-list-item");
    if (accepted) { item.setAttribute("type", "button"); item.dataset.account = c.account; }
    else item.classList.add("pending-contact");
    // Avatar leads the row (picture or initials), with the presence dot overlaid
    // on its corner for accepted contacts. Pending contacts show no presence.
    // It occupies md-list-item's `start` slot so the headline and the supporting
    // text below it share one text column (see renderGroupItem).
    const lead = avatarNode(c.avatar_hash, contactLabel(c), accepted ? c.presence : null);
    lead.setAttribute("slot", "start");
    const head = document.createElement("div");
    head.setAttribute("slot", "headline");
    head.textContent = contactLabel(c);
    const sub = document.createElement("div");
    sub.setAttribute("slot", "supporting-text");
    // awaiting_accept means we accepted them but the message telling them so
    // hasn't reached them yet — from their side we're still just "pending", and
    // they can't message us until it lands. Say so rather than looking done.
    if (accepted && c.awaiting_accept) sub.textContent = "Accepted · still trying to tell them — they can't reply yet";
    else sub.textContent = accepted ? (lastMsgPreview(c.account) || "No messages yet") : "Request sent · waiting for them to accept";
    item.append(lead, head, sub);

    if (accepted) {
      const at = lastMsgAt(c.account);
      const meta = document.createElement("div");
      meta.setAttribute("slot", "trailing-supporting-text");
      meta.className = "list-meta";
      if (at) { const t = document.createElement("span"); t.className = "list-time"; t.textContent = fmtTime(at); meta.append(t); }
      if (c.unread) { const b = document.createElement("span"); b.className = "badge unread-badge"; b.textContent = c.unread; meta.append(b); }
      item.append(meta);
      if (c.unread) item.classList.add("has-unread");
    } else if (c.status === "pending_out") {
      const cancel = document.createElement("md-text-button");
      cancel.setAttribute("slot", "end");
      cancel.textContent = "Cancel";
      cancel.dataset.cancel = c.account;
      item.append(cancel);
    }
    list.append(item);
  }
  const noContacts = orderedConversations().length === 0;
  $("no-contacts").hidden = !noContacts;
  // One "start something" affordance at a time: the empty state already offers
  // Add someone, so the FAB steps aside while it's visible.
  if (currentTab === "chats") $("fab-add").hidden = noContacts;
  if ($("empty-scan-btn")) $("empty-scan-btn").hidden = !scanSupported();
  const cb = $("chat-badge");
  if (cb) { const n = totalUnread(); cb.textContent = n; cb.hidden = n === 0; }
  updateChatPresence();
  renderRelayRequests();
}

// ---- search overlay: names-only filter over contacts + groups ----
// A trimmed contact row for the search results (avatar + name + preview),
// tappable via data-account like the main list.
function searchContactItem(c) {
  const item = document.createElement("md-list-item");
  item.setAttribute("type", "button");
  item.dataset.account = c.account;
  const name = contactLabel(c);
  const lead = avatarNode(c.avatar_hash, name, c.presence);
  lead.setAttribute("slot", "start");
  const head = document.createElement("div");
  head.setAttribute("slot", "headline");
  head.textContent = name;
  const sub = document.createElement("div");
  sub.setAttribute("slot", "supporting-text");
  sub.textContent = lastMsgPreview(c.account) || shortAccount(c.account);
  item.append(lead, head, sub);
  return item;
}
// Names-only match: a contact's display name OR account number; a group's name.
function convMatches(it, q) {
  if (it.kind === "group") return (it.g.name || "Group").toLowerCase().includes(q);
  const c = it.c;
  return contactLabel(c).toLowerCase().includes(q) || (c.name || "").toLowerCase().includes(q) ||
    c.account.toLowerCase().includes(q);
}
function renderSearchResults(raw) {
  const box = $("search-results");
  box.innerHTML = "";
  const q = (raw || "").trim().toLowerCase();
  // Only openable conversations: accepted contacts + groups (a pending contact
  // has no chat to open). Empty query lists everything so the view is browsable.
  const items = orderedConversations().filter((it) => it.kind === "group" || it.c.status === "accepted");
  const matches = q === "" ? items : items.filter((it) => convMatches(it, q));
  for (const it of matches) box.append(it.kind === "group" ? renderGroupItem(it.g) : searchContactItem(it.c));
  const empty = $("search-empty");
  const emptyText = $("search-empty-text");
  if (matches.length === 0) {
    emptyText.textContent = q === "" ? "No chats or contacts yet." : `No chats or contacts found for "${raw.trim()}".`;
    empty.hidden = false;
  } else empty.hidden = true;
  syncSearchClear();
}
function openSearch() {
  $("search-view").hidden = false;
  const i = $("search-input");
  i.value = "";
  renderSearchResults("");
  i.focus();
}
function closeSearch() { $("search-input").blur(); $("search-view").hidden = true; }
// The trailing clear affordance an M3 search view carries: present only while
// there is something to clear, and it returns focus to the field so the user
// can keep typing rather than being dropped out of the search.
function syncSearchClear() {
  $("search-clear").hidden = $("search-input").value === "";
}

function renderRequests() {
  // Browser notification for new friend requests (desktop only; Android uses JNI callbacks).
  if (requests.length > prevRequestCount && prevRequestCount > 0 && "Notification" in window && Notification.permission === "granted") {
    const newReq = requests[requests.length - 1];
    // contactLabel, not .name: someone you had already nicknamed can request you
    // again (after a remove), and the desktop notification must agree with the
    // row behind it. The Android twin of this is contactDisplayNameLocked().
    new Notification("Friend request", { body: contactLabel(newReq, "Someone") + " wants to connect with you" });
  }
  prevRequestCount = requests.length;
  const list = $("requests-list");
  list.innerHTML = "";
  for (const r of requests) {
    const row = document.createElement("div");
    row.className = "request-row";
    const info = document.createElement("div");
    const name = document.createElement("div"); name.className = "body"; name.textContent = contactLabel(r, "(no name)");
    const short = document.createElement("div"); short.className = "label muted"; short.textContent = shortAccount(r.account);
    info.append(name, short);
    const actions = document.createElement("div"); actions.className = "request-actions";
    const accept = document.createElement("md-filled-tonal-button"); accept.textContent = "Accept"; accept.dataset.accept = r.account;
    const decline = document.createElement("md-filled-tonal-button"); decline.textContent = "Decline"; decline.dataset.decline = r.account; decline.classList.add("danger-tonal");
    actions.append(accept, decline);
    row.append(info, actions);
    list.append(row);
  }
  updateRequestsBadge();
}

// renderRelayRequests shows contacts who've asked to use us as a relay, each with
// the plain-language disclosure of what approving entails.
function renderRelayRequests() {
  const pending = contacts.filter((c) => c.relay_pending);
  const list = $("relay-requests-list");
  list.innerHTML = "";
  for (const c of pending) {
    const row = document.createElement("div");
    row.className = "request-row relay-req-row";
    const info = document.createElement("div");
    const name = document.createElement("div"); name.className = "body"; name.textContent = contactLabel(c);
    const disc = document.createElement("div"); disc.className = "label muted";
    disc.textContent = "Wants to use you as a relay. Your device will occasionally connect to people you don't know to pass along their messages — you can't read them. Revoke anytime.";
    info.append(name, disc);
    const actions = document.createElement("div"); actions.className = "request-actions";
    const approve = document.createElement("md-text-button"); approve.textContent = "Approve"; approve.dataset.relayApprove = c.account;
    const decline = document.createElement("md-text-button"); decline.textContent = "Decline"; decline.dataset.relayDecline = c.account;
    actions.append(approve, decline);
    row.append(info, actions);
    list.append(row);
  }
  $("relay-requests-section").hidden = pending.length === 0;
  updateRequestsBadge();
}

function relayPendingCount() { return contacts.filter((c) => c.relay_pending).length; }
function updateRequestsBadge() {
  const total = requests.length + relayPendingCount() + groupInvites.length;
  $("no-requests").hidden = total > 0;
  const badge = $("req-badge");
  badge.textContent = total;
  badge.hidden = total === 0;
}

// Mirrors the backend's deleteWindow. The server is the authority; this only
// decides whether to offer the button.
const DELETE_WINDOW_MS = 60 * 60 * 1000;
const withinDeleteWindow = (at) => Date.now() - new Date(at).getTime() < DELETE_WINDOW_MS;

// atBottom reports whether the scroll box is at (or within 40px of) its bottom,
// i.e. the reader is looking at the newest messages. Used to decide whether a
// re-render should stick to the bottom or leave the scroll position alone.
function atBottom(box) {
  return box.scrollHeight - box.scrollTop - box.clientHeight < 40;
}
// stickBottom tracks whether the chat view is pinned to the newest message.
// It's the single source of truth item 1 hangs off: the scroll listener updates
// it, late-loading images re-pin while it's true, and the floating jump button
// shows while it's false. msgRenderLock silences the scroll events our own
// innerHTML rebuild fires (which reset scrollTop to 0 mid-render).
let stickBottom = true;
let msgRenderLock = false;
function scrollMessagesToBottom() {
  const box = $("messages");
  box.scrollTop = box.scrollHeight;
}
function updateScrollBtn() {
  const btn = $("scroll-bottom-btn");
  if (btn) btn.hidden = !(detailContent === "chat" && !stickBottom);
}
// ---- message runs ----
// Consecutive messages from the same sender, close enough together in time, are
// drawn as one run: only the LAST bubble carries the timestamp and the delivery
// status, and only it keeps the tail corner. Everything above it is just the
// bubble, tucked up against its neighbour.
//
// A failed message never joins a run, in either direction. It owns an error line
// and a "Tap to retry" button, and those have to stay attached to the message
// they act on — collapsing them into a neighbour's footer would hide a failure
// or put the retry on the wrong message.
const MSG_RUN_WINDOW_MS = 5 * 60 * 1000;
function msgStatusKey(m) {
  if (!m || m.direction !== "out") return "in";
  if (m.delivery === "failed") return "failed";
  if (m.delivery === "pending" || m.delivery === "queued") return "pending";
  return "delivered"; // the flag is cleared on ack, so "no flag" means delivered
}
function sameMsgRun(prev, m) {
  if (!prev || !m) return false;
  if (prev.direction !== m.direction) return false;
  if ((prev.author || "") !== (m.author || "")) return false;
  if (prev.delivery === "failed" || m.delivery === "failed") return false;
  const dt = new Date(m.at) - new Date(prev.at);
  return Number.isFinite(dt) && dt >= 0 && dt <= MSG_RUN_WINDOW_MS;
}
// Whether this message shows its own delivery status. Normally only the last of
// a run does, but a message whose state DIFFERS from the next one's keeps its
// own — otherwise one still-sending message hides behind a later delivered one.
function showsOwnStatus(m, next, runWithNext) {
  return !runWithNext || msgStatusKey(m) !== msgStatusKey(next);
}

function renderMessages(forceBottom = false) {
  if (chatKind === "group") { renderGroupMessages(forceBottom); return; }
  const box = $("messages");
  // Preserve the reader's position on background refreshes: only jump to the
  // newest message when opening the chat (forceBottom) or when they're already
  // at the bottom. Otherwise the 2.5s poll's re-render would yank them back down
  // mid-scroll while they read history.
  const stick = forceBottom || atBottom(box);
  msgRenderLock = true;
  const convo = messages.filter((m) => m.peer === currentPeer && !m.group_id);
  box.innerHTML = "";
  if (convo.length === 0) {
    box.append(emptyState("ic-chat", "No messages yet", "Say hello — you both need to be online."));
  }
  for (let i = 0; i < convo.length; i++) {
    const m = convo[i];
    const next = convo[i + 1];
    const runWithPrev = sameMsgRun(convo[i - 1], m);
    const runWithNext = sameMsgRun(m, next);
    const row = document.createElement("div");
    row.className = "bubble-row " + (m.direction === "out" ? "out" : "in") + (runWithPrev ? " grouped" : "");
    row.dataset.msgId = m.id;
    const b = document.createElement("div");
    b.className = "bubble " + (m.direction === "out" ? "out" : "in") +
      (m.delivery === "failed" ? " failed" : "") + (runWithNext ? "" : " tail");
    if (m.reply_to) b.append(quoteElement(m.reply_to));
    if (m.kind === "image") { b.classList.add("image"); b.append(imageElement(m.id, m.delivery)); }
    else b.append(textNode(m.text));
    row.append(b);
    // The run's footer sits under its last bubble only.
    if (!runWithNext) {
      const t = document.createElement("div");
      t.className = "bubble-time";
      t.textContent = fmtTime(m.at);
      row.append(t);
    }
    const rx = reactionsElement(m);
    if (rx) row.append(rx);

    // Delivery state is the backend's, read straight off the message. The
    // protocol only stores "pending" / "failed"; the flag is CLEARED on ack, so
    // an outgoing message with no flag is a delivered one. Success is an
    // EXPLICIT terminal state (check + "Delivered"), not the absence of
    // "Sending…" — the old behaviour made arrival indistinguishable from a
    // status that never existed.
    if (m.direction === "out" && showsOwnStatus(m, next, runWithNext)) {
      if (m.delivery === "failed") {
        const status = document.createElement("div");
        status.className = "msg-status error";
        status.textContent = m.error || "couldn't send";
        row.append(status);
        const retry = document.createElement("button");
        retry.type = "button";
        retry.className = "msg-retry";
        retry.dataset.retry = m.id;
        retry.innerHTML = '<svg class="icon" aria-hidden="true"><use href="#ic-refresh"/></svg>Tap to retry';
        row.append(retry);
        if (m.relay_available) {
          const relay = document.createElement("button");
          relay.className = "relay-offer";
          relay.textContent = "Still trying — send via a friend's relay?";
          relay.dataset.relaySend = m.id;
          row.append(relay);
        }
      } else if (m.delivery === "pending" || m.delivery === "queued") {
        const status = document.createElement("div");
        status.className = "msg-status";
        status.textContent = "Sending…";
        row.append(status);
      } else {
        // delivered / read / any other terminal success value
        const status = document.createElement("div");
        status.className = "msg-status delivered";
        const tick = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        tick.setAttribute("class", "icon");
        tick.setAttribute("aria-hidden", "true");
        const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
        use.setAttribute("href", "#ic-check");
        tick.append(use);
        status.append(tick, document.createTextNode("Delivered"));
        row.append(status);
      }
    }

    // "Delete for everyone" now lives in the long-press / right-click message
    // menu (item 3), gated to our own in-window messages there.
    box.append(row);
  }
  if (mailboxNote && mailboxNote.peer === currentPeer) {
    const note = document.createElement("div");
    note.className = "mailbox-note label muted";
    note.textContent = "📮 Delivered to their mailbox — they'll get it when they next come online.";
    box.append(note);
  }
  // Re-apply selection highlight after DOM re-render (the old node is gone, so
  // re-bind selectedBubbleRow). If the popover is open, re-anchor the spotlight
  // to the fresh node so it doesn't point at a detached element.
  if (selectedMsgId) {
    const sel = document.querySelector(`[data-msg-id="${selectedMsgId}"]`);
    if (sel) {
      sel.classList.add("selected");
      selectedBubbleRow = sel;
    }
  }
  // Same for multi-select mode: the Set survives a re-render but the DOM classes
  // don't, so re-apply .selected to every still-selected row.
  if (selectedMsgIds.size) {
    for (const id of selectedMsgIds) {
      const r = document.querySelector(`[data-msg-id="${id}"]`);
      if (r) r.classList.add("selected");
    }
    // Re-apply .selecting to ALL rows and ensure checkboxes exist
    document.querySelectorAll(".bubble-row").forEach((r) => {
      if (!r.dataset.msgId) return;
      r.classList.add("selecting");
      if (!r.querySelector(".select-check")) {
        const check = document.createElement("span");
        check.className = "select-check";
        r.appendChild(check);
      }
    });
  }
  settleMessagesScroll(stick);
}

// settleMessagesScroll finishes a message re-render: after the browser lays the
// new content out (rAF), it pins to the bottom when we should stick, then lifts
// the render lock so the scroll listener tracks the user again. Images that load
// later re-pin themselves via the capture-phase load listener while stickBottom
// stays true (see wiring near the navigation events).
function settleMessagesScroll(stick) {
  stickBottom = stick;
  requestAnimationFrame(() => {
    if (stickBottom) scrollMessagesToBottom();
    msgRenderLock = false;
    updateScrollBtn();
  });
}

// renderGroupMessages renders the open group's conversation. Inbound bubbles are
// labelled with the author's name (a group can have many senders); consecutive
// messages from the same author don't repeat the label.
function renderGroupMessages(forceBottom = false) {
  const box = $("messages");
  const stick = forceBottom || atBottom(box);
  msgRenderLock = true;
  const convo = messages.filter((m) => m.group_id === currentGroup);
  box.innerHTML = "";
  if (convo.length === 0) {
    box.append(emptyState("ic-group", "No messages yet", "Say hello to the group."));
  }
  for (let i = 0; i < convo.length; i++) {
    const m = convo[i];
    const next = convo[i + 1];
    const out = m.direction === "out";
    const runWithPrev = sameMsgRun(convo[i - 1], m);
    const runWithNext = sameMsgRun(m, next);
    const row = document.createElement("div");
    row.className = "bubble-row " + (out ? "out" : "in") + (runWithPrev ? " grouped" : "");
    row.dataset.msgId = m.id;
    // The author label heads each run, same boundary the footer closes.
    if (!out && !runWithPrev) {
      const who = document.createElement("div");
      who.className = "bubble-author label muted";
      who.textContent = m.author_name || shortAccount(m.author || "");
      row.append(who);
    }
    const b = document.createElement("div");
    b.className = "bubble " + (out ? "out" : "in") +
      (m.delivery === "failed" ? " failed" : "") + (runWithNext ? "" : " tail");
    if (m.reply_to) b.append(quoteElement(m.reply_to));
    if (m.kind === "image") { b.classList.add("image"); b.append(groupImageElement(m)); }
    else b.append(textNode(m.text));
    row.append(b);
    if (!runWithNext) {
      const t = document.createElement("div");
      t.className = "bubble-time";
      t.textContent = fmtTime(m.at);
      row.append(t);
    }
    const rx = reactionsElement(m);
    if (rx) row.append(rx);
    // Same delivery language as 1:1 chats — groups used to show nothing at all.
    if (out && showsOwnStatus(m, next, runWithNext)) {
      if (m.delivery === "failed") {
        const status = document.createElement("div");
        status.className = "msg-status error";
        status.textContent = m.error || "couldn't send";
        row.append(status);
        const retry = document.createElement("button");
        retry.type = "button";
        retry.className = "msg-retry";
        retry.dataset.retry = m.id;
        retry.innerHTML = '<svg class="icon" aria-hidden="true"><use href="#ic-refresh"/></svg>Tap to retry';
        row.append(retry);
      } else if (m.delivery === "pending") {
        const status = document.createElement("div");
        status.className = "msg-status";
        status.textContent = "Sending…";
        row.append(status);
      } else {
        const status = document.createElement("div");
        status.className = "msg-status delivered";
        const tick = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        tick.setAttribute("class", "icon");
        tick.setAttribute("aria-hidden", "true");
        const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
        use.setAttribute("href", "#ic-check");
        tick.append(use);
        status.append(tick, document.createTextNode("Delivered"));
        row.append(status);
      }
    }
    box.append(row);
  }
  settleMessagesScroll(stick);
}

// ---------- events: chat scroll (item 1) ----------
// These bind once to the persistent #messages box (renders only replace its
// children), so they survive every re-render.
$("messages").addEventListener("scroll", () => {
  if (msgRenderLock) return; // our own rebuild reset scrollTop; not the user
  stickBottom = atBottom($("messages"));
  updateScrollBtn();
});
// img load/error don't bubble, so listen in the capture phase: a late-arriving
// image grows the box, and if we're still pinned to the bottom we follow it down.
function onChatImageSettled(e) {
  if (e.target && e.target.tagName === "IMG" && stickBottom) scrollMessagesToBottom();
}
$("messages").addEventListener("load", onChatImageSettled, true);
$("messages").addEventListener("error", onChatImageSettled, true);
$("scroll-bottom-btn").addEventListener("click", () => {
  stickBottom = true;
  scrollMessagesToBottom();
  updateScrollBtn();
});

// ---------- diagnostics bottom sheet (tor status pill + You-tab entry) ----------

// buildDiagSnapshot assembles the plain-text status header a tester can read
// back. Everything here is either build metadata or the user's own public
// account/connection state — no message content, no contact list.
function buildDiagSnapshot(ver, id) {
  const v = ver || {};
  const gitShort = (v.git_commit || "").slice(0, 10);
  const frac = typeof id.tor_bootstrap_frac === "number" ? Math.round(id.tor_bootstrap_frac * 100) : 0;
  const acct = id.account_number || "";
  const acctShort = acct ? acct.slice(0, 12) + "…" : "—";
  let reach;
  if (!id.tor_enabled) reach = "Tor disabled";
  else if (id.tor_ready) reach = "online — reachable";
  else if (id.tor_sendable) reach = "publishing — can send, address not yet published" + publishElapsedSuffix();
  else if (torConnectingSince > 0 && Date.now() - torConnectingSince > TOR_STALLED_MS) reach = "stalled — check your internet";
  else reach = "connecting";
  return [
    "Molepipe diagnostics",
    "Generated: " + new Date().toISOString(),
    "",
    "App:      " + (v.version || "?") + (gitShort ? " (" + gitShort + ")" : ""),
    "Runtime:  " + (v.go_version || "?") + " " + (v.os || "?") + "/" + (v.arch || "?"),
    "Device:   " + (deviceRoleText || "unknown"),
    "Account:  " + acctShort,
    // tor_service_state is arti's own word for what the service is doing, and is
    // the line that distinguishes a first publish still in flight from one that
    // is retrying after failed uploads. Absent on the desktop sidecar, which
    // scrapes a log and cannot ask.
    "Onion:    " + (id.tor_hs_state || "unknown") + (id.tor_service_state ? " · service " + id.tor_service_state : "") + " · bootstrap " + frac + "% · sendable=" + !!id.tor_sendable + " · reachable=" + !!id.tor_ready,
    "Reach:    " + reach,
  ].join("\n");
}

let diagPollTimer = null;

// The pill is both a status indicator and the fastest route into Diagnostics
// (You › Preferences › Help still has the labeled entry). Restored after the
// polish pass made it passive — users reach for it as "the log button".
$("tor-pill").addEventListener("click", openDiagnostics);
async function openDiagnostics() {
  const dialog = $("tor-log-dialog");
  const snap = $("diag-snapshot");
  const content = $("tor-log-content");
  snap.textContent = "Loading\u2026";
  content.textContent = "Loading\u2026";
  dialog.showModal();
  // Cache the immutable build info once; fetch live connection state each open.
  if (!appVersionInfo) {
    const v = await api("/api/version");
    if (v.ok && v.body) appVersionInfo = v.body;
  }
  const idres = await api("/api/identity");
  const id = (idres.ok && idres.body) ? idres.body : {};
  const logres = await api("/api/tor-log");
  const lines = (logres.ok && logres.body && logres.body.lines) ? logres.body.lines : null;
  snap.textContent = buildDiagSnapshot(appVersionInfo, id);
  content.textContent = lines ? (lines.join("\n") || "(no log lines yet)") : "(failed to load log)";
  content.scrollTop = content.scrollHeight;
  // Poll log every 3 seconds while the dialog is open
  clearInterval(diagPollTimer);
  diagPollTimer = setInterval(async () => {
    if (dialog.closed) { clearInterval(diagPollTimer); return; }
    const r = await api("/api/tor-log");
    if (r.ok && r.body && r.body.lines) {
      content.textContent = r.body.lines.join("\n") || "(no log lines yet)";
      content.scrollTop = content.scrollHeight;
    }
  }, 3000);
}

$("open-diagnostics-btn").addEventListener("click", openDiagnostics);

// Outbound links (Donate / Report a bug). TODO: swap these placeholders for the
// real destinations once the site is live.
const DONATE_URL = "https://molepipe.org/#donate";
const REPORT_BUG_URL = "https://google.com";

// Open an external URL outside the in-app view — a bare navigation would
// replace the whole UI with no way back. Three shells, tried in order of
// reliability:
//   Android  — the AndroidShell bridge fires a system-browser intent.
//   Desktop  — the UI is loaded over a loopback URL and has no Wails runtime of
//              its own, so we ask the backend (POST /api/open-external) to run
//              the platform opener. Registered only when a desktop shell exists.
//   Browser  — cmd/server in a real browser: the endpoint reports itself
//              unavailable, so we fall back to window.open.
async function openExternal(url) {
  try { if (window.AndroidShell?.openUrl) { window.AndroidShell.openUrl(url); return; } } catch (_) {}
  try {
    const res = await api("/api/open-external", { method: "POST", body: JSON.stringify({ url }) });
    if (res.ok) return;
  } catch (_) {}
  window.open(url, "_blank", "noopener");
}
$("donate-btn").addEventListener("click", () => openExternal(DONATE_URL));
$("wiz-donate-btn").addEventListener("click", () => openExternal(DONATE_URL));
$("report-bug-btn").addEventListener("click", () => openExternal(REPORT_BUG_URL));

// ---------- view recovery phrase (You › Security) ----------
// Re-show the 24-word phrase on demand — the promise the onboarding wizard makes
// that it is never lost. The reveal endpoint demands the full password (never
// the session token alone), so we prompt for it every time: an unlocked app
// left unattended must not surrender the account. The revealed phrase lives only
// in this closure and is wiped from memory and the DOM when the modal closes.
let revealedPhrase = null;
function openViewPhrase() {
  revealedPhrase = null;
  $("view-phrase-password").value = "";
  $("view-phrase-error").hidden = true;
  $("view-phrase-pw-step").hidden = false;
  $("view-phrase-show-step").hidden = true;
  $("view-phrase-text").textContent = "";
  $("view-phrase-modal").hidden = false;
  setTimeout(() => { try { $("view-phrase-password").focus(); } catch (_) {} }, 0);
}
function closeViewPhrase() {
  revealedPhrase = null;
  $("view-phrase-password").value = "";
  $("view-phrase-text").textContent = "";
  $("view-phrase-modal").hidden = true;
}
$("view-phrase-btn").addEventListener("click", openViewPhrase);
$("view-phrase-cancel").addEventListener("click", closeViewPhrase);
$("view-phrase-done").addEventListener("click", closeViewPhrase);
$("view-phrase-modal").addEventListener("click", (e) => { if (e.target === $("view-phrase-modal")) closeViewPhrase(); });
$("view-phrase-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("view-phrase-error"); err.hidden = true;
  const password = $("view-phrase-password").value;
  if (!password) { err.textContent = "Enter your password."; err.hidden = false; return; }
  const { ok, status, body } = await api("/api/security", {
    method: "POST", body: JSON.stringify({ action: "phrase-reveal", password }),
  });
  if (!ok) {
    err.textContent = status === 401 ? "That password is incorrect." : (body.error || "Could not show the phrase.");
    err.hidden = false; return;
  }
  revealedPhrase = body.recovery_phrase || "";
  $("view-phrase-password").value = "";
  const grid = $("view-phrase-text");
  grid.innerHTML = "";
  for (const w of revealedPhrase.trim().split(/\s+/)) {
    if (!w) continue;
    const li = document.createElement("li"); li.className = "phrase-word"; li.textContent = w; grid.append(li);
  }
  $("view-phrase-pw-step").hidden = true;
  $("view-phrase-show-step").hidden = false;
});
$("view-phrase-copy").addEventListener("click", async () => {
  if (!revealedPhrase) return;
  const text = revealedPhrase.trim().split(/\s+/).join(" ");
  try { await navigator.clipboard.writeText(text); } catch (_) {
    const ta = document.createElement("textarea"); ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select(); document.execCommand("copy"); document.body.removeChild(ta);
  }
  showToast("Recovery phrase copied");
});
$("view-phrase-download").addEventListener("click", () => {
  if (!revealedPhrase) return;
  const lines = revealedPhrase.trim().split(/\s+/).map((w, i) => `${i + 1}. ${w}`).join("\n");
  const blob = new Blob([lines, "\n"], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = "recovery-phrase.txt"; a.style.display = "none";
  document.body.appendChild(a); a.click();
  setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 1000);
});
$("diag-copy").addEventListener("click", async () => {
  const text = $("diag-snapshot").textContent + "\n\n── Tor log ──────────────\n" + $("tor-log-content").textContent;
  try { await navigator.clipboard.writeText(text); } catch (_) {}
  showToast("Diagnostics copied");
});
$("tor-log-close").addEventListener("click", () => { clearInterval(diagPollTimer); $("tor-log-dialog").close(); });
$("tor-log-dialog").addEventListener("click", (e) => {
  if (e.target === $("tor-log-dialog")) { clearInterval(diagPollTimer); $("tor-log-dialog").close(); }
});

// ---------- events: navigation ----------
document.querySelectorAll(".navitem").forEach((n) => n.addEventListener("click", () => setTab(n.dataset.tab)));
$("fab-add").addEventListener("click", openAdd);
$("empty-add-btn").addEventListener("click", openAdd);
$("empty-scan-btn").addEventListener("click", openScan);
$("empty-group-btn").addEventListener("click", () => { openAdd(); setAddMode("group"); });
// (Paste lives on the Add screen itself, so the empty state no longer needs a
// fourth duplicate CTA.)
// Requests empty state: same two paths as elsewhere, no new surfaces. "Add
// someone" opens the add sheet (which itself reveals the scan button only when a
// camera is present, so there's no dead scan control); "Share my code" jumps to
// the You tab where the account number + QR already live.
$("requests-add-btn").addEventListener("click", openAdd);
// "Share my code" is a deep-link to the account number/QR, so force the Profile
// sub-tab regardless of where the user last left the You tab.
$("requests-share-btn").addEventListener("click", () => { setTab("you"); showYouPane("profile"); });

// Shared empty-state block: organic-blob icon + title + optional subtitle. Text
// args are static literals from call sites, so innerHTML here is not user-fed.
function emptyState(icon, title, sub) {
  const wrap = document.createElement("div");
  wrap.className = "empty-state";
  wrap.innerHTML =
    `<div class="empty-art"><svg class="empty-icon"><use href="#${icon}"/></svg></div>` +
    `<p class="empty-title"></p>` +
    (sub ? `<p class="empty-sub body muted"></p>` : "");
  wrap.querySelector(".empty-title").textContent = title;
  if (sub) wrap.querySelector(".empty-sub").textContent = sub;
  return wrap;
}
$("back-btn").addEventListener("click", backAction);
$("contacts-list").addEventListener("click", async (e) => {
  const cancel = e.target.closest("[data-cancel]");
  if (cancel) {
    e.stopPropagation();
    cancel.setAttribute("disabled", "");
    await api("/api/contacts/delete", { method: "POST", body: JSON.stringify({ account: cancel.dataset.cancel }) });
    await loadContacts();
    return;
  }
  const item = e.target.closest("md-list-item");
  if (item && item.dataset.group) { openGroup(item.dataset.group); return; }
  if (item && item.dataset.account) openChat(item.dataset.account);
});

// Search overlay wiring.
$("search-btn").addEventListener("click", openSearch);
$("search-clear").addEventListener("click", () => {
  const i = $("search-input");
  i.value = "";
  renderSearchResults("");
  syncSearchClear();
  i.focus();
});
$("search-close").addEventListener("click", closeSearch);
$("search-input").addEventListener("input", (e) => renderSearchResults(e.target.value));
$("search-input").addEventListener("keydown", (e) => { if (e.key === "Escape") closeSearch(); });
$("search-results").addEventListener("click", (e) => {
  const item = e.target.closest("md-list-item");
  if (!item) return;
  closeSearch();
  if (item.dataset.group) openGroup(item.dataset.group);
  else if (item.dataset.account) openChat(item.dataset.account);
});

// Chat overflow menu: view number / block / delete.
$("chat-menu-btn").addEventListener("click", (e) => {
  e.stopPropagation();
  if (chatKind === "group") { const gm = $("group-menu"); gm.hidden = !gm.hidden; return; }
  const m = $("chat-menu"); m.hidden = !m.hidden;
  if (!m.hidden) {
    const c = contacts.find((c) => c.account === currentPeer) || {};
    const relay = $("chat-menu-relay");
    if (c.relay_holder) { relay.textContent = "Relaying through them ✓"; relay.setAttribute("disabled", ""); }
    else { relay.textContent = "Ask to relay for me"; relay.removeAttribute("disabled"); }
  }
});
document.addEventListener("click", (e) => {
  if (!$("chat-menu").hidden && !e.target.closest("#chat-menu") && !e.target.closest("#chat-menu-btn")) $("chat-menu").hidden = true;
  if (!$("group-menu").hidden && !e.target.closest("#group-menu") && !e.target.closest("#chat-menu-btn")) $("group-menu").hidden = true;
});
$("group-menu").addEventListener("click", async (e) => {
  const btn = e.target.closest("button"); if (!btn) return;
  $("group-menu").hidden = true;
  if (btn.dataset.action === "ginfo") { openGroupInfo(); return; }
  if (btn.dataset.action === "gleave") {
    const ok0 = await confirmDialog({
      title: "Leave this group?",
      message: "You'll stop receiving its messages and won't be able to rejoin unless someone invites you again.",
      confirmLabel: "Leave group",
      danger: true,
    });
    if (!ok0) return;
    const { ok, body } = await api("/api/groups/leave", { method: "POST", body: JSON.stringify({ group: currentGroup }) });
    if (!ok) { $("send-error").textContent = body.error || "Could not leave the group."; $("send-error").hidden = false; return; }
    currentGroup = null; chatKind = null;
    setTab("chats");
    await loadGroups();
  }
});
$("chat-menu").addEventListener("click", async (e) => {
  const btn = e.target.closest("button"); if (!btn) return;
  $("chat-menu").hidden = true;
  if (btn.dataset.action === "cinfo") { openContactInfo(); return; }
  const acct = currentPeer;
  if (btn.dataset.action === "relay") {
    btn.setAttribute("disabled", "");
    const { ok, body } = await api("/api/relay/request", { method: "POST", body: JSON.stringify({ account: acct }) });
    btn.removeAttribute("disabled");
    $("send-error").textContent = ok ? "Relay request sent to " + contactName(acct) + "." : (body.error || "Could not send relay request.");
    $("send-error").hidden = false;
    return;
  }
  const blocking = btn.dataset.action === "block";
  const name = contactName(acct);
  const ok0 = await confirmDialog({
    title: blocking ? "Block " + name + "?" : "Remove " + name + "?",
    message: blocking
      ? "They'll be removed from your contacts and can't message you or send a new request. You can unblock later by adding them again."
      : "They'll be removed from your contacts and this conversation is deleted from this device. They can send a new request to reconnect.",
    confirmLabel: blocking ? "Block" : "Remove",
    danger: true,
  });
  if (!ok0) return;
  const path = blocking ? "/api/contacts/block" : "/api/contacts/delete";
  await api(path, { method: "POST", body: JSON.stringify({ account: acct }) });
  currentPeer = null;
  setTab("chats");
  await loadContacts();
});
// Approve / decline relay requests.
$("relay-requests-list").addEventListener("click", async (e) => {
  const ap = e.target.closest("[data-relay-approve]"), dc = e.target.closest("[data-relay-decline]");
  if (ap) { ap.setAttribute("disabled", ""); await api("/api/relay/approve", { method: "POST", body: JSON.stringify({ account: ap.dataset.relayApprove }) }); }
  else if (dc) { await api("/api/relay/decline", { method: "POST", body: JSON.stringify({ account: dc.dataset.relayDecline }) }); }
  else return;
  await loadContacts();
});

// ---------- events: auth ----------
async function doUnlock(password) {
  const { ok, body } = await api("/api/unlock", { method: "POST", body: JSON.stringify({ password }) });
  if (!ok) {
    // The backend reports how close a wrong password is to the erase threshold
    // (when that policy is on) and any backoff window; surface it verbatim.
    if (body.wiped) return { ok: false, wiped: true, error: body.error || "This device has been erased." };
    let msg = body.error || "Unlock failed.";
    if (typeof body.attempts_left === "number")
      msg += " " + body.attempts_left + " attempt" + (body.attempts_left === 1 ? "" : "s") + " left before this device is erased.";
    else if (body.retry_after) msg += " Try again in " + body.retry_after + "s.";
    return { ok: false, error: msg };
  }
  setSessionToken(body.session_token);
  await showUnlocked();
  return { ok: true };
}
$("unlock-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("unlock-error"); err.hidden = true;
  const password = $("password").value; $("password").value = "";
  const res = await doUnlock(password);
  if (res.wiped) {
    // The failed-attempts policy just erased the account. Drop the session and
    // return to onboarding, leaving the message up long enough to be read.
    resetSessionState();
    pinEnabled = false;
    err.textContent = res.error; err.hidden = false;
    setTimeout(refresh, 5000);
    return;
  }
  if (!res.ok) { err.textContent = res.error; err.hidden = false; }
});

$("pin-keypad-grid")?.addEventListener("click", (e) => {
  const btn = e.target.closest("button");
  if (!btn) return;
  haptic(8); // Android PIN pads tick per key; the helper is a no-op elsewhere.
  if (btn.dataset.num !== undefined) {
    // PINs are 6+ digits with no fixed length, so we never auto-submit — the
    // user always taps the ✓ key (or presses Enter). Auto-submitting at 6 would
    // truncate and lock out anyone with a longer PIN.
    if (pinBuffer.length < 12) {
      pinBuffer += btn.dataset.num;
      updatePinDots();
    }
  } else if (btn.dataset.action === "back") {
    pinBuffer = pinBuffer.slice(0, -1);
    updatePinDots();
  } else if (btn.dataset.action === "submit") {
    if (pinBuffer.length > 0) {
      $("pin-form")?.requestSubmit();
    }
  }
});

// PIN unlock. The backend enforces the backoff and the attempt cap; the UI's
// job is to report exactly what happened, including the moment the shortcut
// spends its last attempt and disappears.
$("pin-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("pin-error"); err.hidden = true;
  const code = (isAndroid && pinEnabled) ? pinBuffer : $("pin").value;
  $("pin").value = "";
  pinBuffer = "";
  updatePinDots();

  const { ok, status, body } = await api("/api/pin/unlock", { method: "POST", body: JSON.stringify({ pin: code }) });
  if (ok) { setSessionToken(body.session_token); return showUnlocked(); }

  if (isAndroid && pinEnabled) {
    renderPinKeypad(); // Scramble keypad numbers on failed attempt
    if (shufflePin) showToast("Keypad shuffled", null, { duration: 2500 });
  }

  if (status === 403 || status === 409) {
    // The shortcut is gone (attempt cap, or it was never there). Fall back.
    pinEnabled = false;
    showPinEntry(false);
    const ue = $("unlock-error");
    ue.textContent = body.error || "PIN unlock is no longer available — use your password.";
    ue.hidden = false;
    return;
  }
  const leftEl = $("pin-attempts");
  if (leftEl) leftEl.hidden = true;
  if (status === 429) {
    err.textContent = "Too many attempts.";
    if (leftEl) { leftEl.textContent = "Try again in " + (body.retry_after || 0) + "s, or use your password."; leftEl.hidden = false; }
  } else {
    const left = body.attempts_left;
    err.textContent = body.error || "Incorrect PIN.";
    // Countdown is its own line — burying it mid-sentence made the most
    // consequential number on the screen easy to skim past.
    if (leftEl) {
      if (typeof left === "number") {
        leftEl.textContent = left + " attempt" + (left === 1 ? "" : "s") + " left before PIN unlock is removed.";
        leftEl.hidden = false;
      } else leftEl.hidden = true;
    }
  }
  err.hidden = false;
});
// Forgotten-credentials path. Deliberately a disclosure the user has to open,
// not a button sitting next to Unlock: it is destructive and irreversible, and
// the explanation is the point of the screen.
$("forgot-btn").addEventListener("click", async () => {
  // Your password can't be reset — nobody holds a copy. The only path is to
  // remove the account from this device and restore it from the 24-word phrase.
  // The modal is the deliberate friction (it replaces typing DELETE); we send the
  // confirmation word the server still requires.
  const ok0 = await confirmDialog({
    title: "Forgot your password?",
    message:
      "Your password can't be reset or recovered — that's what keeps anyone else out. " +
      "If you still have your 24-word recovery phrase, remove the account here and restore it straight away, nothing lost. " +
      "If you've lost the phrase too, this erases your identity, messages and contacts from this device permanently.",
    confirmLabel: "Remove account from this device",
    danger: true,
  });
  if (!ok0) return;
  const { ok, body } = await api("/api/forget-identity", { method: "POST", body: JSON.stringify({ confirm: "DELETE" }) });
  if (!ok) {
    await confirmDialog({ title: "Couldn't remove the account", message: body.error || "Please try again.", confirmLabel: "OK", cancelLabel: "" });
    return;
  }
  // Back to onboarding, where "I already have a recovery phrase" restores the
  // account for anyone who still has it.
  resetSessionState();
  pinEnabled = false;
  await refresh();
});

$("use-password-btn").addEventListener("click", () => showPinEntry(false));
$("use-pin-btn").addEventListener("click", () => showPinEntry(true));

// ---------- pin unlock settings (You tab) ----------
async function loadPinState() {
  const { body } = await api("/api/status");
  pinEnabled = !!body.pin_enabled;
  renderPinState();
  // Sync shuffle PIN toggle
  const shuffleSwitch = $("shuffle-pin-switch");
  if (shuffleSwitch) {
    shuffleSwitch.selected = shufflePin;
    shuffleSwitch.addEventListener("change", () => {
      shufflePin = shuffleSwitch.selected;
      try { localStorage.setItem("shufflePin", shufflePin ? "1" : "0"); } catch (_) {}
    });
  }
}
function renderPinState() {
  $("pin-state").textContent = pinEnabled
    ? "On — this device unlocks with your PIN, or your password"
    : "Off — this device asks for your password every time";
  $("pin-off-btn").hidden = !pinEnabled;
  $("edit-pin-btn").hidden = pinEnabled;
}
$("edit-pin-btn").addEventListener("click", async () => {
  // Keep the dialog open across validation/API failures: mismatch shows an
  // inline error and preserves what was typed; the API error re-opens with a
  // static error message (never an editable "field" containing the error).
  let values = {};
  for (let attempt = 0; attempt < 3; attempt++) {
    const result = await editDialog({
      title: "Set up PIN unlock",
      passwordFirst: true,
      confirmLabel: "Turn on PIN",
      values,
      fields: [
        { id: "pin", label: "New PIN (6+ digits)", type: "password", inputmode: "numeric" },
        { id: "pin2", label: "Confirm PIN", type: "password", inputmode: "numeric" },
      ],
    });
    if (!result) return;
    values = { pin: result.pin, pin2: result.pin2 };
    if (!result.password) {
      values.password = "";
      await editDialog({
        title: "Set up PIN unlock",
        passwordFirst: true,
        confirmLabel: "Turn on PIN",
        values,
        errorMessage: "Enter your password to confirm.",
        fields: [
          { id: "pin", label: "New PIN (6+ digits)", type: "password", inputmode: "numeric" },
          { id: "pin2", label: "Confirm PIN", type: "password", inputmode: "numeric" },
        ],
      });
      continue;
    }
    const code = (result.pin || "").trim();
    if (!/^\d{6,}$/.test(code)) {
      await editDialog({
        title: "Set up PIN unlock",
        passwordFirst: true,
        confirmLabel: "Turn on PIN",
        values,
        errorMessage: "PINs must be at least 6 digits.",
        fields: [
          { id: "pin", label: "New PIN (6+ digits)", type: "password", inputmode: "numeric" },
          { id: "pin2", label: "Confirm PIN", type: "password", inputmode: "numeric" },
        ],
      });
      continue;
    }
    if (code !== (result.pin2 || "").trim()) {
      await editDialog({
        title: "Set up PIN unlock",
        passwordFirst: true,
        confirmLabel: "Turn on PIN",
        values,
        errorMessage: "The two PINs don't match — try again.",
        fields: [
          { id: "pin", label: "New PIN (6+ digits)", type: "password", inputmode: "numeric" },
          { id: "pin2", label: "Confirm PIN", type: "password", inputmode: "numeric" },
        ],
      });
      continue;
    }
    const { ok, body } = await api("/api/security", { method: "POST", body: JSON.stringify({ action: "pin-enable", password: result.password, code }) });
    if (!ok) {
      await editDialog({
        title: "Set up PIN unlock",
        passwordFirst: true,
        confirmLabel: "Turn on PIN",
        values,
        errorMessage: body.error || "Could not turn on PIN unlock.",
        fields: [
          { id: "pin", label: "New PIN (6+ digits)", type: "password", inputmode: "numeric" },
          { id: "pin2", label: "Confirm PIN", type: "password", inputmode: "numeric" },
        ],
      });
      continue;
    }
    pinEnabled = true;
    renderPinState();
    showToast("PIN unlock is on");
    return;
  }
});
// ---------- erase after failed unlocks (You tab) ----------
// Opt-in: after N failed unlocks in a row this device erases the account (the
// same wipe as "Remove account"). Off by default; changing it needs the
// password, like the PIN and duress controls.
async function loadWipeState() {
  const { ok, body } = await api("/api/security");
  const section = $("wipe-section");
  if (!ok || !body.wipe_available) { section.hidden = true; return; }
  section.hidden = false;
  renderWipeState(!!body.wipe_enabled, body.wipe_threshold || 10);
}
function renderWipeState(enabled, threshold) {
  $("wipe-state").textContent = enabled
    ? "On — this device erases itself after " + threshold + " failed unlocks"
    : "Off — wrong passwords are only slowed down";
  // Update segmented button active state
  document.querySelectorAll("#wipe-threshold-segs .seg").forEach(seg => {
    seg.classList.toggle("active", parseInt(seg.dataset.val, 10) === threshold);
  });
  $("wipe-off-btn").hidden = !enabled;
  $("wipe-save").textContent = enabled ? "Update" : "Turn on";
}
$("edit-wipe-btn").addEventListener("click", () => {
  const f = $("wipe-form");
  f.hidden = !f.hidden;
  $("wipe-error").hidden = true;
  if (!f.hidden) { $("wipe-password").value = ""; $("wipe-password").focus(); }
});
$("wipe-cancel").addEventListener("click", () => { $("wipe-form").hidden = true; });
async function saveWipePolicy(enabled) {
  const err = $("wipe-error"); err.hidden = true;
  const password = $("wipe-password").value;
  const activeSeg = document.querySelector("#wipe-threshold-segs .seg.active");
  const threshold = activeSeg ? parseInt(activeSeg.dataset.val, 10) : 10;
  if (enabled) {
    const ok0 = await confirmDialog({
      title: "Erase after " + threshold + " failed unlocks?",
      message:
        "When armed, this device permanently erases your identity, messages and Tor key after " + threshold +
        " wrong unlocks in a row — any failed unlock counts. Only your 24-word recovery phrase can restore the account afterward.",
      confirmLabel: "Arm auto-erase",
      danger: true,
    });
    if (!ok0) return;
  }
  const { ok, body } = await api("/api/security", {
    method: "POST",
    body: JSON.stringify({ action: "wipe-set", password, wipe_enabled: enabled, wipe_threshold: threshold }),
  });
  $("wipe-password").value = "";
  if (!ok) { err.textContent = body.error || "Could not change this setting."; err.hidden = false; return; }
  $("wipe-form").hidden = true;
  renderWipeState(!!body.wipe_enabled, body.wipe_threshold || threshold);
}
$("wipe-form").addEventListener("submit", (e) => { e.preventDefault(); saveWipePolicy(true); });
$("wipe-off-btn").addEventListener("click", () => saveWipePolicy(false));
// Segmented threshold selector: toggle active on click
document.querySelectorAll("#wipe-threshold-segs .seg").forEach(seg => {
  seg.addEventListener("click", () => {
    document.querySelectorAll("#wipe-threshold-segs .seg").forEach(s => s.classList.remove("active"));
    seg.classList.add("active");
  });
});
// ---------- duress code (You tab) ----------
// There is deliberately no "on/off" indicator anywhere: displaying whether a
// duress code is set would hand a coercer the one fact the feature exists to
// hide. Setting replaces, clearing removes, and neither reports prior state.
const duressWiz = $("duress-wizard");
const duressSteps = [$("duress-step1"), $("duress-step2"), $("duress-step3")];
let duressVerifiedPw = ""; // password confirmed in step 2

function showDuressStep(n) {
  duressSteps.forEach((s, i) => { s.hidden = i !== n; });
}

function resetDuressWizard() {
  showDuressStep(0);
  $("duress-password").value = "";
  $("duress-code").value = "";
  $("duress-code2").value = "";
  $("duress-error").hidden = true;
  $("duress-error2").hidden = true;
  $("duress-ok").hidden = true;
  duressVerifiedPw = "";
}

$("edit-duress-btn").addEventListener("click", () => {
  resetDuressWizard();
  duressWiz.hidden = false;
});

$("duress-wiz-cancel").addEventListener("click", () => { duressWiz.hidden = true; });

// Step 1 → Step 2
$("duress-wiz-next1").addEventListener("click", () => { showDuressStep(1); $("duress-password").focus(); });

// Step 2: verify password then move to Step 3
$("duress-password-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const pw = $("duress-password").value;
  if (!pw) { $("duress-error2").textContent = "Password is required."; $("duress-error2").hidden = false; return; }
  duressVerifiedPw = pw;
  $("duress-error2").hidden = true;
  showDuressStep(2);
  $("duress-code").focus();
});

// Step 2 → Step 1
$("duress-wiz-back1").addEventListener("click", () => { showDuressStep(0); });

// Step 3 → Step 2
$("duress-wiz-back2").addEventListener("click", () => { showDuressStep(1); });

// Step 3: submit
$("duress-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("duress-error"), ok = $("duress-ok");
  err.hidden = true; ok.hidden = true;
  const code = $("duress-code").value;
  if (code !== $("duress-code2").value) { err.textContent = "The two codes don't match."; err.hidden = false; return; }
  const res = await api("/api/security", { method: "POST", body: JSON.stringify({ action: "duress-set", password: duressVerifiedPw, code }) });
  $("duress-code").value = ""; $("duress-code2").value = "";
  if (!res.ok) { err.textContent = res.body.error || "Could not set the duress code."; err.hidden = false; return; }
  ok.textContent = "Duress code set. Entering it at the unlock screen will wipe this device.";
  ok.hidden = false;
  // Auto-close after a moment
  setTimeout(() => { duressWiz.hidden = true; }, 2000);
});

$("duress-clear").addEventListener("click", async () => {
  const err = $("duress-error"), ok = $("duress-ok");
  err.hidden = true; ok.hidden = true;
  const res = await api("/api/security", { method: "POST", body: JSON.stringify({ action: "duress-clear" }) });
  if (!res.ok) { err.textContent = "Could not clear the duress code."; err.hidden = false; return; }
  ok.textContent = "Cleared. No duress code is set on this device.";
  ok.hidden = false;
  setTimeout(() => { duressWiz.hidden = true; }, 2000);
});

$("pin-off-btn").addEventListener("click", async () => {
  const ok0 = await confirmDialog({
    title: "Turn off PIN unlock?",
    message: "This device will ask for your full password every time. Your account and messages are not affected.",
    confirmLabel: "Turn off PIN",
    danger: true,
  });
  if (!ok0) return;
  const { ok } = await api("/api/security", { method: "POST", body: JSON.stringify({ action: "pin-disable" }) });
  if (!ok) return;
  pinEnabled = false;
  renderPinState();
});
function resetSessionState() {
  setSessionToken(null);
  contacts = []; requests = []; messages = []; currentPeer = null; myName = ""; detailContent = null;
  groups = []; groupInvites = []; groupMembers = []; groupInfoCtx = {}; currentGroup = null; chatKind = null;
  for (const url of imageURLs.values()) URL.revokeObjectURL(url);
  imageURLs.clear();
  notifSeenAt = 0;
  clearTimeout(pollTimer);
}
$("lock-btn").addEventListener("click", async () => {
  haptic(); // subtle tick on lock (no-op where unsupported)
  await api("/api/lock", { method: "POST" });
  resetSessionState();
  await refresh(); // re-reads pin_enabled so the right credential is asked for
});

// Remove account: wipes identity + messages + Tor key from this device.
$("remove-account-btn").addEventListener("click", async () => {
  const ok = await confirmDialog({
    title: "Erase this account from this device?",
    message:
      "This permanently deletes your identity, messages, contacts and Tor key from this device. " +
      "It cannot be undone. You can only get back in with your 24-word recovery phrase — there is no other copy.",
    confirmLabel: "Erase everything",
    danger: true,
  });
  if (!ok) return;
  // Password confirmation via the app's own dialog — window.prompt is a silent
  // no-op in the Android WebView (no onJsPrompt handler), which made the most
  // destructive button in the app appear to do nothing.
  const result = await editDialog({
    title: "Confirm your password",
    passwordFirst: true,
    confirmLabel: "Erase everything",
    fields: [],
  });
  if (!result || !result.password) return;
  const { ok: success, body } = await api("/api/delete-identity", {
    method: "POST",
    body: JSON.stringify({ password: result.password }),
  });
  if (!success) {
    await confirmDialog({ title: "Could not remove account", message: body.error || "Incorrect password.", confirmLabel: "OK", cancelLabel: "" });
    return;
  }
  resetSessionState();
  await refresh();
});

// ---------- notifications ----------
async function toggleNotifs(on) {
  if (on) {
    let perm = Notification.permission;
    if (perm === "default") { try { perm = await Notification.requestPermission(); } catch (_) { perm = "denied"; } }
    notifsOn = perm === "granted";
  } else {
    notifsOn = false;
  }
  $("notif-switch").selected = notifsOn;
  $("notif-state").textContent = notifsOn ? "On — alerts for new messages" : (Notification.permission === "denied" ? "Blocked by your browser" : "Off");
  try { localStorage.setItem("notifs", notifsOn ? "1" : "0"); } catch (_) {}
}
$("notif-switch").addEventListener("change", (e) => { toggleNotifs(e.target.selected); });
function initNotifs() {
  if (isAndroid) {
    // The Android shell posts message notifications natively (the WebView has no
    // web Notification API); Android's own per-app/channel settings control them,
    // not this in-page toggle.
    $("notif-switch").setAttribute("disabled", "");
    $("notif-state").textContent = "Managed in Android settings";
    return;
  }
  if (!("Notification" in window)) { $("notif-switch").setAttribute("disabled", ""); $("notif-state").textContent = "Not supported"; return; }
  let want = false;
  try { want = localStorage.getItem("notifs") === "1"; } catch (_) {}
  notifsOn = want && Notification.permission === "granted";
  $("notif-switch").selected = notifsOn;
  $("notif-state").textContent = notifsOn ? "On — alerts for new messages" : "Off";
}

// ---------- desktop shell (window + tray build only) ----------
// The browser build gets {available:false} here and shows none of this. The
// same page is served either way; the server tells it which one it is in.
let desktopAvailable = false;

async function loadDesktop() {
  const { ok, body } = await api("/api/desktop");
  if (!ok) return;
  desktopAvailable = !!body.available;
  $("refresh-btn").hidden = !desktopAvailable;
  renderNotice(body.notice || "");

  const section = $("autostart-section");
  section.hidden = !(desktopAvailable && body.autostart_available);
  if (section.hidden) return;
  $("autostart-switch").selected = !!body.autostart;
  $("autostart-state").textContent = body.autostart ? "On" : "Off";
  const err = $("autostart-error");
  err.hidden = !body.error;
  if (body.error) err.textContent = body.error;
}

async function setAutostart(on) {
  const err = $("autostart-error"); err.hidden = true;
  const { ok, body } = await api("/api/desktop", {
    method: "POST", body: JSON.stringify({ autostart: on }),
  });
  if (!ok) {
    // Put the switch back where it really is rather than leaving it showing a
    // setting that was not saved.
    $("autostart-switch").selected = !on;
    err.textContent = body.error || "Could not change this setting.";
    err.hidden = false;
    return;
  }
  $("autostart-switch").selected = !!body.autostart;
  $("autostart-state").textContent = body.autostart ? "On" : "Off";
}
$("autostart-switch").addEventListener("change", (e) => setAutostart(e.target.selected));

// ---------- single-use invite code ----------
// A toggle for a one-time friend-request code that burns after one add. The bare
// account number keeps working regardless — this only makes the code single-use.
// The friend code is always on: it replaces the raw account in the profile card.
// It always carries a live token (the account alone is no longer addable), Copy
// and QR (the shared #copy-account / #show-qr handlers, reading #account.dataset
// .full and /api/qr) act on it, "New code" refreshes it, and the toggle chooses
// whether it auto-renews after each use or stays reusable until a manual refresh.
function renderInviteCode(b) {
  renderFriendCode($("account"), b.code || ""); // code takes the account's place
  $("onetime-switch").selected = !!b.auto_refresh;
  $("onetime-state").textContent = b.auto_refresh
    ? "On — each code works once, then a fresh one appears"
    : "Off — this code can be shared and reused";
}
// While a toggle/refresh POST is outstanding, the background poll must not
// GET and re-render the pre-action state — that snaps the switch back for a
// frame until the POST lands. loadInviteCode() (the poll caller) skips itself
// while this is set; inviteCodeAction owns the render during its own window.
let inviteActionInFlight = false;
async function loadInviteCode() {
  if (!$("onetime-switch") || inviteActionInFlight) return;
  const { ok, body } = await api("/api/invite-code");
  if (ok) renderInviteCode(body);
}
async function inviteCodeAction(action) {
  inviteActionInFlight = true;
  let ok, body;
  try {
    ({ ok, body } = await api("/api/invite-code", { method: "POST", body: JSON.stringify({ action }) }));
  } finally {
    inviteActionInFlight = false;
  }
  if (ok) renderInviteCode(body);
  else await loadInviteCode(); // resync the switch/code to the real state on failure
}
$("onetime-switch").addEventListener("change", (e) => inviteCodeAction(e.target.selected ? "enable" : "disable"));
$("onetime-refresh").addEventListener("click", () => inviteCodeAction("refresh"));

// renderNotice shows a one-time message from the desktop shell. It is raised
// while the window is hidden, so it waits here until the window is looked at.
function renderNotice(text) {
  $("desktop-notice").hidden = !text;
  $("desktop-notice-text").textContent = text;
}
$("desktop-notice-ok").addEventListener("click", async () => {
  renderNotice("");
  await api("/api/desktop", { method: "POST", body: JSON.stringify({ dismiss_notice: true }) });
});

// ---------- events: create / recover ----------
let pendingPassword = null;
// Recovery phrase held only across the save → unlock steps of a fresh
// signup, then wiped by clearOnboardingSecrets() on every exit (success,
// or Escape).
let pendingPhrase = null;
// PIN chosen at the wizard's PIN step, held until "Start messaging" unlocks and
// can actually enable it. Wiped by clearOnboardingSecrets() like the other two.
// See the PIN step for why it cannot be enabled where it is entered.
let wizPendingPin = null;

// ---- password strength (advisory only; never blocks account creation) ----
function pwScore(p) {
  if (!p) return 0;
  if (p.length < 6) return 1;
  let variety = 0;
  if (/\p{Ll}/u.test(p) && /\p{Lu}/u.test(p)) variety++;
  if (/\p{N}/u.test(p)) variety++;
  if (/[\p{P}\p{S}]/u.test(p)) variety++;
  // Strong requires all 3 categories (upper+lower, digit, symbol) and 12+ chars.
  if (variety >= 3 && p.length >= 12) return 3;
  // Fair requires at least 2 categories and 8+ chars.
  if (variety >= 2 && p.length >= 8) return 2;
  return 1;
}
function updatePwStrength(p) {
  const box = $("pw-strength");
  if (!box) return;
  if (!p) { box.hidden = true; box.className = "pw-strength"; return; }
  const sc = pwScore(p);
  box.hidden = false;
  box.className = "pw-strength s" + sc;
  $("pw-strength-label").textContent = sc >= 3 ? "Strong" : sc === 2 ? "Fair" : "Weak";
  // Update requirement checklist visual state (neutral → met/unmet).
  updatePwRequirements(p, "pw-req-length", "pw-req-upper", "pw-req-lower", "pw-req-digit", "pw-req-symbol");
}
function updatePwRequirements(p, lengthId, upperId, lowerId, digitId, symbolId) {
  const l = $(lengthId), u = $(upperId), lo = $(lowerId), d = $(digitId), s = $(symbolId);
  if (!p) {
    // Neutral: no typing yet — grey dots
    [l, u, lo, d, s].forEach(el => { if (el) el.className = ""; });
    return;
  }
  if (l) l.className = p.length >= 8 ? "met" : "unmet";
  if (u) u.className = /\p{Lu}/u.test(p) ? "met" : "unmet";
  if (lo) lo.className = /\p{Ll}/u.test(p) ? "met" : "unmet";
  if (d) d.className = /\p{N}/u.test(p) ? "met" : "unmet";
  if (s) s.className = /[\p{P}\p{S}]/u.test(p) ? "met" : "unmet";
}

// checkCreateFormValid enables/disables the Create Account button.
function checkCreateFormValid() {
  const pw = $("create-password")?.value || "";
  const pw2 = $("create-password2")?.value || "";
  const btn = $("create-btn");
  if (!btn) return;
  const pwOk = validatePassword(pw) === null;
  const matchOk = pw && pw2 && pw === pw2;
  btn.disabled = !(pwOk && matchOk);
}

// checkRecoverFormValid enables/disables the Recover Account button.
function checkRecoverFormValid() {
  const phrase = ($("recover-mnemonic")?.value || "").trim();
  const pw = $("recover-password")?.value || "";
  const pw2 = ($("recover-password2")?.value || "") || "";
  const btn = $("recover-btn");
  if (!btn) return;
  const words = phrase.split(/\s+/).filter(Boolean);
  const phraseOk = words.length === 24;
  const pwOk = validatePassword(pw) === null;
  const matchOk = pw && pw2 && pw === pw2;
  btn.disabled = !(phraseOk && pwOk && matchOk);
}

// updateConfirmIcon shows ✓ or ✗ next to the confirm field.
function updateConfirmIcon(pw, pw2, iconSel, errorSel) {
  const icon = $(iconSel), err = $(errorSel);
  if (!icon || !err) return;
  if (!pw2) { icon.hidden = true; err.hidden = true; return; }
  if (pw === pw2) {
    icon.textContent = "\u2713"; icon.className = "pw-match-icon match"; icon.hidden = false;
    err.hidden = true;
  } else {
    icon.textContent = "\u2717"; icon.className = "pw-match-icon nomatch"; icon.hidden = false;
    err.textContent = "Passwords do not match.";
    err.hidden = false;
  }
}

// autoFormatPhrase strips commas, extra spaces, line breaks from pasted phrases.
function autoFormatPhrase(el) {
  if (!el) return;
  el.addEventListener("paste", (e) => {
    setTimeout(() => {
      el.value = el.value.replace(/[,.\n\r\t]+/g, " ").replace(/\s+/g, " ").trim();
      el.dispatchEvent(new Event("input", { bubbles: true }));
    }, 0);
  });
}

// validatePassword mirrors the backend rules: 8-256 chars, uppercase, lowercase,
// digit, and symbol (punctuation/symbol Unicode categories) all required.
function validatePassword(pw) {
  if (!pw) return "Choose a password.";
  if (pw.length < 8) return "Password must be at least 8 characters.";
  if (pw.length > 256) return "Password must be at most 256 characters.";
  if (!/\p{Lu}/u.test(pw)) return "Password must include an uppercase letter.";
  if (!/\p{Ll}/u.test(pw)) return "Password must include a lowercase letter.";
  if (!/\p{N}/u.test(pw)) return "Password must include a number.";
  if (!/[\p{P}\p{S}]/u.test(pw)) return "Password must include a symbol.";
  return null;
}

function clearOnboardingSecrets() {
  pendingPassword = null;
  pendingPhrase = null;
  wizPendingPin = null;
  if ($("phrase-text")) $("phrase-text").textContent = "";
}
// Paint the recovery phrase as a numbered grid so each word is easy to
// transcribe in order. The ordinals come from a CSS counter, not text nodes,
// so the element's textContent stays exactly the 24 words — clearOnboarding-
// Secrets() still wipes the phrase by emptying the list (textContent = "").
function renderPhrase(phrase) {
  const grid = $("phrase-text");
  if (!grid) return;
  grid.innerHTML = "";
  for (const w of (phrase || "").trim().split(/\s+/)) {
    if (!w) continue;
    const li = document.createElement("li");
    li.className = "phrase-word";
    li.textContent = w;
    grid.append(li);
  }
}

// Copy recovery phrase to clipboard.
$("phrase-copy").addEventListener("click", async () => {
  if (!pendingPhrase) return;
  const text = pendingPhrase.trim().split(/\s+/).join(" ");
  try {
    await navigator.clipboard.writeText(text);
    showToast("Recovery phrase copied");
  } catch {
    // Fallback for non-HTTPS contexts.
    const ta = document.createElement("textarea");
    ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    document.execCommand("copy"); document.body.removeChild(ta);
    showToast("Recovery phrase copied");
  }
});

// Download recovery phrase as a plain text file.
$("phrase-download").addEventListener("click", async () => {
  if (!pendingPhrase) return;
  const words = pendingPhrase.trim().split(/\s+/);
  const lines = words.map((w, i) => `${i + 1}. ${w}`).join("\n");
  // Try the native save dialog (File System Access API) first.
  if (window.showSaveFilePicker) {
    try {
      const handle = await window.showSaveFilePicker({
        suggestedName: "recovery-phrase.txt",
        types: [{ description: "Text file", accept: { "text/plain": [".txt"] } }],
      });
      const writable = await handle.createWritable();
      await writable.write(lines + "\n");
      await writable.close();
      return;
    } catch (e) {
      // User cancelled or API not supported — fall through to blob download.
      if (e.name === "AbortError") return;
    }
  }
  // Fallback: blob download for browsers without File System Access API.
  const blob = new Blob([lines, "\n"], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "recovery-phrase.txt";
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 1000);
});
// ---------- onboarding wizard ----------
// One consistent stepped flow around the existing create / phrase forms plus
// plain-language explainer panels. The create path is:
//   welcome → privacy → password → profile → phrase → contacts → security → notify → pin → done
// "Recover" and "link" branch off welcome and return straight to the app.
//
// Redundancy if the app closes mid-setup splits in two: everything BEFORE the
// account exists is resumed from localStorage (WIZ_KEY); once /api/create
// succeeds the app boots to the lock screen instead, and the phrase — the one
// thing that used to be lost — is now viewable any time under You › Security.
const WIZ_NUMBERED = ["privacy", "password", "profile", "phrase", "contacts", "security", "notify", "pin"];
// Every step declares Back/Next. Steps whose primary action lives in the panel
// itself (password → Create account, profile → Continue, phrase → I've saved it)
// set next:null so the shared footer shows only Back — one consistent Back
// position across the whole flow. contacts keeps back:null: it renders after the
// account exists and must not walk the user back into the password step.
const WIZ_FLOW = {
  // welcome/done intentionally absent: they own their CTAs and must not show
  // the shared Back/Next footer.
  privacy:  { back: "welcome", next: "password" },
  password: { back: "privacy", next: null },
  profile:  { back: "password", next: null },
  phrase:   { back: "profile", next: null },
  contacts: { back: null,      next: "security" }, // no going back past account creation
  security: { back: "contacts", next: "notify" },
  notify:   { back: "security", next: "pin" },
  pin:      { back: "notify",   next: "done" },
  recover:  { back: "welcome",  next: null },
  link:     { back: "welcome",  next: null },
};
// Only pre-account steps are worth persisting: past "password" the account
// exists and onboarding never renders again (the app opens locked instead).
// "profile" is included because it's set before the phrase and is resumable.
const WIZ_RESUMABLE = new Set(["welcome", "privacy", "password", "profile"]);
const WIZ_KEY = "mp_onboard_step";
let wizStep = "welcome";

function wizPanel(step) { return document.querySelector(`#view-none .wiz-step[data-step="${step}"]`); }

function wizRenderProgress(step) {
  const prog = $("wiz-progress");
  const idx = WIZ_NUMBERED.indexOf(step);
  if (idx < 0) { prog.hidden = true; return; }
  prog.hidden = false;
  const dots = $("wiz-dots");
  dots.innerHTML = "";
  WIZ_NUMBERED.forEach((s, i) => {
    const d = document.createElement("span");
    d.className = "wiz-dot" + (i < idx ? " done" : i === idx ? " active" : "");
    dots.append(d);
  });
  $("wiz-count").textContent = `Step ${idx + 1} of ${WIZ_NUMBERED.length}`;
}

// Move to a step: show its panel, update the progress row and the Back/Next
// footer, move focus to the new heading (so keyboard/screen-reader users land
// on the step instead of a hidden button), and remember the spot (pre-account
// only).
function wizGoTo(step) {
  wizStep = step;
  document.querySelectorAll("#view-none .wiz-step").forEach(el => { el.hidden = true; });
  const panel = wizPanel(step);
  if (panel) panel.hidden = false;
  wizRenderProgress(step);
  const flow = WIZ_FLOW[step];
  $("wiz-nav").hidden = !flow;
  if (flow) {
    $("wiz-back").style.visibility = flow.back ? "visible" : "hidden";
    $("wiz-next").hidden = !flow.next;
  }
  try {
    if (WIZ_RESUMABLE.has(step)) localStorage.setItem(WIZ_KEY, step);
    else localStorage.removeItem(WIZ_KEY);
  } catch (_) {}
  // Focus the step heading (tabindex=-1 set in markup where needed) so focus
  // isn't stranded on a button inside a now-hidden panel.
  if (panel) {
    const h = panel.querySelector("h1, h2");
    if (h) {
      if (!h.hasAttribute("tabindex")) h.setAttribute("tabindex", "-1");
      setTimeout(() => { try { h.focus(); } catch (_) {} }, 0);
    }
  }
}

// Entry point when onboarding is shown: resume the last pre-account step, or
// start at welcome.
function wizInit() {
  let start = "welcome";
  try {
    const saved = localStorage.getItem(WIZ_KEY);
    if (saved && WIZ_RESUMABLE.has(saved)) start = saved;
  } catch (_) {}
  wizGoTo(start);
}

$("wiz-next").addEventListener("click", () => { const n = WIZ_FLOW[wizStep]?.next; if (n) wizGoTo(n); });
$("wiz-back").addEventListener("click", () => { const b = WIZ_FLOW[wizStep]?.back; if (b) wizGoTo(b); });

// Welcome choices.
$("wiz-start-create").addEventListener("click", () => wizGoTo("privacy"));
$("wiz-start-recover").addEventListener("click", () => { wizGoTo("recover"); $("recover-mnemonic").focus(); });
$("wiz-start-link").addEventListener("click", () => { wizGoTo("link"); $("wiz-link-code").focus(); });

// ---------- wizard: profile step (display name + avatar) ----------
// Runs after account creation. POSTs to /api/profile which already supports
// both fields. "Skip" advances without setting anything; "Continue" validates
// the name is non-empty and saves.
let wizPendingAvatar = null; // base64 of the picked avatar, awaiting save
function wizRenderAvatar() {
  const box = $("wiz-my-avatar");
  if (box) { box.innerHTML = ""; box.append(avatarNode(myAvatarHash, myName, null)); }
}
$("wiz-avatar-btn").addEventListener("click", () => $("wiz-avatar-input").click());
$("wiz-avatar-input").addEventListener("change", async (e) => {
  const file = e.target.files && e.target.files[0];
  e.target.value = "";
  if (!file) return;
  const err = $("wiz-avatar-error"); err.hidden = true;
  try {
    const { file: src, note } = await renderableImage(file, 1024);
    const cropped = await openAvatarCropper(src);
    if (!cropped) return; // cancelled in the crop editor
    wizPendingAvatar = await blobToBase64(cropped);
    // Preview straight off the cropped blob — the old code round-tripped the
    // base64 back through fetch() to rebuild a blob it already had.
    const url = URL.createObjectURL(cropped);
    const box = $("wiz-my-avatar");
    box.innerHTML = "";
    const img = document.createElement("img"); img.src = url; img.alt = "Profile picture";
    img.style.cssText = "width:100%;height:100%;object-fit:cover;border-radius:50%";
    box.append(img);
    const n = noteWorthTelling(note);
    if (n) showToast("Picture set — " + n + ".");
  } catch (ex) {
    err.textContent = ex.message || "Couldn't read that image.";
    err.hidden = false;
  }
});
$("wiz-profile-skip").addEventListener("click", () => { wizPendingAvatar = null; wizGoTo("phrase"); });
$("wiz-profile-next").addEventListener("click", async () => {
  const name = ($("wiz-display-name").value || "").trim();
  if (!name) { $("wiz-display-name").setAttribute("error", ""); $("wiz-display-name").focus(); return; }
  $("wiz-display-name").removeAttribute("error");
  // Save display name and avatar in one shot (or two if avatar was picked).
  try {
    const profileBody = { display_name: name };
    if (wizPendingAvatar) profileBody.avatar = wizPendingAvatar;
    const { ok } = await api("/api/profile", { method: "POST", body: JSON.stringify(profileBody) });
    if (ok) { myName = name; $("display-name-text").textContent = myName; }
    if (wizPendingAvatar) {
      // Also fetch back the hash if the server returned it.
      const { body } = await api("/api/profile");
      if (body && body.avatar_hash) myAvatarHash = body.avatar_hash;
    }
  } catch (_) {}
  wizPendingAvatar = null;
  wizGoTo("phrase");
});

// ---------- wizard: PIN step ----------
// Replaces the old post-unlock modal, but it CANNOT enable the PIN where the
// user types it: POST /api/security is s.auth()-gated on a vault session token,
// and no session exists anywhere in the wizard. The only place setSessionToken()
// is called for a fresh signup is doUnlock(), which runs at "Start messaging" —
// i.e. after this step. Posting from here therefore always 401'd, and because
// auth() answers with plain text rather than JSON there was not even a server
// message to show: every user who chose a PIN during onboarding got the generic
// "Could not turn on PIN unlock." (ui-audit frame 13c).
//
// So this step validates and holds the PIN, and wiz-finish enables it once the
// unlock has minted a session. Deferring beats minting a session here: a live
// token mid-wizard makes refresh() take its `sessionToken && unlocked` branch
// and drop the user straight into the chat view on the next WebView rebuild,
// skipping the rest of onboarding — and it would start the onion service three
// steps earlier, moving publish timing for no user-visible gain.
//
// Validation stays client-side and immediate, which is all this step can
// honestly check: the label promises "6+ digits", and an empty pair used to fire
// a raw server error at the user.
$("wiz-pin-save").addEventListener("click", () => {
  const err = $("wiz-pin-error"); err.hidden = true;
  const code = ($("wiz-pin-new").value || "").trim();
  const code2 = ($("wiz-pin-confirm").value || "").trim();
  if (!/^\d{6,}$/.test(code)) {
    err.textContent = "Enter a PIN of at least 6 digits.";
    err.hidden = false; $("wiz-pin-new").focus(); return;
  }
  if (code !== code2) { err.textContent = "The two PINs don't match."; err.hidden = false; return; }
  wizPendingPin = code;
  $("wiz-pin-new").value = ""; $("wiz-pin-confirm").value = "";
  wizGoTo("done");
});
$("wiz-pin-skip").addEventListener("click", () => {
  wizPendingPin = null;
  $("wiz-pin-new").value = ""; $("wiz-pin-confirm").value = "";
  $("wiz-pin-error").hidden = true;
  wizGoTo("done");
});

// Notify step: the explainer's whole subject is notifications, so it gets the
// button that actually requests permission — not just "go find the switch".
$("wiz-notify-enable")?.addEventListener("click", async () => {
  if (isAndroid) {
    // The shell posts natively; there is no web permission to ask. Point at
    // the system settings instead of silently doing nothing.
    showToast("Notifications are managed in Android settings");
    return;
  }
  if (!("Notification" in window)) { showToast("Notifications aren't supported here"); return; }
  let perm = Notification.permission;
  if (perm === "default") { try { perm = await Notification.requestPermission(); } catch (_) { perm = "denied"; } }
  if (perm === "granted") {
    notifsOn = true;
    try { localStorage.setItem("notifs", "1"); } catch (_) {}
    $("notif-switch").selected = true;
    $("notif-state").textContent = "On — alerts for new messages";
    showToast("Notifications are on");
  } else {
    showToast("Notifications stay off — you can enable them in settings");
  }
});

// Finish: unlock into the app, then apply the PIN the wizard collected. This is
// the first moment a session token exists, so it is the first moment
// POST /api/security can succeed (see the PIN step).
$("wiz-finish").addEventListener("click", async () => {
  const pw = pendingPassword;
  const pin = wizPendingPin;
  clearOnboardingSecrets();
  if (!pw) return;
  const unlocked = await doUnlock(pw);
  if (!unlocked?.ok || !pin) return;
  // The password that just unlocked is the one pinEnable re-verifies, so this
  // only fails on a genuine backend fault. The user is already in the app by
  // now, so report it where they are and name the place it can be retried —
  // never silently leave a PIN they asked for turned off.
  const { ok, body } = await api("/api/security", {
    method: "POST",
    body: JSON.stringify({ action: "pin-enable", password: pw, code: pin }),
  });
  if (!ok) {
    showToast(body.error || "PIN unlock couldn't be turned on — set it in You › Security");
    return;
  }
  pinEnabled = true;
  if (typeof renderPinState === "function") renderPinState();
});
$("link-password").addEventListener("input", (e) => {
  const p = e.target.value || "";
  updatePwRequirements(p, "link-pw-req-length", "link-pw-req-upper", "link-pw-req-lower", "link-pw-req-digit", "link-pw-req-symbol");
  const box = $("link-pw-strength");
  if (!box) return;
  if (!p) { box.hidden = true; box.className = "pw-strength"; return; }
  const sc = pwScore(p);
  box.hidden = false;
  box.className = "pw-strength s" + sc;
  $("link-pw-strength-label").textContent = sc >= 3 ? "Strong" : sc === 2 ? "Fair" : "Weak";
});
$("link-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("link-error"); err.hidden = true;
  const code = $("wiz-link-code").value.trim();
  const mnemonic = $("link-mnemonic").value.trim();
  const password = $("link-password").value;
  if (!code) { err.textContent = "Enter the pairing code from your other device."; err.hidden = false; return; }
  if (!mnemonic) { err.textContent = "Enter your recovery phrase."; err.hidden = false; return; }
  const pwErr = validatePassword(password);
  if (pwErr) { err.textContent = pwErr; err.hidden = false; return; }
  err.hidden = true;
  $("link-btn").disabled = true; $("link-btn").textContent = "Linking…";
  try {
    const res = await api("/api/pair/link-setup", {
      method: "POST",
      body: JSON.stringify({ code, mnemonic, password, device_name: navigator.platform || "device" }),
    });
    $("link-btn").disabled = false; $("link-btn").textContent = "Link this device";
    if (!res.ok) { err.textContent = res.body.error || "Could not link device."; err.hidden = false; return; }
    // Success — store the session token and transition to chat.
    setSessionToken(res.body.session_token);
    $("link-form").hidden = true;
    await showUnlocked();
  } catch (_) {
    $("link-btn").disabled = false; $("link-btn").textContent = "Link this device";
    err.textContent = "Could not connect to the server. Please try again."; err.hidden = false;
  }
});
$("link-btn").addEventListener("click", (e) => {
  if ($("link-btn").disabled) return;
  e.preventDefault();
  $("link-form").requestSubmit();
});
$("create-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("create-error"); err.hidden = true;
  const p1 = $("create-password").value, p2 = $("create-password2").value;
  const pwErr = validatePassword(p1);
  if (pwErr) { err.textContent = pwErr; err.hidden = false; return; }
  if (p1 !== p2) { err.textContent = "Passwords do not match."; err.hidden = false; return; }
  try {
    const { ok, body } = await api("/api/create", { method: "POST", body: JSON.stringify({ password: p1 }) });
    if (!ok) { err.textContent = body.error || "Could not create account."; err.hidden = false; return; }
    pendingPassword = p1;
    pendingPhrase = body.recovery_phrase;
    $("create-password").value = ""; $("create-password2").value = ""; updatePwStrength("");
      renderPhrase(pendingPhrase);
      // Account now exists — clear the resume marker and advance to profile.
      wizGoTo("profile");
  } catch (_) {
    err.textContent = "Could not connect to the server. Please try again."; err.hidden = false;
  }
});
// Fallback: if the form submit event doesn't fire (Material Web Components in
// some WebViews), a direct click on the button triggers requestSubmit().
$("create-btn").addEventListener("click", (e) => {
  if ($("create-btn").disabled) return;
  e.preventDefault();
  $("create-form").requestSubmit();
});
// Live password validation: update strength, requirements, confirm match, and button state.
$("create-password").addEventListener("input", (e) => {
  const p = e.target.value || "";
  updatePwStrength(p);
  updateConfirmIcon(p, $("create-password2")?.value || "", "pw-match-icon", "pw-match-error");
  checkCreateFormValid();
});
$("create-password2").addEventListener("input", () => {
  const p = $("create-password")?.value || "";
  const p2 = $("create-password2")?.value || "";
  updateConfirmIcon(p, p2, "pw-match-icon", "pw-match-error");
  checkCreateFormValid();
});
// Recover form: live validation for password requirements, confirm match, and button state.
$("recover-password").addEventListener("input", (e) => {
  const p = e.target.value || "";
  updatePwRequirements(p, "recover-pw-req-length", "recover-pw-req-upper", "recover-pw-req-lower", "recover-pw-req-digit", "recover-pw-req-symbol");
  updateConfirmIcon(p, $("recover-password2")?.value || "", "recover-pw-match-icon", "recover-pw-match-error");
  checkRecoverFormValid();
});
$("recover-password2")?.addEventListener("input", () => {
  const p = $("recover-password")?.value || "";
  const p2 = $("recover-password2")?.value || "";
  updateConfirmIcon(p, p2, "recover-pw-match-icon", "recover-pw-match-error");
  checkRecoverFormValid();
});
$("recover-mnemonic")?.addEventListener("input", () => {
  const phrase = ($("recover-mnemonic")?.value || "").trim();
  const words = phrase.split(/\s+/).filter(Boolean);
  const err = $("recover-mnemonic-error");
  if (phrase && words.length !== 24) {
    err.textContent = "This doesn't look like a 24-word phrase. Please check and try again.";
    err.hidden = false;
  } else {
    err.hidden = true;
  }
  checkRecoverFormValid();
});
// Auto-format pasted recovery phrases.
autoFormatPhrase($("recover-mnemonic"));
autoFormatPhrase($("link-mnemonic"));

// Show/hide password toggle buttons.
document.querySelectorAll(".pw-toggle").forEach(btn => {
  btn.addEventListener("click", () => {
    const field = document.getElementById(btn.dataset.target);
    if (!field) return;
    const input = field.shadowRoot?.querySelector("input");
    if (!input) return;
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    btn.innerHTML = show
      ? '<svg viewBox="0 0 24 24" width="20" height="20"><path fill="currentColor" d="M12 7c2.76 0 5 2.24 5 5 0 .65-.15 1.26-.42 1.81l2.91 2.91c1.52-1.26 2.7-2.89 3.44-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.15 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2z"/></svg>'
      : '<svg viewBox="0 0 24 24" width="20" height="20"><path fill="currentColor" d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/></svg>';
  });
});
// After "I've saved it", show a confirmation dialog before proceeding.
$("phrase-continue").addEventListener("click", () => {
  $("confirm-phrase-modal").hidden = false;
});
// "Go back" returns to the phrase view.
$("confirm-phrase-cancel").addEventListener("click", () => {
  $("confirm-phrase-modal").hidden = true;
});
// "Yes, continue" moves on to the feature explainers. The phrase is dropped
// from memory here (it stays retrievable under You › Security); the password is
// kept until "Start messaging" unlocks the app on the final step.
$("confirm-phrase-ok").addEventListener("click", () => {
  $("confirm-phrase-modal").hidden = true;
  pendingPhrase = null;
  if ($("phrase-text")) $("phrase-text").textContent = "";
  wizGoTo("contacts");
});
$("recover-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("recover-error"); err.hidden = true;
  const mnemonic = $("recover-mnemonic").value.trim();
  const password = $("recover-password").value;
  const password2 = $("recover-password2")?.value || "";
  // Validate phrase
  const words = mnemonic.split(/\s+/).filter(Boolean);
  if (words.length !== 24) {
    err.textContent = "Please enter all 24 words of your recovery phrase.";
    err.hidden = false; return;
  }
  // Validate password
  const pwErr = validatePassword(password);
  if (pwErr) { err.textContent = pwErr; err.hidden = false; return; }
  if (password !== password2) { err.textContent = "Passwords do not match."; err.hidden = false; return; }
  try {
    const { ok, body } = await api("/api/recover", { method: "POST", body: JSON.stringify({ mnemonic, password }) });
    if (!ok) { err.textContent = body.error || "Could not recover account."; err.hidden = false; return; }
    $("recover-mnemonic").value = ""; $("recover-password").value = ""; $("recover-password2").value = "";
    $("recover-form").hidden = true;
    try { localStorage.removeItem(WIZ_KEY); } catch (_) {}
    const res = await doUnlock(password); // recovery goes straight to the app
  } catch (_) {
    err.textContent = "Could not connect to the server. Please try again."; err.hidden = false;
  }
});
$("recover-btn").addEventListener("click", (e) => {
  if ($("recover-btn").disabled) return;
  e.preventDefault();
  $("recover-form").requestSubmit();
});

// ---------- optional PIN step during onboarding ----------
// Shown once, right after the first unlock of a new or recovered account (a PIN
// ---------- events: profile / share ----------
$("edit-name-btn").addEventListener("click", async () => {
  const result = await editDialog({
    title: "Change display name",
    fields: [{ id: "name", label: "Display name", type: "text" }],
    values: { name: myName },
  });
  if (!result) return;
  const name = result.name.trim();
  const { ok, body } = await api("/api/profile", { method: "POST", body: JSON.stringify({ display_name: name }) });
  if (!ok) { showToast(body.error || "Couldn't change your name."); return; }
  myName = body.display_name || name;
  $("display-name-text").textContent = myName || "(not set)";
  renderMyAvatar();
});
// Profile picture. With one set, the button OPENS it fullscreen (kind:"avatar"),
// where Edit and Remove live; with none, it goes straight to the file picker.
// Picking always routes through the crop editor before the upload.
$("avatar-btn").addEventListener("click", () => {
  if (myAvatarHash) openMyAvatarViewer();
  else $("avatar-input").click();
});
$("avatar-input").addEventListener("change", async (e) => {
  const file = e.target.files && e.target.files[0];
  e.target.value = ""; // allow re-picking the same file
  if (!file) return;
  const err = $("avatar-error"); err.hidden = true;
  const btn = $("avatar-btn"); btn.setAttribute("disabled", "");
  try {
    // Converted before the cropper rather than inside it: the cropper draws
    // with an <img>, which reads even fewer formats than createImageBitmap.
    // Without this, a RAW could be sent in a chat but not set as a picture.
    const { file: src, note } = await renderableImage(file, 1024);
    const blob = await openAvatarCropper(src);
    if (!blob) return; // cancelled — keep whatever picture was already set
    const b64 = await blobToBase64(blob);
    const { ok, body } = await api("/api/profile", { method: "POST", body: JSON.stringify({ avatar: b64 }) });
    if (!ok) { err.textContent = (body && body.error) || "Couldn't set that picture."; err.hidden = false; return; }
    myAvatarHash = body.avatar_hash || "";
    renderMyAvatar();
    const n = noteWorthTelling(note);
    if (n) showToast("Picture set — " + n + ".");
  } catch (ex) {
    err.textContent = ex.message || "Couldn't read that image.";
    err.hidden = false;
  } finally {
    btn.removeAttribute("disabled");
  }
});

// openMyAvatarViewer shows my own picture fullscreen. It fetches through api()
// rather than pointing the <img> at /api/avatar directly because that endpoint
// is authenticated — a bare src would 401.
async function openMyAvatarViewer() {
  if (!myAvatarHash) return;
  const url = await avatarObjectURL(myAvatarHash);
  if (!url) { showToast("Couldn't load that picture."); return; }
  openImageViewer(url, { kind: "avatar" });
}
$("image-viewer-avatar-edit").addEventListener("click", () => {
  closeImageViewer();
  $("avatar-input").click();
});
$("image-viewer-avatar-remove").addEventListener("click", async () => {
  if (!(await confirmDialog({
    title: "Remove profile picture?",
    message: "People who already have it keep the copy they downloaded.",
    confirmLabel: "Remove",
    danger: true,
  }))) return;
  const { ok, body } = await api("/api/profile", { method: "POST", body: JSON.stringify({ avatar: "" }) });
  if (!ok) { showToast((body && body.error) || "Couldn't remove that picture."); return; }
  myAvatarHash = body.avatar_hash || "";
  renderMyAvatar();
  closeImageViewer();
}); 
// Mailbox settings.
$("edit-mailbox-btn").addEventListener("click", async () => {
  const result = await editDialog({
    title: "Set up mailbox",
    fields: [{ id: "mailbox", label: "Mailbox .onion address", type: "text" }],
    values: { mailbox: myMailbox },
  });
  if (!result) return;
  const url = result.mailbox.trim();
  const { ok, body } = await api("/api/profile", { method: "POST", body: JSON.stringify({ mailbox_url: url }) });
  if (!ok) { showToast(body.error || "Couldn't save the mailbox."); return; }
  myMailbox = body.mailbox_url || "";
  $("mailbox-state").textContent = myMailbox ? myMailbox : "Not set — messages only arrive when you're online";
});
// Group image backup settings.
$("edit-gib-btn").addEventListener("click", async () => {
  const currentMB = myBackupBytes > 0 ? String(Math.round(myBackupBytes / MB)) : "";
  const result = await editDialog({
    title: "Group image backup",
    fields: [{ id: "gib", label: "Space to use (MB)", type: "number" }],
    values: { gib: currentMB },
  });
  if (!result) return;
  const raw = result.gib.trim();
  const mb = raw === "" ? 0 : Number(raw);
  if (!Number.isFinite(mb) || mb < 0) return;
  const bytes = Math.round(mb) * MB;
  const { ok, body } = await api("/api/profile", { method: "POST", body: JSON.stringify({ group_image_backup_bytes: bytes }) });
  if (!ok) { showToast(body.error || "Couldn't change group image backup."); return; }
  myBackupBytes = body.group_image_backup_bytes || 0;
  myMediaAutoSave = !!body.media_auto_save;
  renderBackupState();
  syncMediaSaveSection();
});
$("gib-restore-btn").addEventListener("click", async () => {
  const st = $("gib-restore-state");
  st.hidden = false;
  st.textContent = "Restoring from your mailbox…";
  const { ok } = await api("/api/groups/image/restore", { method: "POST" });
  st.textContent = ok
    ? "Restore started — group images will fill in as they arrive."
    : "Couldn't start a restore. Check your mailbox is set and you're online.";
});

// ---------- devices / multi-device linking ----------
async function loadDevices() {
  const { ok, body } = await api("/api/devices");
  if (!ok) return;
  const role = body.role || "primary";
  deviceRoleText = role;
  $("device-role").textContent = "This device: " + (role === "primary"
    ? "Primary — publishes your address and receives directly"
    : "Secondary — syncs from your primary device");
  $("make-primary-btn").hidden = role === "primary";
  $("link-new-btn").hidden = role !== "primary";
  const list = $("device-list"); list.innerHTML = "";
  for (const d of body.devices || []) {
    const row = document.createElement("div"); row.className = "device-row";
    const dot = document.createElement("span"); dot.className = "presence-dot presence-online";
    const name = document.createElement("span"); name.textContent = d.is_self ? "This device" : (d.name || "Linked device");
    row.append(dot, name); list.append(row);
  }
}
$("link-new-btn").addEventListener("click", async () => {
  const { ok, body } = await api("/api/pair/start", { method: "POST" });
  if (!ok) return;
  $("link-qr").src = "data:image/png;base64," + body.qr;
  $("link-code").textContent = body.code;
  $("link-existing-form").hidden = true;
  $("link-new-box").hidden = false;
});
$("link-new-done").addEventListener("click", () => { $("link-new-box").hidden = true; });
$("link-copy").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("link-code").textContent.trim()); } catch (_) {}
  showToast("Pairing code copied");
});
$("link-existing-btn").addEventListener("click", () => {
  $("link-new-box").hidden = true;
  $("link-error").hidden = true;
  $("link-existing-form").hidden = false;
  $("link-code-input").focus();
});
$("link-existing-cancel").addEventListener("click", () => { $("link-existing-form").hidden = true; });
$("link-existing-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("link-error"); err.hidden = true;
  const btn = $("link-existing-save"); btn.disabled = true;
  const code = $("link-code-input").value.trim();
  const { ok, body } = await api("/api/pair/link", { method: "POST", body: JSON.stringify({ code, device_name: (navigator.platform || "device") }) });
  btn.disabled = false;
  if (!ok) { err.textContent = body.error || "Could not link this device."; err.hidden = false; return; }
  $("link-existing-form").hidden = true;
  $("link-code-input").value = "";
  await Promise.all([loadDevices(), loadProfile(), loadContacts(), loadMessages()]);
});
$("make-primary-btn").addEventListener("click", async () => {
  await api("/api/device/make-primary", { method: "POST" });
  await loadDevices();
});
$("copy-account").addEventListener("click", async () => {
  // Copy the raw address from dataset.full, never the rendered DOM: the display
  // splits it into emphasized/dimmed spans, so reading textContent risks copying
  // a subtly wrong onion address. No textContent fallback — a hard fail (nothing
  // copied) beats silently copying a corrupted address.
  const full = $("account").dataset.full || "";
  if (!full) return;
  try { await navigator.clipboard.writeText(full); } catch (_) {}
  showToast("Friend code copied");
});
$("show-qr").addEventListener("click", async () => {
  // Open fullscreen QR viewer directly
  const full = $("account").dataset.full || "";
  if (!full) return;
  $("account-fs-text").textContent = full;
  const qr = $("account-fs-qr");
  qr.hidden = true;
  const { ok, body } = await api("/api/qr");
  if (ok && body.png) { qr.src = "data:image/png;base64," + body.png; qr.hidden = false; }
  $("account-fs").hidden = false;
});
function closeAccountFs() { $("account-fs").hidden = true; }
$("account-fs-close").addEventListener("click", closeAccountFs);
$("account-fs").addEventListener("click", (e) => { if (e.target === $("account-fs")) closeAccountFs(); });
// "?" helpers (Password vs PIN, and what a mailbox is) — explain, don't restate
// the form copy. Reuses the info popup.
$("pw-pin-help").addEventListener("click", () => infoDialog(
  "Password vs PIN",
  "Password: your master key. It encrypts your account on this device and, together with your 24-word phrase, is the only thing that can recover it — on any device. Choose it carefully.\n\n" +
  "PIN: an optional shortcut to unlock the app quickly on this one device (you can set it up right after your account is created). It never leaves this device and never replaces your password.",
));
$("mailbox-help-btn").addEventListener("click", () => infoDialog(
  "What is a mailbox?",
  "Think of it like a physical mailbox. When you're offline, people can't hand a message to you directly — so it's left in your mailbox instead, and delivered to you the next time you connect.\n\n" +
  "A mailbox is just another .onion address (your own, or one you trust) that holds encrypted messages for you. Without one, messages only arrive while you're online.",
));
// "Paste": pull an account number straight from the clipboard into the field.
$("paste-account-btn").addEventListener("click", async () => {
  try {
    const t = await navigator.clipboard.readText();
    if (t) { $("find-account").value = t.trim(); $("find-account").focus(); }
  } catch (_) { $("find-account").focus(); }
});

// ---------- events: find + friend requests ----------
// Live preview when typing an account ID
$("find-account").addEventListener("input", () => {
  const val = $("find-account").value.trim();
  const preview = $("find-preview");
  const helpText = $("find-help-text");
  // Show a preview once the input looks like something we can add: an onion
  // address, or a friend code (mp1:<account>:<token>) whose middle segment is
  // the account. The seed for the initials avatar is that bare account.
  let seed = "";
  if (val.startsWith("mp1:")) {
    seed = val.split(":")[1] || "";
  } else if (val.length >= 16 && val.endsWith(".onion")) {
    seed = val;
  }
  if (seed.length >= 16) {
    preview.hidden = false;
    helpText.hidden = true;
    $("find-preview-name").textContent = seed.slice(0, 16) + "…";
    // Render initials avatar
    const av = $("find-preview-avatar");
    av.innerHTML = "";
    av.append(avatarNode("", seed, null));
  } else {
    preview.hidden = true;
    helpText.hidden = false;
  }
});
$("find-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("find-error"); err.hidden = true; $("find-result").hidden = true; lookupResult = null;
  const account = $("find-account").value.trim();
  const btn = $("find-btn"); btn.disabled = true; btn.textContent = "Looking up…";
  const prog = $("find-progress"); if (prog) prog.hidden = false;
  const hint = $("find-hint"); if (hint) hint.hidden = false;
  let ok, body;
  try {
    ({ ok, body } = await api("/api/lookup", { method: "POST", body: JSON.stringify({ account }) }));
  } catch (_) {
    ok = false; body = { error: "Could not reach the server. Try again?" };
  }
  btn.disabled = false; btn.textContent = "Look up";
  if (prog) prog.hidden = true;
  if (hint) hint.hidden = true;
  if (!ok) { err.textContent = body.error || "Could not find that account."; err.hidden = false; return; }
  // Keep the raw typed value (a bare account, or a one-time invite code
  // mp1:<account>:<token>) as `code`: the send step posts that so the token
  // survives to the backend, which re-parses it. `account` is the canonical
  // bare account the peer returned, used only for display.
  lookupResult = { code: account, account: body.account, display_name: body.display_name || "", avatar_hash: body.avatar_hash || "" };
  $("find-name").textContent = lookupResult.display_name || "(no display name)";
  $("find-short").textContent = "· " + shortAccount(lookupResult.account);
  // The face at add-time: the backend fetched and cached the bytes during lookup,
  // so this renders from the local cache (initials until/if the bytes are there).
  const fa = $("find-avatar");
  fa.innerHTML = "";
  fa.append(avatarNode(lookupResult.avatar_hash, lookupResult.display_name || shortAccount(lookupResult.account), null));
  $("find-result").hidden = false;
});
$("send-request-btn").addEventListener("click", async () => {
  if (!lookupResult) return;
  const btn = $("send-request-btn"); btn.disabled = true; btn.textContent = "Sending…";
  let ok, body;
  try {
    ({ ok, body } = await api("/api/friend-requests/send", { method: "POST", body: JSON.stringify({ account: lookupResult.code, name: lookupResult.display_name }) }));
  } catch (_) {
    ok = false; body = { error: "Could not reach the server. Try again?" };
  }
  btn.disabled = false; btn.textContent = "Send friend request";
  if (!ok) { $("find-error").textContent = body.error || "Could not send request."; $("find-error").hidden = false; return; }
  lookupResult = null;
  await loadContacts();
  setTab("chats");
});
$("requests-list").addEventListener("click", async (e) => {
  const acc = e.target.closest("[data-accept]"), dec = e.target.closest("[data-decline]");
  if (acc) {
    acc.setAttribute("disabled", "");
    const { ok, body } = await api("/api/friend-requests/accept", { method: "POST", body: JSON.stringify({ account: acc.dataset.accept }) });
    // Don't imply it's done when the other side hasn't heard. We keep retrying
    // in the background, but they stay stuck at "pending" until it lands.
    if (ok && body.notified === false) {
      const n = $("accept-notice");
      n.textContent = "Accepted — but we couldn't reach them just now. They won't be able to message you until we do; we'll keep trying in the background.";
      n.hidden = false;
      setTimeout(() => { n.hidden = true; }, 12000);
    }
  } else if (dec) {
    dec.setAttribute("disabled", "");
    await api("/api/friend-requests/decline", { method: "POST", body: JSON.stringify({ account: dec.dataset.decline }) });
  }
  else return;
  await Promise.all([loadRequests(), loadContacts()]);
});

// ---------- events: groups ----------
$("add-toggle").addEventListener("click", (e) => { const s = e.target.closest(".seg"); if (s) setAddMode(s.dataset.add); });
$("group-create-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("group-create-error"); err.hidden = true;
  const name = $("group-name-input").value.trim();
  if (!name) return;
  const btn = $("group-create-btn"); btn.disabled = true;
  const { ok, body } = await api("/api/groups/create", { method: "POST", body: JSON.stringify({ name }) });
  btn.disabled = false;
  if (!ok) { err.textContent = body.error || "Could not create group."; err.hidden = false; return; }
  $("group-name-input").value = "";
  await loadGroups();
  setTab("chats");
  openGroup(body.id);
});

// received group invitations
function renderGroupInvites() {
  // Browser notification for new group invites (desktop only; Android uses JNI callbacks).
  if (groupInvites.length > prevGroupInviteCount && prevGroupInviteCount > 0 && "Notification" in window && Notification.permission === "granted") {
    const inv = groupInvites[groupInvites.length - 1];
    new Notification("Group invite", { body: (inv.inviter_name || "Someone") + " invited you to " + (inv.name || "a group") });
  }
  prevGroupInviteCount = groupInvites.length;
  const list = $("group-invites-list");
  list.innerHTML = "";
  for (const inv of groupInvites) {
    const row = document.createElement("div");
    row.className = "request-row";
    const info = document.createElement("div");
    const name = document.createElement("div"); name.className = "body";
    name.textContent = (inv.inviter_name || shortAccount(inv.inviter)) + " invited you to “" + (inv.name || "a group") + "”";
    info.append(name);
    const actions = document.createElement("div"); actions.className = "request-actions";
    if (inv.status === "joining") {
      const s = document.createElement("span"); s.className = "label muted"; s.textContent = "Joining…"; actions.append(s);
    } else {
      const join = document.createElement("md-text-button"); join.textContent = "Join"; join.dataset.gjoin = inv.group;
      const dec = document.createElement("md-text-button"); dec.textContent = "Decline"; dec.dataset.gdecline = inv.group;
      actions.append(join, dec);
    }
    row.append(info, actions);
    list.append(row);
  }
  $("group-invites-section").hidden = groupInvites.length === 0;
  updateRequestsBadge();
}
$("group-invites-list").addEventListener("click", async (e) => {
  const j = e.target.closest("[data-gjoin]"), d = e.target.closest("[data-gdecline]");
  if (j) { j.setAttribute("disabled", ""); await api("/api/groups/invites/accept", { method: "POST", body: JSON.stringify({ group: j.dataset.gjoin }) }); }
  else if (d) { await api("/api/groups/invites/decline", { method: "POST", body: JSON.stringify({ group: d.dataset.gdecline }) }); }
  else return;
  await Promise.all([loadGroupInvites(), loadGroups()]);
});

// group info / manage members
function renderGroupInfo() {
  const g = groupById(currentGroup);
  const isAdmin = groupInfoCtx.my_role === "admin";
  $("group-info-name").textContent = groupInfoCtx.name || (g && g.name) || "Group";
  $("group-info-sub").textContent = groupMembers.length + (groupMembers.length === 1 ? " member" : " members") + (isAdmin ? " · you're an admin" : "");
  $("group-rename-btn").hidden = !isAdmin;
  $("group-admin-controls").hidden = !groupInfoCtx.i_can_invite;
  $("group-info").querySelector(".policy-row").hidden = !isAdmin;
  $("group-info").querySelectorAll(".policy-toggle .seg").forEach((s) => s.classList.toggle("active", s.dataset.policy === groupInfoCtx.policy));
  const list = $("group-members-list");
  list.innerHTML = "";
  for (const m of groupMembers) {
    const row = document.createElement("div"); row.className = "member-row";
    const info = document.createElement("div");
    const nm = document.createElement("div"); nm.className = "body";
    nm.textContent = (m.name || shortAccount(m.account)) + (m.is_self ? " (you)" : "");
    const meta = document.createElement("div"); meta.className = "label muted";
    meta.textContent = m.role === "admin" ? "Admin" : (m.can_invite ? "Member · can invite" : "Member");
    info.append(nm, meta);
    const actions = document.createElement("div"); actions.className = "member-actions";
    if (!m.is_self) {
      if (m.friend_status === "accepted") { const b = document.createElement("md-text-button"); b.textContent = "Message"; b.dataset.gmsg = m.account; actions.append(b); }
      // No "Add friend" for a co-member: the account alone is no longer addable —
      // adding someone now requires their current friend code, which you only have
      // if they shared it with you out of band.
      else if (m.friend_status === "pending_out") { const s = document.createElement("span"); s.className = "label muted"; s.textContent = "Requested"; actions.append(s); }
      else if (m.friend_status === "pending_in") { const b = document.createElement("md-text-button"); b.textContent = "Accept friend"; b.dataset.gacceptfriend = m.account; actions.append(b); }
      if (isAdmin) {
        if (m.role !== "admin") { const b = document.createElement("md-text-button"); b.textContent = "Make admin"; b.dataset.gpromote = m.account; actions.append(b); }
        const rmv = document.createElement("md-text-button"); rmv.textContent = "Remove"; rmv.dataset.gremove = m.account; rmv.classList.add("danger-text"); actions.append(rmv);
      }
    }
    row.append(info, actions);
    list.append(row);
  }
  renderGroupInviteContacts();
}
// Contacts already invited this session — kept disabled so a second tap can't
// overwrite the sent-invite's reqID and strand an in-flight join. Frontend-local
// (there's no endpoint exposing sentGroupInvites), so it resets on reload; the
// backend still rejects a re-invite to an existing member, so that's a safe floor.
const groupInvitedThisSession = new Set();
// The straightforward invite path: a tap-to-invite list of accepted contacts who
// aren't already in the open group. The account-number form stays as the fallback.
function renderGroupInviteContacts() {
  const box = $("group-invite-contacts");
  if (!box) return;
  box.innerHTML = "";
  const members = new Set(groupMembers.map((m) => m.account));
  const invitable = contacts.filter((c) => c.status === "accepted" && !members.has(c.account));
  if (invitable.length === 0) {
    const p = document.createElement("p");
    p.className = "label muted";
    p.textContent = contacts.some((c) => c.status === "accepted")
      ? "All your contacts are already in this group."
      : "Add someone as a contact first, or invite by account number below.";
    box.append(p);
    return;
  }
  for (const c of invitable) {
    const row = document.createElement("div"); row.className = "member-row";
    const info = document.createElement("div"); info.className = "member-id";
    info.append(avatarNode(c.avatar_hash, contactLabel(c), null));
    const nm = document.createElement("div"); nm.className = "body";
    nm.textContent = contactLabel(c);
    info.append(nm);
    const actions = document.createElement("div"); actions.className = "member-actions";
    if (groupInvitedThisSession.has(sentInviteKey(currentGroup, c.account))) {
      const s = document.createElement("span"); s.className = "label muted"; s.textContent = "Invited";
      actions.append(s);
    } else {
      const b = document.createElement("md-text-button"); b.textContent = "Invite"; b.dataset.ginvite = c.account;
      actions.append(b);
    }
    row.append(info, actions);
    box.append(row);
  }
}
function sentInviteKey(group, account) { return group + "|" + account; }
// Per-row invite: disable only the tapped row (a peer who's offline blocks the
// request for up to 2 min server-side), and treat a queued/502 as success — the
// sent-invite record persists and the accept-retry path completes the join once
// they're online. Only a real rejection (already a member, not allowed) re-enables.
$("group-invite-contacts").addEventListener("click", async (e) => {
  const b = e.target.closest("[data-ginvite]");
  if (!b) return;
  const account = b.dataset.ginvite, group = currentGroup;
  b.setAttribute("disabled", "");
  b.textContent = "Inviting…";
  const { ok, body } = await api("/api/groups/invite", { method: "POST", body: JSON.stringify({ group, account }) });
  if (ok || (body && body.queued)) {
    groupInvitedThisSession.add(sentInviteKey(group, account));
    renderGroupInviteContacts();
    return;
  }
  const err = $("group-action-error");
  err.textContent = (body && body.error) || "Could not send invite.";
  err.hidden = false;
  b.removeAttribute("disabled");
  b.textContent = "Invite";
});
async function groupAction(path, payload) {
  const err = $("group-action-error"); err.hidden = true;
  const { ok, body } = await api(path, { method: "POST", body: JSON.stringify(payload) });
  if (!ok) { err.textContent = body.error || "That didn't work."; err.hidden = false; return false; }
  return true;
}
$("group-members-list").addEventListener("click", async (e) => {
  const t = e.target.closest("[data-gmsg],[data-gacceptfriend],[data-gpromote],[data-gremove]");
  if (!t) return;
  if (t.dataset.gmsg) { setTab("chats"); openChat(t.dataset.gmsg); return; }
  t.setAttribute("disabled", "");
  if (t.dataset.gacceptfriend) { await groupAction("/api/friend-requests/accept", { account: t.dataset.gacceptfriend }); await loadRequests(); }
  else if (t.dataset.gpromote) { await groupAction("/api/groups/promote", { group: currentGroup, account: t.dataset.gpromote }); }
  else if (t.dataset.gremove) { await groupAction("/api/groups/remove", { group: currentGroup, account: t.dataset.gremove }); }
  await Promise.all([loadGroupMembers(), loadContacts()]);
});
// invite from the group info pane
$("group-invite-btn").addEventListener("click", () => { $("group-invite-form").hidden = false; $("group-invite-btn").hidden = true; $("group-invite-account").focus(); });
$("group-invite-cancel").addEventListener("click", () => { $("group-invite-form").hidden = true; $("group-invite-btn").hidden = false; $("group-invite-error").hidden = true; });
$("group-invite-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("group-invite-error"); err.hidden = true;
  const account = $("group-invite-account").value.trim();
  if (!account) return;
  const btn = $("group-invite-send"); btn.disabled = true;
  const { ok, body } = await api("/api/groups/invite", { method: "POST", body: JSON.stringify({ group: currentGroup, account }) });
  btn.disabled = false;
  if (!ok) { err.textContent = body.error || "Could not send invite."; err.hidden = false; return; }
  $("group-invite-account").value = "";
  $("group-invite-form").hidden = true; $("group-invite-btn").hidden = false;
});
// rename
$("group-rename-btn").addEventListener("click", async () => {
  const result = await editDialog({
    title: "Rename group",
    fields: [{ id: "name", label: "Group name", type: "text" }],
    values: { name: groupInfoCtx.name || "" },
  });
  if (!result) return;
  const name = result.name.trim();
  if (!name) return;
  if (await groupAction("/api/groups/rename", { group: currentGroup, name })) {
    await Promise.all([loadGroups(), loadGroupMembers()]);
  }
});
// policy toggle
$("group-info").querySelector(".policy-toggle").addEventListener("click", async (e) => {
  const s = e.target.closest(".seg"); if (!s) return;
  if (s.dataset.policy === groupInfoCtx.policy) return;
  if (await groupAction("/api/groups/policy", { group: currentGroup, policy: s.dataset.policy })) await loadGroupMembers();
});

// ---------- events: chat ----------
$("compose-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("send-error").hidden = true;
  const text = $("compose-text").value.trim();
  if (!text) return;
  if (!torSendable) { $("send-error").textContent = "Still connecting to Tor — one moment, then you can send."; $("send-error").hidden = false; return; }
  haptic(); // subtle tick on send (no-op where unsupported)
  const reply = replyTarget; // capture before we clear it
  clearReply();
  // The author on replyTarget is OUR point of view ("You" / our nickname for
  // them); it must never cross the wire or the recipient renders the wrong name.
  // Send only id + preview; the recipient resolves the author locally.
  const wireReply = reply ? { id: reply.id, preview: reply.preview } : null;
  if (chatKind === "group") {
    if (!currentGroup) return;
    $("compose-text").value = "";
    $("compose-text").style.height = "";
    const { ok, body } = await api("/api/groups/send", { method: "POST", body: JSON.stringify({ group: currentGroup, text, reply_to: wireReply }) });
    if (!ok) { $("send-error").textContent = body.error || "Could not send."; $("send-error").hidden = false; return; }
    await loadMessages();
    return;
  }
  if (!currentPeer) return;
  $("compose-text").value = "";
  $("compose-text").style.height = "";
  // The backend queues, persists and acknowledges immediately, then delivers in
  // the background — so there is no optimistic client-side copy to keep in step
  // any more. Reloading shows the message already in the conversation, marked
  // pending until it lands.
  const { ok, body } = await api("/api/messages", { method: "POST", body: JSON.stringify({ to: currentPeer, text, reply_to: wireReply }) });
  if (!ok) {
    $("send-error").textContent = body.error || "Could not send.";
    $("send-error").hidden = false;
    return;
  }
  await loadMessages();
  // If they're offline with no mailbox, the message can't land until they come
  // back — so proactively offer to route it through a relay now, rather than
  // waiting for the send to visibly fail first.
  const peerC = contacts.find((c) => c.account === currentPeer);
  if (peerC && peerC.presence === "offline" && peerC.relay_available) {
    openRelayOffer(body.id, currentPeer);
  }
});
async function retrySend(id) {
  const { ok, body } = await api("/api/messages/retry", { method: "POST", body: JSON.stringify({ id }) });
  if (!ok) { $("send-error").textContent = body.error || "Could not retry."; $("send-error").hidden = false; return; }
  await loadMessages();
}
// ---- offline-send relay picker ----
let relayOfferId = null;     // the queued message this offer is for
let relayOfferHolder = null; // the relay-holder account the sender has picked

function relayHolders() {
  return contacts.filter((c) => c.relay_holder && c.status === "accepted");
}

// openRelayOffer shows the picker for a queued message that can't be delivered
// directly. Both paths funnel through here: the proactive one (just sent to a
// 🔴 offline, no-mailbox contact) and the reactive per-message "still trying"
// button on a send that has since failed.
function openRelayOffer(id, peer) {
  const holders = relayHolders();
  if (!id || holders.length === 0) return;
  relayOfferId = id;
  relayOfferHolder = holders.length === 1 ? holders[0].account : null;
  $("relay-offer-msg").textContent =
    contactName(peer) + " is offline and has no mailbox, so this message won’t arrive until they’re back online. Route it through a friend’s relay instead?";
  const list = $("relay-offer-list");
  list.innerHTML = "";
  for (const h of holders) {
    const item = document.createElement("button");
    item.type = "button";
    item.className = "relay-item";
    item.dataset.holder = h.account;
    item.setAttribute("role", "radio");
    item.setAttribute("aria-checked", String(h.account === relayOfferHolder));
    const radio = document.createElement("span"); radio.className = "radio";
    const label = document.createElement("span"); label.textContent = contactLabel(h, h.account);
    item.append(radio, label);
    list.append(item);
  }
  $("relay-offer-send").disabled = !relayOfferHolder;
  $("relay-offer").hidden = false;
}

function closeRelayOffer() {
  $("relay-offer").hidden = true;
  relayOfferId = null;
  relayOfferHolder = null;
}

$("relay-offer-list").addEventListener("click", (e) => {
  const item = e.target.closest("[data-holder]");
  if (!item) return;
  relayOfferHolder = item.dataset.holder;
  $("relay-offer-list").querySelectorAll(".relay-item").forEach((el) =>
    el.setAttribute("aria-checked", String(el.dataset.holder === relayOfferHolder)));
  $("relay-offer-send").disabled = false;
});
$("relay-offer-cancel").addEventListener("click", closeRelayOffer);
// A tap on the dimmed backdrop (outside the card) also just keeps waiting.
$("relay-offer").addEventListener("click", (e) => { if (e.target.id === "relay-offer") closeRelayOffer(); });

// ---------- QR camera scan (add a contact by their account QR) ----------
let scanStream = null;
let scanRAF = null;

function scanSupported() {
  const ok = !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia && window.jsQR);
  if (!ok && !window.jsQR) console.warn("QR scan unavailable: vendor/jsqr.js did not load");
  return ok;
}

async function openScan() {
  if (!scanSupported()) return;
  const overlay = $("scan-overlay"), video = $("scan-video");
  $("scan-hint").textContent = "Point the camera at their QR code";
  overlay.hidden = false;
  try {
    // Prefer the rear camera for scanning someone else's screen/printout.
    scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
  } catch (_) {
    $("scan-hint").textContent = "Couldn't open the camera — paste the code instead.";
    setTimeout(closeScan, 1800);
    return;
  }
  video.srcObject = scanStream;
  try { await video.play(); } catch (_) {}
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  const tick = () => {
    if (!scanStream) return; // torn down between frames
    if (video.readyState >= 2 && video.videoWidth) {
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = window.jsQR(img.data, img.width, img.height, { inversionAttempts: "dontInvert" });
      if (code && code.data) { onScanResult(code.data.trim()); return; }
    }
    scanRAF = requestAnimationFrame(tick);
  };
  scanRAF = requestAnimationFrame(tick);
}

// closeScan tears the camera down. Idempotent, and called from every exit path
// (cancel, decode, back, pane navigation via showDetail, tab hidden) so the
// camera and its indicator never outlive the scanner.
function closeScan() {
  if (scanRAF) { cancelAnimationFrame(scanRAF); scanRAF = null; }
  if (scanStream) { scanStream.getTracks().forEach((t) => t.stop()); scanStream = null; }
  const v = $("scan-video"); if (v) v.srcObject = null;
  const o = $("scan-overlay"); if (o) o.hidden = true;
}

function onScanResult(text) {
  closeScan();
  // Ensure the add-screen is visible — the scanner can be opened from the
  // empty-state button which bypasses the add screen entirely.
  if (detailContent !== "add") showDetail("add");
  // Land the result on the person-lookup form even if the user opened the
  // scanner while the add screen was in group mode (its find-form would be
  // hidden, so the submit below would run unseen).
  setAddMode("person");
  // A decoded QR is attacker-supplied camera input. Don't act on it cleverly —
  // drop it into the lookup field and run the ordinary lookup, whose backend
  // validates the account (AccountNumberFromString: strips .onion, checks the
  // version byte + checksum) and shows a visible error on garbage.
  $("find-account").value = text;
  if ($("find-form").requestSubmit) $("find-form").requestSubmit();
  else $("find-btn").click();
}

$("scan-btn").addEventListener("click", openScan);
$("scan-cancel").addEventListener("click", closeScan);

// ---------- photos (image attachments, 1:1) ----------
// The serve endpoint needs the auth token, which an <img src> can't send, so we
// fetch each image with the token, turn it into a same-origin blob: URL, and
// cache it by id (the bytes are immutable per id) so repeated polls don't
// re-fetch or leak object URLs.
const imageURLs = new Map();

function imageElement(id, delivery) {
  const img = document.createElement("img");
  img.className = "msg-image";
  img.alt = delivery === "failed" ? "Photo, not sent" : "Photo";
  const cached = imageURLs.get(id);
  if (cached) {
    img.src = cached;
  } else {
    img.classList.add("skeleton");
    fetchImage(id, img);
  }
  img.addEventListener("click", () => {
    if (img.src && !img.classList.contains("img-missing") && !img.classList.contains("skeleton")) {
      openImageViewer(img.src, { delivery });
    }
  });
  return img;
}

async function fetchImage(id, img) {
  try {
    const res = await fetch("/api/attachment?id=" + encodeURIComponent(id), {
      headers: { Authorization: "Bearer " + sessionToken, "X-Control-Token": controlToken },
    });
    if (!res.ok) throw new Error("unavailable");
    const url = URL.createObjectURL(await res.blob());
    imageURLs.set(id, url);
    img.classList.remove("skeleton");
    img.src = url;
  } catch (_) {
    // 404 = the blob isn't on THIS device yet. On a secondary it backfills from
    // the primary in the background (see /sync/attachment); failures aren't
    // cached, so the next poll's re-render retries and the image appears once it
    // lands. It stays a placeholder only if no device still holds the bytes.
    img.classList.remove("skeleton");
    img.classList.add("img-missing");
    img.alt = "Photo unavailable on this device";
  }
}

// groupImageElement renders a group image: the full image once it's local, else a
// blurry thumbnail with a Download button that fetches the full on demand (from
// the sender, v1 — so it can fail while they're offline, and the button stays).
function groupImageElement(m) {
  const wrap = document.createElement("div");
  wrap.className = "group-image";
  const img = document.createElement("img");
  img.className = "msg-image";
  if (m.has_full) {
    img.alt = "Photo";
    const cached = imageURLs.get(m.attach_id);
    if (cached) {
      img.src = cached;
    } else {
      img.classList.add("skeleton");
      fetchImage(m.attach_id, img);
    }
    img.addEventListener("click", () => { if (img.src && !img.classList.contains("img-missing") && !img.classList.contains("skeleton")) openImageViewer(img.src); });
    wrap.append(img);
    return wrap;
  }
  img.classList.add("blurred");
  img.alt = "Photo — tap Download";
  const cached = imageURLs.get(m.thumb_id);
  if (cached) img.src = cached; else fetchImage(m.thumb_id, img);
  const dl = document.createElement("button");
  dl.className = "img-download";
  dl.textContent = "Download";
  dl.addEventListener("click", async (e) => {
    e.stopPropagation();
    dl.disabled = true; dl.textContent = "Downloading…";
    const { ok } = await api("/api/groups/image/download", { method: "POST", body: JSON.stringify({ group: m.group_id, id: m.id }) });
    if (ok) await loadMessages(); // re-render: has_full is now true, shows the full image
    else { dl.disabled = false; dl.textContent = "Retry download"; }
  });
  wrap.append(img, dl);
  return wrap;
}

// ---- fullscreen image viewer: zoom / pan / download / forward (item 2) ----
let ivSrc = null;                 // the currently-shown image's object URL
let ivIsQR = false;               // true when the viewer holds a QR (no save/forward)
let ivIsAvatar = false;           // true when the viewer holds MY profile picture
const ivZoom = { scale: 1, tx: 0, ty: 0 }; // applied transform
const ivPointers = new Map();     // active pointers on the stage (pinch tracking)
let ivPinchStart = null;          // {dist, scale, cx, cy} captured when the 2nd finger lands
let ivLastTap = 0;                // for double-tap detection
let ivMultiTouched = false;       // was this gesture ever a pinch? (suppresses double-tap)

function ivApply() {
  $("image-viewer-img").style.transform =
    `translate(${ivZoom.tx}px, ${ivZoom.ty}px) scale(${ivZoom.scale})`;
}
function ivReset() {
  ivZoom.scale = 1; ivZoom.tx = 0; ivZoom.ty = 0;
  ivPointers.clear(); ivPinchStart = null; ivMultiTouched = false;
  ivApply();
}
// opts.kind === "qr" opens the viewer for a QR code: no gallery-save or forward
// (a QR isn't a photo), just fullscreen + zoom. opts.kind === "avatar" opens MY
// profile picture: the photo actions step aside for Edit and Remove, since
// saving your own avatar to your gallery or forwarding it is not the point. opts.delivery === "failed" marks
// an undelivered outgoing image: a persistent "Not sent" chip appears and the
// share/forward/download actions step aside — the viewer must never imply the
// message went out. Visibility is set on EVERY open so a prior QR/failed view
// never leaks into the next photo.
let ivHintShown = false;
function openImageViewer(src, opts = {}) {
  const isQR = opts.kind === "qr";
  const isAvatar = opts.kind === "avatar";
  const notSent = opts.delivery === "failed";
  ivSrc = src;
  ivIsQR = isQR;
  ivIsAvatar = isAvatar;
  $("image-viewer-img").src = src;
  $("image-viewer-img").alt = isQR ? "QR code" : (isAvatar ? "Your profile picture" : (notSent ? "Photo, not sent" : "Photo"));
  $("image-viewer-actions").hidden = isQR || isAvatar || notSent;
  $("image-viewer-avatar-actions").hidden = !isAvatar;
  const state = $("image-viewer-state");
  if (state) state.hidden = !notSent;
  ivReset();
  ivNote(ivHintShown || isQR ? null : "Double-tap to zoom");
  ivHintShown = true;
  // Mirror showDetail's nav rule: the bar hides only in the narrow overlay
  // layout — an unconditional hide/show resurrected it wrongly on wide.
  const isWide = window.matchMedia("(min-width: 900px)").matches;
  $("bottomnav").hidden = !isWide ? true : $("bottomnav").hidden;
  $("image-viewer").hidden = false;
  // Focus the close control so keyboard/switch users land inside the overlay.
  setTimeout(() => { try { $("image-viewer-close").focus(); } catch (_) {} }, 0);
}
function closeImageViewer() {
  $("image-viewer").hidden = true;
  clearTimeout(ivNoteTimer);
  // Restore the nav exactly as showDetail would: visible unless a detail pane
  // is overlaying the list on a narrow layout.
  const isWide = window.matchMedia("(min-width: 900px)").matches;
  $("bottomnav").hidden = detailContent !== null && !isWide;
  const state = $("image-viewer-state");
  if (state) state.hidden = true;
  ivIsAvatar = false;
  $("image-viewer-avatar-actions").hidden = true;
  $("image-viewer-img").removeAttribute("src");
  $("image-viewer-img").style.transform = "";
  ivSrc = null;
}
function ivNote(text) {
  const n = $("image-viewer-note");
  if (!text) { n.hidden = true; return; }
  n.textContent = text; n.hidden = false;
}

// Zoom around a stage-space point (px,py), clamped to [1, 5]. At scale 1 we
// recentre (tx/ty = 0) so the image can't drift off after zooming back out.
// A brief zoom-level pill (reusing .iv-note) surfaces the change — without it
// a "stuck" pinch at the 5× cap reads as a bug.
let ivNoteTimer = null;
function ivShowZoom() {
  if (ivIsQR) return;
  clearTimeout(ivNoteTimer);
  ivNote(Math.round(ivZoom.scale * 100) + "%");
  ivNoteTimer = setTimeout(() => ivNote(null), 1200);
}
// ivLocalPoint converts a client-space point (a finger, a pinch centroid, the
// mouse) into the image's own transform space.
//
// ivZoomTo's anchor maths requires the point to be measured from the SAME origin
// the scale happens about. #image-viewer-img sets transform-origin: 0 0 — the
// IMAGE element's top-left — but every caller was passing a point measured from
// the STAGE's top-left. The stage flex-centres the image, so the two differ by
// the letterbox margin, and each zoom was displaced by exactly that: a double-tap
// right of centre zoomed to a point left of the finger, and the error grew with
// the gap between the image box and the stage (worst for a portrait photo on a
// landscape screen).
//
// With origin 0 0 the transformed rect's top-left is just the untransformed
// top-left plus the current translation, so subtracting tx/ty recovers the layout
// origin exactly — no need to measure the letterbox.
function ivLocalPoint(clientX, clientY) {
  const r = $("image-viewer-img").getBoundingClientRect();
  return { x: clientX - (r.left - ivZoom.tx), y: clientY - (r.top - ivZoom.ty) };
}
function ivZoomTo(newScale, px, py) {
  newScale = Math.max(1, Math.min(5, newScale));
  const k = newScale / ivZoom.scale;
  ivZoom.tx = px - k * (px - ivZoom.tx);
  ivZoom.ty = py - k * (py - ivZoom.ty);
  ivZoom.scale = newScale;
  if (newScale === 1) { ivZoom.tx = 0; ivZoom.ty = 0; }
  ivApply();
}

const ivStage = $("image-viewer-stage");
ivStage.addEventListener("pointerdown", (e) => {
  ivStage.setPointerCapture(e.pointerId);
  ivPointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
  if (ivPointers.size === 2) {
    ivMultiTouched = true;
    const [a, b] = [...ivPointers.values()];
    ivPinchStart = {
      dist: Math.hypot(a.x - b.x, a.y - b.y), scale: ivZoom.scale,
      cx: (a.x + b.x) / 2, cy: (a.y + b.y) / 2,
    };
  }
});
ivStage.addEventListener("pointermove", (e) => {
  const p = ivPointers.get(e.pointerId);
  if (!p) return;
  const prev = { x: p.x, y: p.y };
  p.x = e.clientX; p.y = e.clientY;
  if (ivPointers.size === 2 && ivPinchStart) {
    const [a, b] = [...ivPointers.values()];
    const dist = Math.hypot(a.x - b.x, a.y - b.y);
    const anchor = ivLocalPoint(ivPinchStart.cx, ivPinchStart.cy);
    ivZoomTo(ivPinchStart.scale * (dist / ivPinchStart.dist), anchor.x, anchor.y);
  } else if (ivPointers.size === 1 && ivZoom.scale > 1) {
    ivZoom.tx += p.x - prev.x; ivZoom.ty += p.y - prev.y;
    ivApply();
  }
});
function ivPointerEnd(e) {
  ivPointers.delete(e.pointerId);
  if (ivPointers.size < 2) ivPinchStart = null;
  if (ivPointers.size === 0) {
    // Double-tap toggle — only for a purely single-finger gesture, so lifting the
    // fingers off a pinch never registers as a tap and snaps the zoom.
    if (!ivMultiTouched) {
      const now = Date.now();
      if (now - ivLastTap < 300) {
        const anchor = ivLocalPoint(e.clientX, e.clientY);
        ivZoomTo(ivZoom.scale > 1 ? 1 : 2.5, anchor.x, anchor.y);
        ivShowZoom();
        ivLastTap = 0;
      } else {
        ivLastTap = now;
      }
    } else {
      ivShowZoom(); // pinch just ended — surface the landing zoom level once
    }
    ivMultiTouched = false;
  }
}
ivStage.addEventListener("pointerup", ivPointerEnd);
ivStage.addEventListener("pointercancel", ivPointerEnd);
// Desktop wheel zoom.
ivStage.addEventListener("wheel", (e) => {
  e.preventDefault();
  const anchor = ivLocalPoint(e.clientX, e.clientY);
  ivZoomTo(ivZoom.scale * (e.deltaY < 0 ? 1.15 : 0.87), anchor.x, anchor.y);
  ivShowZoom();
}, { passive: false });
// Close only from the backdrop (the stage itself, at fit) or the ✕ — never from
// a tap on the image or a control, so zoom/pan and the buttons stay usable.
ivStage.addEventListener("click", (e) => {
  if (e.target === ivStage && ivZoom.scale === 1) closeImageViewer();
});
$("image-viewer-close").addEventListener("click", closeImageViewer);
$("image-viewer-download").addEventListener("click", () => downloadViewerImage());
$("image-viewer-share").addEventListener("click", () => shareViewerImage());
$("image-viewer-forward").addEventListener("click", () => {
  if (ivSrc && !ivIsQR) openForwardPicker({ kind: "image", src: ivSrc });
});
// Tapping a QR code opens it fullscreen (zoom to scan/photograph). The handler
// reads .src at click time, so it works once the QR image has been generated.
for (const qrId of ["qr-img", "link-qr"]) {
  const qr = $(qrId);
  if (qr) qr.addEventListener("click", () => { if (qr.src) openImageViewer(qr.src, { kind: "qr" }); });
}

// downloadViewerImage saves the open photo to the device gallery. On Android the
// native bridge writes it via MediaStore; on the desktop/browser build we fall
// back to a normal file download.
async function downloadViewerImage() {
  if (!ivSrc) return;
  try {
    const blob = await (await fetch(ivSrc)).blob();
    const mime = blob.type || "image/jpeg";
    if (window.AndroidShell && window.AndroidShell.saveImageToGallery) {
      const b64 = await blobToBase64(blob);
      const res = window.AndroidShell.saveImageToGallery(b64, mime);
      ivNote(res === "" || res === true || res === undefined ? "Saved to your gallery" : String(res));
      return;
    }
    const ext = mime === "image/gif" ? "gif" : mime === "image/png" ? "png" : mime === "image/webp" ? "webp" : "jpg";
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "photo-" + Date.now() + "." + ext;
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 10000);
    ivNote("Downloaded");
  } catch (_) {
    ivNote("Couldn't save that photo");
  }
}

// shareViewerImage opens the OS share sheet for the currently viewed photo.
// On Android the native bridge writes a temp file and fires ACTION_SEND;
// on desktop/browser we fall back to the Web Share API if available.
async function shareViewerImage() {
  if (!ivSrc) return;
  try {
    const blob = await (await fetch(ivSrc)).blob();
    const mime = blob.type || "image/jpeg";
    if (window.AndroidShell && window.AndroidShell.shareImage) {
      const b64 = await blobToBase64(blob);
      window.AndroidShell.shareImage(b64, mime);
      return;
    }
    // Desktop/browser fallback: Web Share API
    if (navigator.share) {
      const file = new File([blob], "photo." + (mime === "image/gif" ? "gif" : mime === "image/png" ? "png" : "jpg"), { type: mime });
      await navigator.share({ files: [file] });
      return;
    }
    ivNote("Sharing is not available on this device");
  } catch (_) {
    ivNote("Couldn't share that photo");
  }
}

// Decode, downscale and re-encode to JPEG under the size cap the backend
// enforces, so the wire payload is bounded and the type is always allowlisted.
const IMAGE_CAP_BYTES = 3 * 1024 * 1024;
// Backend format conversion gets its own, longer budget than an ordinary API
// call: a 90 MB RAW has to be read off storage and walked before a single byte
// comes back, and timing that out would look like "this app rejects my photos".
const IMAGE_DECODE_TIMEOUT_MS = 180000;
// Cap for a group image's inline thumbnail (matches protocol.MaxGroupThumbBytes).
const GROUP_THUMB_CAP_BYTES = 16 * 1024;

// encodeScaled downscales a decoded bitmap to fit maxDim on its longest side and
// re-encodes to JPEG, dropping quality until it fits capBytes. Does NOT close the
// bitmap — the caller may reuse it (a group image encodes both a full and a thumb).
async function encodeScaled(bitmap, maxDim, capBytes, startQ = 0.85) {
  const scale = Math.min(1, maxDim / Math.max(bitmap.width, bitmap.height));
  const w = Math.max(1, Math.round(bitmap.width * scale));
  const h = Math.max(1, Math.round(bitmap.height * scale));
  const canvas = document.createElement("canvas");
  canvas.width = w; canvas.height = h;
  canvas.getContext("2d").drawImage(bitmap, 0, 0, w, h);
  const toBlob = (q) => new Promise((res) => canvas.toBlob(res, "image/jpeg", q));
  let q = startQ, blob = await toBlob(q);
  while (blob && blob.size > capBytes && q > 0.3) { q -= 0.15; blob = await toBlob(q); }
  if (!blob || blob.size > capBytes) throw new Error("That photo is too large, even compressed.");
  return blob;
}

// tryBitmap decodes a file with the browser, or returns null if the browser
// can't read it. It does NOT rely on createImageBitmap rejecting: a file with a
// missing or wrong type can also resolve to a degenerate 0x0 bitmap, which
// would sail through a bare try/catch and then fail further along as a blank
// photo. Both outcomes mean the same thing here — ask the backend.
async function tryBitmap(file) {
  try {
    const bm = await createImageBitmap(file);
    if (bm.width > 0 && bm.height > 0) return bm;
    if (bm.close) bm.close();
  } catch (_) { /* unreadable by the browser */ }
  return null;
}

// convertViaBackend posts the picked file to the Go decoder and gets back
// something the browser can definitely read. This is what makes RAW files,
// PSDs, TIFFs, HDRs and the rest pickable — the browser decodes four or five
// formats, the backend decodes dozens.
//
// Not routed through api(): the body is the raw file rather than JSON (a 90 MB
// RAW would become ~120 MB of base64, held in memory on both sides), the reply
// is image bytes rather than JSON, and a large RAW can take longer than the
// usual API timeout to walk.
async function convertViaBackend(file, maxDim) {
  const headers = {};
  if (controlToken) headers["X-Control-Token"] = controlToken;
  if (sessionToken) headers["Authorization"] = "Bearer " + sessionToken;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), IMAGE_DECODE_TIMEOUT_MS);
  let res;
  try {
    res = await fetch("/api/image/decode?max_dim=" + encodeURIComponent(maxDim || 4096),
      { method: "POST", headers, body: file, signal: ctrl.signal });
  } catch (e) {
    if (e && e.name === "AbortError") throw new Error("That file took too long to open — it may be very large.");
    throw new Error("Couldn't read that image.");
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    // The backend writes these messages for a human ("Canon CR2: no embedded
    // JPEG preview to extract…", "JPEG XL files can't be read on this device —
    // export the photo as JPEG"). Replacing them with a generic string would
    // throw away the only part the user can act on.
    let body = null;
    try { body = await res.json(); } catch (_) {}
    throw new Error((body && body.error) || "Couldn't read that image.");
  }
  const blob = await res.blob();
  return { file: blob, note: res.headers.get("X-Image-Note") || "" };
}

// decodeAnyImage turns whatever the user picked into { file, bitmap, note }:
// bytes the browser can read, an already-decoded bitmap for them, and a note
// describing anything surprising that happened on the way (chiefly that a RAW
// became the camera's own preview JPEG). The browser gets first refusal, so the
// common JPEG/PNG/WebP/HEIC-on-Android path is untouched and costs nothing.
async function decodeAnyImage(file, maxDim) {
  const direct = await tryBitmap(file);
  if (direct) return { file, bitmap: direct, note: "" };
  const conv = await convertViaBackend(file, maxDim);
  const bitmap = await tryBitmap(conv.file);
  if (!bitmap) throw new Error("Couldn't read that image.");
  return { file: conv.file, bitmap, note: conv.note };
}

// renderableImage is decodeAnyImage for callers that draw with an <img> instead
// of a bitmap — the avatar cropper does, so it needs the converted blob and not
// the probe bitmap.
async function renderableImage(file, maxDim) {
  const r = await decodeAnyImage(file, maxDim);
  if (r.bitmap && r.bitmap.close) r.bitmap.close();
  return { file: r.file, note: r.note };
}

// noteWorthTelling filters the backend's note down to the cases a user should
// hear about. "passed through unchanged" and "converted to image/jpeg" describe
// a conversion that lost nothing visible; a note mentioning a preview means the
// bytes being sent are the camera's rendering rather than the real image, which
// is a thing someone sending a RAW deserves to be told.
function noteWorthTelling(note) {
  return note && /preview/i.test(note) ? note : "";
}

// processImage returns { blob, mime, note } for a 1:1 photo. A GIF is passed
// through byte-for-byte (the backend allowlists image/gif) — re-encoding to
// JPEG would flatten an animated GIF to a single static frame. Everything else
// is decoded, downscaled and re-encoded to JPEG under the cap.
async function processImage(file) {
  if (file.type === "image/gif") {
    if (file.size > IMAGE_CAP_BYTES) throw new Error("That GIF is too large to send — a GIF can't be shrunk without losing the animation.");
    return { blob: file, mime: "image/gif" };
  }
  const { file: src, bitmap, note } = await decodeAnyImage(file, 1600);
  try {
    // Re-checked against the source actually in hand, not the original pick: a
    // converted file carries whatever type the decoder gave it.
    if (src.type === "image/gif") {
      if (src.size > IMAGE_CAP_BYTES) throw new Error("That GIF is too large to send — a GIF can't be shrunk without losing the animation.");
      return { blob: src, mime: "image/gif", note };
    }
    return { blob: await encodeScaled(bitmap, 1600, IMAGE_CAP_BYTES), mime: "image/jpeg", note };
  } finally { if (bitmap.close) bitmap.close(); }
}

// processGroupImage makes the two payloads a group image needs: the full image
// (a GIF passed through to keep its animation, otherwise a downscaled JPEG) and a
// tiny low-quality JPEG thumbnail that fans out inline as a blurry preview. The
// thumb is always JPEG — createImageBitmap on a GIF gives its first frame, which
// is all a static preview needs.
async function processGroupImage(file) {
  const { file: src, bitmap, note } = await decodeAnyImage(file, 1600);
  // As in processImage: the GIF question is about the bytes being sent, which
  // for a converted file are the decoder's, not the pick's.
  const gif = src.type === "image/gif";
  try {
    if (gif && src.size > IMAGE_CAP_BYTES) throw new Error("That GIF is too large to send — a GIF can't be shrunk without losing the animation.");
    const full = gif ? src : await encodeScaled(bitmap, 1600, IMAGE_CAP_BYTES);
    const thumb = await encodeScaled(bitmap, 96, GROUP_THUMB_CAP_BYTES, 0.5);
    return { full, fullMime: gif ? "image/gif" : "image/jpeg", thumb, thumbMime: "image/jpeg", note };
  } finally { if (bitmap.close) bitmap.close(); }
}

function blobToBase64(blob) {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = () => res(String(r.result).split(",")[1]);
    r.onerror = rej;
    r.readAsDataURL(blob);
  });
}

$("attach-btn").addEventListener("click", () => { if (chatKind === "contact" || chatKind === "group") $("image-input").click(); });
$("image-input").addEventListener("change", async (e) => {
  const file = e.target.files && e.target.files[0];
  e.target.value = ""; // allow re-picking the same file
  const toContact = chatKind === "contact" && currentPeer;
  const toGroup = chatKind === "group" && currentGroup;
  if (!file || (!toContact && !toGroup)) return;
  if (!torSendable) { $("send-error").textContent = "Still connecting to Tor — one moment, then you can send."; $("send-error").hidden = false; return; }
  $("send-error").hidden = true;
  const btn = $("attach-btn"); btn.setAttribute("disabled", "");
  try {
    let ok, body, note = "";
    if (toContact) {
      const r = await processImage(file);
      note = r.note || "";
      const b64 = await blobToBase64(r.blob);
      ({ ok, body } = await api("/api/messages/image", { method: "POST", body: JSON.stringify({ to: currentPeer, mime: r.mime, data: b64 }) }));
    } else {
      const { full, fullMime, thumb, thumbMime, note: n } = await processGroupImage(file);
      note = n || "";
      const [fullB64, thumbB64] = await Promise.all([blobToBase64(full), blobToBase64(thumb)]);
      ({ ok, body } = await api("/api/groups/image", { method: "POST", body: JSON.stringify({ group: currentGroup, full_mime: fullMime, full_data: fullB64, thumb_mime: thumbMime, thumb_data: thumbB64 }) }));
    }
    if (!ok) { $("send-error").textContent = (body && body.error) || "Couldn't send the photo."; $("send-error").hidden = false; }
    else {
      await loadMessages();
      // Said after the send, not before: nothing failed, but a RAW went out as
      // the camera's own preview and the sender should know which bytes landed.
      const n = noteWorthTelling(note);
      if (n) showToast("Sent — " + n + ".");
    }
  } catch (err) {
    $("send-error").textContent = (err && err.message) || "Couldn't send the photo.";
    $("send-error").hidden = false;
  } finally {
    btn.removeAttribute("disabled");
  }
});
// A tab going to the background (or the Activity being backgrounded) must not
// leave the camera running.
document.addEventListener("visibilitychange", () => { if (document.hidden) closeScan(); });
$("relay-offer-send").addEventListener("click", async () => {
  if (!relayOfferId || !relayOfferHolder) return;
  const id = relayOfferId, holder = relayOfferHolder, peer = currentPeer;
  $("relay-offer-send").disabled = true;
  const res = await api("/api/relay/send", { method: "POST", body: JSON.stringify({ id, holder }) });
  closeRelayOffer();
  await loadMessages();
  if (res.ok) { showMailboxNote(peer); return; }
  // If the message left the queue while the dialog was open — usually because
  // the direct send landed after all (presence was stale) — that's a success,
  // not a failure, so don't alarm the user. Only surface an error if it really
  // is still waiting to go.
  const m = messages.find((x) => x.id === id);
  if (m && (m.delivery === "pending" || m.delivery === "failed")) {
    $("send-error").textContent = (res.body && res.body.error) || "Relay failed.";
    $("send-error").hidden = false;
  }
});
let mailboxNote = null; // {peer} — transient "delivered to mailbox" note
let mailboxNoteTimer = null;
function showMailboxNote(peer) {
  mailboxNote = { peer };
  renderMessages();
  clearTimeout(mailboxNoteTimer);
  mailboxNoteTimer = setTimeout(() => { mailboxNote = null; renderMessages(); }, 6000);
}
$("messages").addEventListener("click", (e) => {
  const relay = e.target.closest("[data-relay-send]");
  if (relay) { openRelayOffer(relay.dataset.relaySend, currentPeer); return; }
  const chip = e.target.closest("[data-react-msg]");
  if (chip) { toggleReaction(chip.dataset.reactMsg, chip.dataset.reactEmoji); return; }
  const jump = e.target.closest("[data-jump-to]");
  if (jump && jump.dataset.jumpTo) { jumpToMessage(jump.dataset.jumpTo); return; }
  const el = e.target.closest("[data-retry]"); if (el) retrySend(el.dataset.retry);
});

// ========================= message actions (item 3) =========================
// Bubble content builders. Text goes in as a text node (so a reply-quote can
// sit above it); the quote and reaction chips are their own elements.
function textNode(text) { return document.createTextNode(text || ""); }
function quoteElement(rt) {
  // rt is m.reply_to = {id, preview, author}. The author label is direction-
  // relative to whoever composed the reply ("You" / their nickname for someone),
  // so it must NOT be trusted for display — we resolve it locally from the quoted
  // row, named by the shared wire id. When we don't hold that row, show no author.
  if (!rt) return null;
  const id = rt.id;
  // Scope the local lookup: in a group, only resolve against rows in THIS group, so
  // a quote id can never pull a preview/author from an unrelated conversation even
  // if a peer runs a patched client. (The backend scopes the id before signing too.)
  const src = id && messages.find((z) => z.id === id && (chatKind !== "group" || z.group_id === currentGroup));
  // Preview: the transmitted hint (rt.preview) is used for 1:1; group replies carry
  // no preview over the wire, so derive it locally from the quoted row when we hold
  // it (also keeps the quote in sync if the original was edited/is an image).
  let preview = rt.preview || "";
  if (!preview && src) preview = src.kind === "image" ? "📷 Photo" : (src.text || "");
  let author = "";
  if (src) author = src.direction === "out" ? "You" : (src.author_name || contactName(src.peer || src.author || ""));
  // Nothing to show (e.g. a group reply whose quoted row we don't hold): render no
  // quote rather than an empty bordered box, which would read as a rendering bug.
  if (!preview && !author) return null;
  const q = document.createElement("div");
  q.className = "bubble-quote";
  if (id) q.dataset.jumpTo = id;
  q.textContent = (author ? author + ": " : "") + preview;
  return q;
}
function reactionsElement(m) {
  const rs = m.reactions;
  if (!rs || !rs.length) return null;
  // The backend stores reactions raw as {emoji, by}; aggregate into chips here so
  // chatMessage stays a straight copy of chatstore.Message. Iterate in array order
  // (not object-key order) so chip order is stable across polls. "mine" is any
  // entry placed by our own account.
  const order = [];
  const agg = new Map();
  for (const r of rs) {
    if (r.removed) continue; // group un-react tombstone: kept for gossip LWW, never rendered
    let a = agg.get(r.emoji);
    if (!a) { a = { emoji: r.emoji, count: 0, mine: false }; agg.set(r.emoji, a); order.push(a); }
    a.count++;
    if (r.by === selfAccount) a.mine = true;
  }
  if (!order.length) return null; // all entries were tombstones — nothing live to show
  const wrap = document.createElement("div");
  wrap.className = "reactions";
  for (const r of order) {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "reaction-chip" + (r.mine ? " mine" : "");
    chip.dataset.reactMsg = m.id;
    chip.dataset.reactEmoji = r.emoji;
    const em = document.createElement("span"); em.textContent = r.emoji; chip.append(em);
    if (r.count > 1) { const c = document.createElement("span"); c.className = "count"; c.textContent = String(r.count); chip.append(c); }
    wrap.append(chip);
  }
  return wrap;
}
function jumpToMessage(id) {
  const row = $("messages").querySelector(`.bubble-row[data-msg-id="${CSS.escape(id)}"]`);
  if (row) { row.scrollIntoView({ behavior: "smooth", block: "center" }); row.classList.add("flash"); setTimeout(() => row.classList.remove("flash"), 900); }
}

// ---- the menu ----
let menuMsgId = null;
let msgMenuOpenedAt = 0;
let selectedBubbleRow = null;
let selectedMsgId = null; // persist across re-renders
let menuAnchorRect = null; // the selected bubble's rect, measured once at open time

// Position a floating popover relative to a message bubble with viewport clamping.
function positionPopover(el, anchorRect, opts = {}) {
  const { above = false, gap = 8 } = opts;
  const w = el.offsetWidth || el.scrollWidth || 200;
  const h = el.offsetHeight || el.scrollHeight || 200;
  let left, top;
  if (above) {
    // Reaction bar: centered horizontally over the bubble, above it
    left = anchorRect.left + anchorRect.width / 2 - w / 2;
    top = anchorRect.top - h - gap;
    // Flip below if no room above
    if (top < gap) top = anchorRect.bottom + gap;
  } else {
    // Context menu: left-aligned with bubble, below it
    left = anchorRect.left;
    top = anchorRect.bottom + gap;
    // Flip above if no room below
    if (top + h > window.innerHeight - gap) {
      top = anchorRect.top - h - gap;
    }
  }
  // Clamp horizontal to viewport
  left = Math.max(gap, Math.min(left, window.innerWidth - w - gap));
  top = Math.max(gap, Math.min(top, window.innerHeight - h - gap));
  el.style.left = left + "px";
  el.style.top = top + "px";
}

function openMsgMenu(id, x, y) {
  const m = messages.find((z) => z.id === id);
  if (!m) return;
  const row = document.querySelector(`[data-msg-id="${id}"]`);
  if (!row) return; // can't anchor a popover to a bubble that isn't rendered
  menuMsgId = id;
  msgMenuOpenedAt = performance.now();

  // Highlight the bubble (persists across re-renders via selectedMsgId).
  if (selectedBubbleRow) selectedBubbleRow.classList.remove("selected");
  selectedMsgId = id;
  selectedBubbleRow = row;
  row.classList.add("selected");

  // The bubble itself (not the full-width row) is what we anchor to and light up.
  const bubble = row.querySelector(".bubble") || row;
  // Only scroll when the bubble isn't comfortably in view — and then instantly,
  // so the very next getBoundingClientRect() is already at the settled position.
  // (A smooth scroll would animate for ~400ms, leaving every anchor measured
  // against the pre-scroll rect. One instant scroll = one source of truth.)
  const msgsRect = $("messages").getBoundingClientRect();
  const margin = 96;
  let rect = bubble.getBoundingClientRect();
  if (rect.top < msgsRect.top + margin || rect.bottom > msgsRect.bottom - margin) {
    bubble.scrollIntoView({ block: "center" });
    rect = bubble.getBoundingClientRect();
  }
  menuAnchorRect = rect;

  const menu = $("msg-menu");
  // Reply works in both 1:1 and group chats
  const replyOK = REPLY_REACT_ENABLED && (chatKind === "contact" || chatKind === "group");
  const inChat = chatKind === "contact" || chatKind === "group";
  menu.querySelector('[data-act="reply"]').hidden = !replyOK;
  menu.querySelector('[data-act="select"]').hidden = !inChat;
  // Copy only makes sense for text; an image bubble has none.
  menu.querySelector('[data-act="copy"]').hidden = m.kind === "image";
  // "Delete for me" is local-only, so it works on any message in any chat.
  menu.querySelector('[data-act="delete-me"]').hidden = !inChat;
  // "Delete for everyone" reaches the peer, so it's limited to a message we sent,
  // not yet delivered, in a 1:1 chat, still inside the recall window.
  const canDelete = m.direction === "out" && !m.delivery && chatKind === "contact" && withinDeleteWindow(m.at);
  menu.querySelector('[data-act="delete"]').hidden = !canDelete;

  // Show menu and reaction bar
  renderReactBar(id, false);
  menu.hidden = false;
  positionPopover(menu, rect, { above: false, gap: 8 });
  positionPopover($("react-bar"), rect, { above: true, gap: 8 });
  // On a short conversation the bar can flip to the same side as the menu and
  // overlap it; nudge the menu clear of the bar if their rects intersect.
  deConflictPopovers(menu, $("react-bar"), rect);

  // Lock scrolling while the menu is open
  $("messages").style.overflow = "hidden";
}

function renderReactBar(id, expanded) {
  const bar = $("react-bar");
  bar.innerHTML = "";
  bar.classList.toggle("expanded", !!expanded);
  const set = expanded ? REACTIONS_MORE : REACTIONS;
  for (const emoji of set) {
    const b = document.createElement("button");
    b.type = "button"; b.textContent = emoji;
    b.addEventListener("click", () => { closeMsgMenu(); toggleReaction(id, emoji); });
    bar.append(b);
  }
  if (!expanded) {
    // "+" reveals the extended custom-emoji grid in place.
    const more = document.createElement("button");
    more.type = "button"; more.className = "react-more"; more.textContent = "+";
    more.setAttribute("aria-label", "More reactions");
    more.addEventListener("click", () => {
      // Hide the context menu so the wide emoji grid has room and can't collide.
      $("msg-menu").hidden = true;
      renderReactBar(id, true);
      if (menuAnchorRect) positionPopover(bar, menuAnchorRect, { above: true, gap: 8 });
    });
    bar.append(more);
  }
  bar.hidden = false;
}

// If the two popovers overlap (the reaction bar flipped onto the menu's side on
// a short/edge-anchored conversation), move the menu to the bar's far side.
function deConflictPopovers(menu, bar, bubbleRect) {
  const m = menu.getBoundingClientRect(), b = bar.getBoundingClientRect();
  const overlap = !(m.right <= b.left || m.left >= b.right || m.bottom <= b.top || m.top >= b.bottom);
  if (!overlap) return;
  const gap = 8;
  // Bar above the bubble → stack menu above the bar; bar below → below the bar.
  let top = b.top < bubbleRect.top ? b.top - menu.offsetHeight - gap : b.bottom + gap;
  top = Math.max(gap, Math.min(top, window.innerHeight - menu.offsetHeight - gap));
  menu.style.top = top + "px";
}

// Size the spotlight cutout to the selected bubble; its box-shadow dims the rest.
// Position the spotlight cutout at the selected bubble's viewport coordinates.
// clip-path constrains the 9999px box-shadow to only the #messages area,
// so the sidebar, top bar, and compose bar stay bright.
// Close popovers. Clears the selection highlight unless keepSel is
// set (only the transient re-render path keeps it, re-applying it right after).
function closeMsgMenu(keepSel) {
  $("msg-menu").hidden = true;
  $("react-bar").hidden = true;
  $("react-bar").classList.remove("expanded");
  // Unlock scrolling
  $("messages").style.overflow = "";
  menuMsgId = null;
  menuAnchorRect = null;
  lpSwallowClick = false;
  if (!keepSel) {
    if (selectedBubbleRow) selectedBubbleRow.classList.remove("selected");
    selectedBubbleRow = null;
    selectedMsgId = null;
  }
}

// Menu item actions
$("msg-menu").addEventListener("click", (e) => {
  const item = e.target.closest(".msg-menu-item");
  if (!item) return;
  const id = menuMsgId, act = item.dataset.act;
  closeMsgMenu();
  const m = messages.find((z) => z.id === id);
  if (!m) return;
  if (act === "reply") startReply(m);
  else if (act === "forward") forwardMessage(m);
  else if (act === "delete") deleteForEveryone(id);
  else if (act === "delete-me") deleteLocal(id);
  else if (act === "select") startSelectionMode(id);
  else if (act === "copy") copyMessageText(m);
});
async function copyMessageText(m) {
  if (m.kind === "image" || !m.text) return;
  try { await navigator.clipboard.writeText(m.text); }
  catch (_) { /* clipboard denied — nothing better to fall back to here */ }
}
// Right-click (desktop) opens the menu.
$("messages").addEventListener("contextmenu", (e) => {
  const row = e.target.closest(".bubble-row");
  if (!row) return;
  e.preventDefault();
  openMsgMenu(row.dataset.msgId, e.clientX, e.clientY);
});
// Long-press (touch) opens the menu.
let lpTimer = null, lpStart = null, lpSwallowClick = false;
$("messages").addEventListener("pointerdown", (e) => {
  if (e.pointerType === "mouse") return;
  const row = e.target.closest(".bubble-row");
  if (!row) return;
  lpStart = { x: e.clientX, y: e.clientY, id: row.dataset.msgId };
  lpTimer = setTimeout(() => {
    lpTimer = null;
    if (lpStart) {
      try { navigator.vibrate && navigator.vibrate(10); } catch (_) {}
      // Swallow the click the finger-lift will fire, so a long-press on an image
      // bubble opens the menu without also opening the photo viewer underneath.
      lpSwallowClick = true;
      openMsgMenu(lpStart.id, lpStart.x, lpStart.y);
    }
  }, 500);
});
// Capture-phase: runs before the bubble/image click listeners, so it can cancel
// the post-long-press click before it reaches them.
$("messages").addEventListener("click", (e) => {
  if (lpSwallowClick) { lpSwallowClick = false; e.stopPropagation(); e.preventDefault(); }
}, true);
function cancelLongPress() { if (lpTimer) { clearTimeout(lpTimer); lpTimer = null; } lpStart = null; }
$("messages").addEventListener("pointermove", (e) => {
  if (lpStart && Math.hypot(e.clientX - lpStart.x, e.clientY - lpStart.y) > 10) cancelLongPress();
});
$("messages").addEventListener("pointerup", cancelLongPress);
$("messages").addEventListener("pointercancel", cancelLongPress);
// Any tap outside the popovers dismisses them and clears the highlight. This is
// the single dismissal path (the spotlight is pointer-events:none, so a tap over
// it lands on the backdrop, which counts as outside). The short open-guard stops
// the gesture that opened the menu from also closing it.
document.addEventListener("pointerdown", (e) => {
  if ($("msg-menu").hidden && $("react-bar").hidden && !selectMode) return; // nothing open
  if (performance.now() - msgMenuOpenedAt < 400) return;
  if (e.target.closest("#msg-menu") || e.target.closest("#react-bar")) return;
  // If in multi-select mode, tapping outside exits select mode — but a tap on a
  // message row must toggle that message's selection (handled on click at #messages),
  // so don't exit here or the pointerdown would cancel selectMode before the click.
  if (selectMode) {
    // A tap on a message row toggles its selection (#messages click handler);
    // a tap on the select bar itself runs that button (delete/forward/close).
    if (e.target.closest(".bubble-row") || e.target.closest("#select-bar")) return;
    exitSelectMode(); closeMsgMenu(); return;
  }
  closeMsgMenu();
}, true);

// ---- reactions ----
// Reply-with-context and reactions are live for both 1:1 and group chats.
const REPLY_REACT_ENABLED = true;
const REACTIONS = ["👍", "❤️", "😂", "😮", "😢", "😡"];
// Extended set revealed by the "+" custom-emoji button.
const REACTIONS_MORE = ["👍", "❤️", "😂", "😮", "😢", "😡", "🎉", "🔥", "😍", "🤔", "👀", "😅", "🙏", "💯", "😎", "👏", "🥳", "😭", "🤯", "✅", "❌", "💜", "⭐", "🚀"];
async function toggleReaction(id, emoji) {
  const m = messages.find((z) => z.id === id);
  if (!m) return;
  const url = m.group_id ? "/api/groups/react" : "/api/messages/react";
  const payload = m.group_id ? { group: m.group_id, id, emoji } : { id, emoji };
  const res = await api(url, { method: "POST", body: JSON.stringify(payload) });
  if (!res.ok) { $("send-error").textContent = (res.body && res.body.error) || "Couldn't react."; $("send-error").hidden = false; return; }
  await loadMessages();
}

// ---- reply ----
let replyTarget = null; // {id, preview, author}
function replyPreview(m) {
  if (m.kind === "image") return "Photo";
  return (m.text || "").slice(0, 120);
}
function startReply(m) {
  replyTarget = { id: m.id, preview: replyPreview(m), author: m.direction === "out" ? "You" : (m.author_name || contactName(m.peer || m.author || "")) };
  $("reply-context-text").textContent = (replyTarget.author ? replyTarget.author + ": " : "") + replyTarget.preview;
  $("reply-context").hidden = false;
  $("compose-text").focus();
}
function clearReply() {
  replyTarget = null;
  $("reply-context").hidden = true;
}
$("reply-context-cancel").addEventListener("click", clearReply);

// ---- forward ----
let pendingForward = null; // {kind:'text'|'image', text?, src?}
function forwardMessage(m) {
  if (m.kind === "image") {
    const src = imageURLs.get(m.attach_id) || imageURLs.get(m.id);
    if (!src) { $("send-error").textContent = "That photo isn't downloaded on this device yet."; $("send-error").hidden = false; return; }
    openForwardPicker({ kind: "image", src });
  } else {
    openForwardPicker({ kind: "text", text: m.text });
  }
}
// opts.title overrides the modal heading: the same picker serves "forward this
// message" and "send this shared photo", and calling the second one Forward
// would be a lie about where the photo came from.
//
// The picker is always a WhatsApp-style multi-select: tapping a chat ticks it
// and Send dispatches to all of them at once. It used to also have a single-tap
// mode that sent on the first tap; every caller wanted multi in the end, so the
// second mode is gone rather than left as an unused branch.
const forwardSelected = new Map(); // "type:id" -> target, in tap order
function forwardKey(t) { return t.type + ":" + t.id; }

function openForwardPicker(payload, opts = {}) {
  pendingForward = payload;
  forwardSelected.clear();
  $("forward-title").textContent = opts.title || "Forward to\u2026";
  const list = $("forward-list");
  list.innerHTML = "";
  list.setAttribute("aria-multiselectable", "true");
  const add = (label, icon, target) => {
    const b = document.createElement("button");
    b.type = "button"; b.className = "forward-item";
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "icon");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", icon); svg.append(use);
    const span = document.createElement("span"); span.className = "forward-label"; span.textContent = label;
    b.append(svg, span);
    // role=option + aria-selected is what makes the tick legible to a screen
    // reader; the listbox above is marked aria-multiselectable to match.
    b.setAttribute("role", "option");
    b.setAttribute("aria-selected", "false");
    const check = document.createElement("span");
    check.className = "forward-check";
    const csvg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    csvg.setAttribute("class", "icon");
    const cuse = document.createElementNS("http://www.w3.org/2000/svg", "use");
    cuse.setAttribute("href", "#ic-check"); csvg.append(cuse);
    check.append(csvg);
    b.append(check);
    b.addEventListener("click", () => toggleForwardTarget(b, target));
    list.append(b);
  };
  for (const c of contacts.filter((c) => c.status === "accepted")) {
    add(contactLabel(c), "#ic-person", { type: "contact", id: c.account });
  }
  for (const g of groups) {
    add(g.name || "Group", "#ic-group", { type: "group", id: g.id });
  }
  if (!list.children.length) {
    const p = document.createElement("p"); p.className = "body muted";
    p.textContent = opts.title ? "No chats to send to yet." : "No chats to forward to yet.";
    list.append(p);
  }
  updateForwardSend();
  $("forward-modal").hidden = false;
}

function toggleForwardTarget(btn, target) {
  const k = forwardKey(target);
  const on = !forwardSelected.has(k);
  if (on) forwardSelected.set(k, target); else forwardSelected.delete(k);
  btn.classList.toggle("selected", on);
  btn.setAttribute("aria-selected", on ? "true" : "false");
  updateForwardSend();
}

// The count goes in the button label so the number of recipients is visible
// without counting ticks, and Send is dead until at least one is chosen.
function updateForwardSend() {
  const btn = $("forward-send");
  if (!btn) return;
  const n = forwardSelected.size;
  btn.disabled = n === 0;
  btn.textContent = n ? "Send to " + n : "Send";
}

function closeForwardPicker() {
  $("forward-modal").hidden = true;
  pendingForward = null;
  forwardSelected.clear();
}
$("forward-cancel").addEventListener("click", closeForwardPicker);
$("forward-send").addEventListener("click", () => doForward([...forwardSelected.values()]));
$("forward-modal").addEventListener("click", (e) => { if (e.target === $("forward-modal")) closeForwardPicker(); });

// Sends the picked payload to every chosen chat. The expensive half — resizing
// and JPEG-encoding the photo — is done ONCE and the identical bytes are posted
// per recipient; doing it per target would re-encode the same image N times for
// no difference in the result.
async function doForward(targets) {
  const payload = pendingForward;
  closeForwardPicker();
  if (!payload || !targets.length) return;
  if (!torSendable) { forwardError("Still connecting to Tor — one moment, then you can send."); return; }

  let forContacts = null, forGroups = null, note = "";
  try {
    const blob = payload.kind === "text" ? null : (payload.blob || await (await fetch(payload.src)).blob());
    if (blob && targets.some((t) => t.type === "contact")) {
      const out = await processImage(blob);
      note = out.note || note;
      forContacts = { mime: out.mime, data: await blobToBase64(out.blob) };
    }
    // Groups need their own pair (full + thumbnail), so they get a second encode
    // — but still only one, however many groups were ticked.
    if (blob && targets.some((t) => t.type === "group")) {
      const { full, fullMime, thumb, thumbMime, note: n } = await processGroupImage(blob);
      note = n || note;
      const [fullB64, thumbB64] = await Promise.all([blobToBase64(full), blobToBase64(thumb)]);
      forGroups = { full_mime: fullMime, full_data: fullB64, thumb_mime: thumbMime, thumb_data: thumbB64 };
    }
  } catch (err) {
    forwardError((err && err.message) || "Couldn't send that.");
    return;
  }

  // Sequential, not Promise.all: each send dials a peer over Tor, and firing a
  // dozen circuits at once is how you get timeouts rather than speed.
  let sent = 0;
  let lastError = "";
  for (const t of targets) {
    try {
      let res;
      if (payload.kind === "text") {
        res = t.type === "contact"
          ? await api("/api/messages", { method: "POST", body: JSON.stringify({ to: t.id, text: payload.text }) })
          : await api("/api/groups/send", { method: "POST", body: JSON.stringify({ group: t.id, text: payload.text }) });
      } else if (t.type === "contact") {
        res = await api("/api/messages/image", { method: "POST", body: JSON.stringify(Object.assign({ to: t.id }, forContacts)) });
      } else {
        res = await api("/api/groups/image", { method: "POST", body: JSON.stringify(Object.assign({ group: t.id }, forGroups)) });
      }
      // api() resolves for a 4xx/5xx too, so an unchecked call would count a
      // rejected send as delivered.
      if (res && res.ok) sent++;
      else lastError = (res && res.body && res.body.error) || lastError;
    } catch (err) {
      lastError = (err && err.message) || lastError;
    }
  }

  const missed = targets.length - sent;
  // Folded into the success toast rather than raised as its own: showToast
  // replaces whatever is on screen, so a second call would eat the first.
  const n = noteWorthTelling(note);
  if (sent && !missed) {
    // One recipient behaves like the single-tap flow: drop into the chat so the
    // sent copy is visible. For several, there is no one chat to land in.
    if (targets.length === 1) {
      if (targets[0].type === "contact") openChat(targets[0].id); else openGroup(targets[0].id);
      if (n) showToast("Sent — " + n + ".");
    } else {
      showToast("Sent to " + sent + " chats" + (n ? " — " + n : "") + ".");
    }
  } else if (sent) {
    showToast("Sent to " + sent + " of " + targets.length + " — " + missed + " didn't go through.");
  } else {
    forwardError(lastError || "Couldn't send that.");
    return;
  }
  await loadMessages();
}

// The picker is reachable with no chat behind it (a photo shared in from
// another app), where #send-error — which lives inside the chat screen — would
// be written to an invisible element. Toast in that case.
function forwardError(msg) {
  $("send-error").textContent = msg;
  $("send-error").hidden = false;
  if ($("chat-screen").hidden) showToast(msg);
}

// ---- inbound share: an image handed to us by the device share sheet ----
// The shell parks the bytes natively and the page collects them here. The
// readiness check is the security boundary the feature turns on: while the lock
// screen (or the setup wizard) is up this returns without collecting, so the
// image stays behind the bridge, the contact list is never drawn, and the user
// has to unlock before there is anything to tap. Called from showUnlocked() —
// which is reached only with a live session — and from the onNewIntent nudge
// below, which can fire while locked and must be filtered by the same check.
// See android/app/src/main/java/org/molepipe/molepipe/SharedImage.kt.
function consumeSharedImage() {
  if (!isAndroid) return;
  if (!sessionToken || screens.unlocked.hidden) return;
  let raw = "";
  try { raw = window.AndroidShell?.takeSharedImage?.() || ""; } catch (_) { return; }
  if (!raw) return;
  let payload = null;
  try { payload = JSON.parse(raw); } catch (_) { return; }
  if (!payload || !payload.data) return;
  // A concrete image type is kept; anything else (the shell sends
  // application/octet-stream when neither the provider nor the sender named a
  // type, which is the normal case for a RAW out of a file manager) is left as
  // it is. It must NOT be relabelled "image/jpeg": processImage would then take
  // it for a readable JPEG, and the honest answer is "unknown — sniff it",
  // which is exactly what the decode fallback does with it.
  const mime = /^image\/[a-z0-9.+-]+$/.test(payload.mime || "") ? payload.mime : "application/octet-stream";
  let blob = null;
  try { blob = base64ToBlob(payload.data, mime); } catch (_) { showToast("Couldn't read that image."); return; }
  openForwardPicker({ kind: "image", blob }, { title: "Send photo to\u2026" });
}

// Decodes the bridge's base64 into a Blob. Deliberately not via a data: URL and
// fetch() — see the CSP note in doForward.
function base64ToBlob(b64, mime) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new Blob([bytes], { type: mime });
}

// Nudge from the shell when a share lands on an already-running app. A cold
// start has no page to nudge and is covered by showUnlocked()'s own pull.
window.onSharedImage = () => { consumeSharedImage(); };

// Delete for me: remove this copy from my own devices only. Unlike
// delete-for-everyone it never contacts the peer, so it works on any message —
// theirs or mine, any age.
async function deleteLocal(id) {
  const ok = await confirmDialog({
    title: "Delete for me?",
    message:
      "This removes the message from your devices only. It stays on everyone else's device, " +
      "and this cannot be undone.",
    confirmLabel: "Delete for me",
    danger: true,
  });
  if (!ok) return;
  const res = await api("/api/messages/delete", { method: "POST", body: JSON.stringify({ id, local: true }) });
  if (!res.ok) {
    const err = $("send-error");
    err.textContent = res.body.error || "Could not delete that message.";
    err.hidden = false;
    return;
  }
  await loadMessages();
}
// Enter multi-select mode starting from a given message.
// ---- multi-select mode ----
let selectMode = false;
let selectedMsgIds = new Set();

function enterSelectMode(id) {
  selectMode = true;
  selectedMsgIds.clear();
  selectedMsgIds.add(id);
  // Set contact context in the header
  const nameEl = $("select-name");
  const avatarEl = $("select-avatar");
  const peerName = chatKind === "group" ? groupName(currentGroup) : contactName(currentPeer);
  if (nameEl) nameEl.textContent = peerName || "";
  if (avatarEl) {
    const c = contacts.find((x) => x.account === currentPeer);
    avatarEl.replaceChildren(avatarNode(c && c.avatar_hash, peerName || "", null));
  }
  updateSelectBar();
  // Add .selecting class and checkboxes to all bubble rows
  document.querySelectorAll(".bubble-row").forEach((r) => {
    if (!r.dataset.msgId) return;
    r.classList.add("selecting");
    r.classList.toggle("selected", selectedMsgIds.has(r.dataset.msgId));
    // Add checkbox if not already present
    if (!r.querySelector(".select-check")) {
      const check = document.createElement("span");
      check.className = "select-check";
      r.appendChild(check);
    }
  });
}

function toggleSelect(id) {
  if (selectedMsgIds.has(id)) selectedMsgIds.delete(id);
  else selectedMsgIds.add(id);
  const row = document.querySelector(`[data-msg-id="${id}"]`);
  if (row) row.classList.toggle("selected", selectedMsgIds.has(id));
  updateSelectBar();
  if (selectedMsgIds.size === 0) exitSelectMode();
}

function exitSelectMode() {
  selectMode = false;
  selectedMsgIds.clear();
  $("select-bar").hidden = true;
  document.querySelectorAll(".bubble-row").forEach((r) => {
    r.classList.remove("selected");
    r.classList.remove("selecting");
    const check = r.querySelector(".select-check");
    if (check) check.remove();
  });
}

function updateSelectBar() {
  const bar = $("select-bar");
  const n = selectedMsgIds.size;
  bar.hidden = n === 0;
  $("select-count").textContent = n + " selected";
  // Disable delete if none are deletable
  const hasDeletable = [...selectedMsgIds].some((id) => {
    const m = messages.find((z) => z.id === id);
    return m && m.direction === "out" && !m.delivery && chatKind === "contact" && withinDeleteWindow(m.at);
  });
  $("select-delete").disabled = !hasDeletable;
}

function startSelectionMode(id) {
  closeMsgMenu();
  enterSelectMode(id);
}

// Selection bar button handlers
$("select-close").addEventListener("click", () => exitSelectMode());
$("select-forward").addEventListener("click", () => {
  if (selectedMsgIds.size === 0) return;
  // Forward all selected messages
  const first = messages.find((z) => z.id === [...selectedMsgIds][0]);
  if (first) forwardMessage(first);
  exitSelectMode();
});
$("select-delete").addEventListener("click", async () => {
  const ids = [...selectedMsgIds];
  if (ids.length === 0) return;
  const ok = await confirmDialog({
    title: `Delete ${ids.length} message${ids.length > 1 ? "s" : ""}?`,
    message: "This will remove the message" + (ids.length > 1 ? "s" : "") + " from your view. Other people may still see them.",
    confirmLabel: "Delete",
    danger: true,
  });
  if (!ok) return;
  for (const id of ids) await deleteForEveryone(id);
  exitSelectMode();
});

// Bubble click handler for select mode
$("messages").addEventListener("click", (e) => {
  if (!selectMode) return;
  const row = e.target.closest(".bubble-row");
  if (!row || !row.dataset.msgId) return;
  e.stopPropagation();
  toggleSelect(row.dataset.msgId);
}, true);

// request their client chooses to honour, not a guarantee — the confirmation
// says exactly that rather than implying the message is unrecoverable.
async function deleteForEveryone(id) {
  const ok = await confirmDialog({
    title: "Delete for everyone?",
    message:
      "This removes the message from your device and asks their app to remove it from their view. " +
      "That is not a guarantee: if they are offline they may never receive the request, and anyone who " +
      "already read or screenshotted it still has it.",
    confirmLabel: "Delete for everyone",
    danger: true,
  });
  if (!ok) return;
  const res = await api("/api/messages/delete", { method: "POST", body: JSON.stringify({ id }) });
  if (!res.ok) {
    const err = $("send-error");
    err.textContent = res.body.error || "Could not delete that message.";
    err.hidden = false;
    return;
  }
  if (res.body.reached === false) {
    const err = $("send-error");
    err.textContent = "Removed here, but we couldn't reach them — it may still be on their device.";
    err.hidden = false;
  }
  await loadMessages();
}

// Material text fields don't submit their form on Enter — wire it up.
function submitOnEnter(id) {
  const f = $(id); if (!f) return;
  f.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); f.closest("form")?.requestSubmit(); } });
}
["password", "pin", "compose-text", "find-account", "link-code-input", "create-password", "create-password2", "recover-password", "recover-mnemonic", "wiz-pin-new", "wiz-pin-confirm", "wiz-link-code", "view-phrase-password", "duress-password", "duress-code", "duress-code2"].forEach(submitOnEnter);

// Send button: disabled when compose box is empty
$("compose-text").addEventListener("input", () => {
  if (detailContent !== "chat") return;
  $("send-btn").disabled = !torSendable || !$("compose-text").value.trim();
  // Auto-resize the textarea (fallback for browsers without field-sizing: content).
  const el = $("compose-text");
  el.style.height = "auto";
  el.style.height = el.scrollHeight + "px";
});

// Smart hierarchical back navigation for Android back gesture / back button and Esc key
window.handleAndroidBack = function() {
  // The camera-scan overlay is the top-most modal and holds the camera live, so
  // back must tear it down before anything else.
  const scan = $("scan-overlay");
  if (scan && !scan.hidden) { closeScan(); return true; }
  // Message action menu / reaction bar — back tears the whole thing down.
  if (!$("msg-menu").hidden) { closeMsgMenu(); return true; }
  if (!$("forward-modal").hidden) { closeForwardPicker(); return true; }
  // A confirm dialog is the top-most interaction: back/Escape cancels it. It
  // sits above the image viewer because Remove-profile-picture opens a confirm
  // ON TOP of the viewer — checked after, back would have closed the viewer out
  // from under the question and left it hanging.
  if (confirmOpen()) { confirmResolver(false); return true; }
  // The avatar crop editor holds unsaved framing: back cancels the crop (and
  // resolves its promise) rather than falling through to the screen beneath.
  const crop = $("avatar-crop");
  if (crop && !crop.hidden) { closeAvatarCropper(null); return true; }
  const viewer = $("image-viewer");
  if (viewer && !viewer.hidden) { closeImageViewer(); return true; }
  // The search overlay is a full-screen view above the chat list — back closes it.
  const searchView = $("search-view");
  if (searchView && !searchView.hidden) { closeSearch(); return true; }
  // Fullscreen account-number view — back/Escape closes it.
  const acctFs = $("account-fs");
  if (acctFs && !acctFs.hidden) { closeAccountFs(); return true; }
  // Tor log bottom sheet — close it on back.
  const torLog = $("tor-log-dialog");
  if (torLog && torLog.open) { torLog.close(); return true; }
  // 0. A modal dialog takes back before anything else.
  const relayOffer = $("relay-offer");
  if (relayOffer && !relayOffer.hidden) { closeRelayOffer(); return true; }
  const phraseModal = $("confirm-phrase-modal");
  if (phraseModal && !phraseModal.hidden) { phraseModal.hidden = true; return true; }
  // 1. Close chat overflow menu if open
  const menu = $("chat-menu");
  if (menu && !menu.hidden) {
    menu.hidden = true;
    return true;
  }
  const gmenu = $("group-menu");
  if (gmenu && !gmenu.hidden) {
    gmenu.hidden = true;
    return true;
  }
  // 2. Close open sub-boxes and inline forms.
  const subBoxes = [
    { id: "edit-dialog", hide: () => { editDialogResolver && editDialogResolver(false); } },
    { id: "link-new-box", hide: () => $("link-new-box").hidden = true },
    { id: "link-existing-form", hide: () => $("link-existing-form").hidden = true },
    { id: "duress-wizard", hide: () => $("duress-wizard").hidden = true },
    { id: "wipe-form", hide: () => $("wipe-form").hidden = true },
  ];
  for (const box of subBoxes) {
    const el = $(box.id);
    if (el && !el.hidden) {
      box.hide();
      return true;
    }
  }
  // 2b. Onboarding wizard: back steps to the previous panel via WIZ_FLOW —
  // never the legacy sub-box teardown, which desynced wizStep and could wipe
  // the recovery phrase behind an open modal. From welcome, back exits the app.
  const noneView = $("view-none");
  if (noneView && !noneView.hidden) {
    const flow = WIZ_FLOW[wizStep];
    if (flow && flow.back) { wizGoTo(flow.back); return true; }
    return false; // on welcome (or a step with no back) — let the platform exit
  }
  // 2b. Multi-select is a chat-scoped mode, not a separate screen: back must exit
  // it (and keep the chat open) before it can fall through to closing the chat —
  // otherwise selection mode stays stuck active and reappears on reopening.
  if (selectMode) { exitSelectMode(); return true; }
  // 3. Close detail view (chat, add person, info) if active
  if (detailContent !== null) {
    backAction();
    return true;
  }
  // 4. Return to 'chats' tab if currently on 'requests' or 'you'
  if (typeof currentTab !== "undefined" && currentTab !== "chats") {
    setTab("chats");
    return true;
  }
  // 5. Nothing active to close -> return false to let platform exit/background
  return false;
};

window.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    window.handleAndroidBack();
  }
});

// ---------- soft-keyboard handling (WebView) ----------
// The Android side sets --kb via WindowInsets (see MainActivity.kt) and the
// CSS on #app uses padding-bottom: var(--kb) to keep the compose bar above the
// keyboard.  We do NOT try to detect keyboard height from JS here — on newer
// Android the visualViewport API does not shrink for the keyboard when
// adjustResize is active, so any JS computation would be wrong and overwrite
// the correct Kotlin-set value.
//
// Re-pin the message list when the keyboard opens.  --kb lands as an inline
// style on <html>, and setting a CSS custom property fires no resize/JS event,
// so #app's padding-bottom shrinks #messages with nothing to re-scroll it — the
// newest messages slide behind the keyboard and the reader has to scroll down by
// hand.  Watch the root's style attribute and, while the reader is pinned to the
// newest message, keep them pinned.  #app animates padding-bottom over ~0.18s, so
// re-pin every frame for a short window after the last --kb change rather than
// once: a single scroll drifts off the bottom as the list keeps shrinking, and a
// lone transitionend can be missed when the insets listener fires again mid-
// animation.
(function () {
  const root = document.documentElement;
  if (!root || typeof MutationObserver === "undefined") return;
  let running = false;
  let deadline = 0;
  let wantPin = false;
  function frame() {
    // Drive off the intent captured when the burst began, NOT live stickBottom:
    // our own re-pin fires a scroll event whose atBottom check can transiently read
    // false while the list is still shrinking mid-transition, which flips the global
    // and would stop us re-pinning halfway — leaving the newest messages cut off
    // (verified with a headless harness). The final settled pin restores the global.
    if (wantPin) scrollMessagesToBottom();
    if (performance.now() < deadline) { requestAnimationFrame(frame); return; }
    running = false;
    // Layout has settled; reconcile the global so the jump-to-bottom button state
    // matches reality (the mid-transition scroll events left it stale).
    if (wantPin) { stickBottom = atBottom($("messages")); updateScrollBtn(); }
  }
  function kick() {
    deadline = performance.now() + 260;
    if (running) return;
    // Only chase the bottom if the reader was already there — someone who has
    // scrolled up into history is left where they are.
    wantPin = detailContent === "chat" && stickBottom;
    if (!wantPin) return;
    running = true;
    requestAnimationFrame(frame);
  }
  new MutationObserver(kick).observe(root, { attributes: true, attributeFilter: ["style"] });
  // Legacy Android WebViews that DO resize the window for the keyboard fire a
  // real resize instead of touching --kb; re-pin there too.
  window.addEventListener("resize", kick);
})();

// ---------- scroll-to-bottom button positioning ----------
// The button sits above the compose bar.  Instead of a fixed bottom: 5.2rem
// that breaks when safe-area-inset adds height, we measure the compose bar
// each time it changes and pin the button just above it.
(function () {
  const btn = $("scroll-bottom-btn");
  const form = $("compose-form");
  if (!btn || !form) return;
  function reposition() {
    btn.style.bottom = (form.offsetHeight + 10) + "px";
  }
  reposition();
  // Recompute on resize (keyboard open/close changes compose height via --sab)
  window.addEventListener("resize", reposition);
  // Also observe the compose form for size changes (e.g. reply-context appears)
  if (typeof ResizeObserver !== "undefined") {
    new ResizeObserver(reposition).observe(form);
  }
})();

initTheme();
initNotifs();
// boot trades a one-time ?x= bootstrap token for the real one if that's how we
// were launched (cmd/server browser), then starts. Without a control token
// every /api call is refused (see controlToken above), so skip the doomed
// status probe and tell the user how to recover. Every failure path ends on a
// message, never on the silent "Loading…" placeholder.
function boot() {
  const retry = $("loading-retry");
  if (retry) retry.hidden = true;
  const msg = $("loading-msg");
  if (msg) msg.textContent = "Loading…";
  exchangeControlToken().then(() => {
    if (!controlToken) return showControlTokenError();
    // Android only: pick the session back up if the shell is still holding one
    // from before a WebView rebuild. Gated on isAndroid as well as the method so
    // the desktop and browser builds, served this same file, keep the strict
    // memory-only behaviour no matter what a future shell bridge is called.
    if (isAndroid && window.AndroidShell?.getSessionToken) {
      try { sessionToken = window.AndroidShell.getSessionToken() || null; } catch (_) {}
    }
    refresh();
  }).catch(() => showLoadingError("Couldn't reach the Molepipe backend."));
}
const loadingRetryBtn = $("loading-retry");
if (loadingRetryBtn) loadingRetryBtn.addEventListener("click", boot);
boot();


// ============================================================================
// Friend profile pane (#contact-info)
// ----------------------------------------------------------------------------
// A sub-screen of an open 1:1 chat, reached by tapping the contact's name or
// avatar in the chat header. It gathers the per-contact surfaces that had no
// home: shared media, in-conversation search, notification mute, the media
// auto-save policy, groups in common, and the existing block / clear actions.
//
// Media and search read the already-loaded `messages` array rather than calling
// the backend: the conversation is polled into memory anyway, so filtering it is
// free and stays correct as new messages land.
// ============================================================================

let ciAccount = null;      // account whose profile is open (null = pane closed)
let ciCommonGroups = [];   // groups we share with them, from /api/groups/common
let ciGroupsLoaded = false;

function ciContact() { return contacts.find((c) => c.account === ciAccount) || null; }

// ciConvo is every message in this 1:1 conversation, oldest first — the same
// filter renderMessages uses, so the pane can never disagree with the chat.
function ciConvo() {
  return messages.filter((m) => m.peer === ciAccount && !m.group_id);
}

// mediaAttachId resolves the attachment-store key for an image message.
// /api/messages sets attach_id ONLY on group images; a 1:1 image is keyed by the
// row id itself ("A 1:1 image renders by its row id, so it needs none of these"
// — handleListMessages). Reading m.attach_id alone yielded undefined for every
// 1:1 photo, so the grid fetched ?id=undefined and sat on a grey skeleton.
function mediaAttachId(m) { return m.attach_id || m.id; }

function openContactInfo() {
  if (!currentPeer || chatKind !== "contact") return;
  ciAccount = currentPeer;
  ciCommonGroups = [];
  ciGroupsLoaded = false;
  $("ci-search-input").value = "";
  $("ci-search-clear").hidden = true;
  $("ci-action-error").hidden = true;
  showDetail("contact-info");
  renderContactInfo();
  loadCommonGroups();
}

async function loadCommonGroups() {
  const acct = ciAccount;
  const { ok, body } = await api("/api/groups/common", {
    method: "POST", body: JSON.stringify({ account: acct }),
  });
  // The pane may have been closed or reopened on someone else while this was in
  // flight; a late response must not paint another contact's groups.
  if (!ok || acct !== ciAccount) return;
  ciCommonGroups = body.groups || [];
  ciGroupsLoaded = true;
  renderCiGroups();
}

function renderContactInfo() {
  if (!ciAccount) return;
  const c = ciContact();
  const name = contactName(ciAccount);
  const av = $("ci-avatar-btn");
  av.innerHTML = "";
  av.append(avatarNode(c && c.avatar_hash, name, null));
  av.disabled = !(c && c.avatar_hash); // no picture → nothing to open full screen
  $("ci-name").textContent = name;
  // With a nickname set, the hero shows it as the name and the peer's own
  // published name underneath, so "who did I rename?" is always answerable.
  const real = $("ci-realname");
  const published = (c && c.name) || "";
  const nicked = !!(c && c.nickname);
  real.hidden = !(nicked && published);
  real.textContent = nicked && published ? published : "";
  $("ci-nickname-btn").setAttribute("aria-label", nicked ? "Edit nickname for this contact" : "Add a nickname for this contact");
  const state = presenceFor(ciAccount);
  const pres = $("ci-presence");
  pres.textContent = "";
  pres.append(presenceDot(state), " " + (PRESENCE_LABEL[state] || ""));
  pres.className = "body muted presence-text-" + state;
  $("ci-account").textContent = ciAccount;
  renderCiSettings();
  renderCiMedia();
  renderCiSearch();
  renderCiGroups();
}

// ---- settings: mute + media auto-save ----

function renderCiSettings() {
  const c = ciContact();
  const muted = !!(c && c.muted);
  const sw = $("ci-mute-switch");
  if (sw.selected !== muted) sw.selected = muted;
  $("ci-mute-state").textContent = muted
    ? "Muted — messages still arrive, quietly"
    : "Notifications are on";

  const policy = (c && c.media_auto_save) || "default";
  $("contact-info").querySelectorAll(".ci-media-toggle .seg")
    .forEach((b) => b.classList.toggle("active", b.dataset.media === policy));
  const globalOn = !!myMediaAutoSave;
  $("ci-media-hint").textContent =
    policy === "on" ? "Photos from this chat are copied into your phone's gallery."
    : policy === "off" ? "Photos from this chat stay inside Molepipe."
    : globalOn
      ? "Following your default: photos are copied into your phone's gallery."
      : "Following your default: photos stay inside Molepipe.";
}

async function setCiSettings(patch) {
  const acct = ciAccount;
  const { ok } = await api("/api/contacts/settings", {
    method: "POST", body: JSON.stringify(Object.assign({ account: acct }, patch)),
  });
  if (!ok) {
    $("ci-action-error").textContent = "Couldn't save that setting.";
    $("ci-action-error").hidden = false;
    return false;
  }
  $("ci-action-error").hidden = true;
  await loadContacts();       // refresh the cached row the pane renders from
  if (ciAccount === acct) renderCiSettings();
  return true;
}

// ---- nickname ----

// The nickname is private to this device and the user's own linked devices: it is
// stored on our Contact record, never sent to the peer, and it survives them
// renaming themselves (their signed profile owns Contact.Name, which the nickname
// shadows rather than replaces). See chatstore.Contact.Nickname.
$("ci-nickname-btn").addEventListener("click", async () => {
  const c = ciContact();
  const current = (c && c.nickname) || "";
  const result = await editDialog({
    title: current ? "Edit nickname" : "Add a nickname",
    fields: [{ id: "nickname", label: "Nickname", type: "text" }],
    values: { nickname: current },
  });
  if (!result) return;
  const next = result.nickname.trim();
  if (next === current) return;
  // Spread, not .length: a string's length is UTF-16 units, so 33 emoji would
  // trip a 64 "character" check that the server (counting runes) would pass.
  if ([...next].length > 64) {
    $("ci-action-error").textContent = "That nickname is too long (64 characters max).";
    $("ci-action-error").hidden = false;
    return;
  }
  const acct = ciAccount;
  // An empty value clears the nickname — that is the "remove" path, so there is
  // no separate delete control to find.
  if (!(await setCiSettings({ nickname: next }))) return;
  if (ciAccount !== acct) return; // the user navigated away mid-save
  renderContactInfo();
  // Surfaces outside the pane that name this contact: the detail top bar, and
  // any quoted-reply authors in the chat sitting behind it. The lists were
  // already redrawn by loadContacts().
  $("detail-title").textContent = contactName(acct);
  if (currentPeer === acct) renderMessages();
  showToast(next ? "Nickname saved." : "Nickname removed.");
});

// ---- shared media ----

function renderCiMedia() {
  const grid = $("ci-media-grid");
  grid.innerHTML = "";
  // Newest first: a media panel is usually opened to find something recent.
  const shots = ciConvo().filter((m) => m.kind === "image").reverse();
  $("ci-media-empty").hidden = shots.length > 0;
  for (const m of shots) {
    const cell = document.createElement("button");
    cell.type = "button";
    cell.className = "ci-media-cell";
    cell.setAttribute("aria-label", "Photo from " + fmtTime(m.at));
    const img = document.createElement("img");
    img.alt = "";
    const aid = mediaAttachId(m);
    const cached = imageURLs.get(aid);
    if (cached) img.src = cached;
    else { img.classList.add("skeleton"); fetchImage(aid, img); }
    cell.append(img);
    cell.addEventListener("click", () => {
      if (img.src && !img.classList.contains("img-missing")) openImageViewer(img.src);
    });
    grid.append(cell);
  }
}

// ---- in-conversation search ----

function renderCiSearch() {
  const q = $("ci-search-input").value.trim().toLowerCase();
  const box = $("ci-search-results");
  box.innerHTML = "";
  $("ci-search-clear").hidden = q === "";
  if (!q) return;
  // Newest first, and capped: this renders synchronously on every keystroke, and
  // a long conversation would otherwise build thousands of nodes per character.
  const hits = ciConvo()
    .filter((m) => m.kind !== "image" && (m.text || "").toLowerCase().includes(q))
    .reverse();
  if (!hits.length) {
    const none = document.createElement("p");
    none.className = "body muted";
    none.textContent = "No messages match “" + $("ci-search-input").value.trim() + "”.";
    box.append(none);
    return;
  }
  for (const m of hits.slice(0, 50)) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "ci-hit";
    row.setAttribute("role", "listitem");
    const who = document.createElement("span");
    who.className = "label muted";
    who.textContent = (m.direction === "out" ? "You" : contactName(ciAccount)) + " · " + fmtTime(m.at);
    const txt = document.createElement("span");
    txt.className = "body ci-hit-text";
    txt.textContent = m.text || "";
    row.append(who, txt);
    row.addEventListener("click", () => jumpToMessage(m.id));
    box.append(row);
  }
  if (hits.length > 50) {
    const more = document.createElement("p");
    more.className = "label muted";
    more.textContent = hits.length - 50 + " more matches — keep typing to narrow it down.";
    box.append(more);
  }
}

// jumpToMessage returns to the chat and scrolls the hit into view, flashing it
// so the eye can find it in a wall of text.
function jumpToMessage(id) {
  showDetail("chat");
  renderMessages();
  requestAnimationFrame(() => {
    const row = $("messages").querySelector('[data-msg-id="' + CSS.escape(id) + '"]');
    if (!row) return;
    row.scrollIntoView({ block: "center" });
    row.classList.add("msg-flash");
    setTimeout(() => row.classList.remove("msg-flash"), 1600);
  });
}

// ---- groups in common ----

function renderCiGroups() {
  const box = $("ci-groups");
  box.innerHTML = "";
  $("ci-groups-empty").hidden = !ciGroupsLoaded || ciCommonGroups.length > 0;
  for (const g of ciCommonGroups) {
    const row = document.createElement("md-list-item");
    row.setAttribute("type", "button");
    const head = document.createElement("div");
    head.setAttribute("slot", "headline");
    head.textContent = g.name || "Group";
    const sub = document.createElement("div");
    sub.setAttribute("slot", "supporting-text");
    sub.textContent = g.member_count + (g.member_count === 1 ? " member" : " members");
    row.append(head, sub);
    row.addEventListener("click", () => openGroup(g.id));
    box.append(row);
  }
}

// ---- friend profile: wiring ----

// Tapping the contact's name or picture in the chat header opens their profile.
// Groups keep their existing "Group info & members" menu item, so this is gated
// on a 1:1 chat.
function ciHeaderTap() {
  if (detailContent === "chat" && chatKind === "contact" && currentPeer) openContactInfo();
}
$("detail-titles").addEventListener("click", ciHeaderTap);
$("detail-avatar").addEventListener("click", ciHeaderTap);

// The profile picture opens full screen in the viewer everything else uses.
$("ci-avatar-btn").addEventListener("click", async () => {
  const c = ciContact();
  if (!c || !c.avatar_hash) return;
  const url = await avatarObjectURL(c.avatar_hash);
  if (url) openImageViewer(url);
});

$("ci-search-input").addEventListener("input", renderCiSearch);
$("ci-search-clear").addEventListener("click", () => {
  const i = $("ci-search-input");
  i.value = "";
  renderCiSearch();
  i.focus();
});

$("ci-mute-switch").addEventListener("change", async (e) => {
  const want = e.target.selected;
  // Re-render from the server's answer rather than trusting the switch: if the
  // write fails the control must snap back, not sit there lying.
  if (!(await setCiSettings({ muted: want }))) renderCiSettings();
});

$("contact-info").querySelector(".ci-media-toggle").addEventListener("click", async (e) => {
  const b = e.target.closest(".seg");
  if (!b) return;
  if (!(await setCiSettings({ media_auto_save: b.dataset.media }))) renderCiSettings();
});

$("ci-clear-btn").addEventListener("click", async () => {
  const acct = ciAccount;
  const ok0 = await confirmDialog({
    title: "Clear this chat?",
    message: "Every message and photo in this conversation is removed from your devices. "
      + contactName(acct) + " keeps their copy, and you stay contacts.",
    confirmLabel: "Clear",
    danger: true,
  });
  if (!ok0) return;
  const { ok } = await api("/api/messages/clear", {
    method: "POST", body: JSON.stringify({ account: acct }),
  });
  if (!ok) {
    $("ci-action-error").textContent = "Couldn't clear this chat.";
    $("ci-action-error").hidden = false;
    return;
  }
  await loadMessages();
  renderContactInfo();
  showToast("Chat cleared");
});

// Block reuses the existing contact-menu flow (confirm → /api/contacts/block →
// back to the chat list) rather than duplicating it here.
$("ci-block-btn").addEventListener("click", () => {
  const menu = $("chat-menu");
  const btn = menu.querySelector('[data-action="block"]');
  if (btn) btn.click();
});

// ---- media auto-save on receipt ----

// effectiveMediaAutoSave resolves the per-contact override against the global
// default. The override is a tri-state string ("default"/"on"/"off") precisely
// so "inherit" stays distinguishable from "explicitly off".
function effectiveMediaAutoSave(account) {
  const c = contacts.find((x) => x.account === account);
  const p = (c && c.media_auto_save) || "default";
  if (p === "on") return true;
  if (p === "off") return false;
  return !!myMediaAutoSave;
}

// Image message ids we've already considered for auto-save. Seeded from the
// FIRST poll after unlock without saving anything: without that seed, unlocking
// would dump the entire conversation backlog into the phone's gallery — the
// exact outcome someone who turns this on for one contact is not asking for.
const mediaSaveSeen = new Set();
let mediaSaveSeeded = false;

async function autoSaveNewMedia() {
  const inbound = messages.filter((m) => m.kind === "image" && m.direction === "in" && !m.group_id);
  if (!mediaSaveSeeded) {
    for (const m of inbound) mediaSaveSeen.add(m.id);
    mediaSaveSeeded = true;
    return;
  }
  if (!window.AndroidShell || !window.AndroidShell.saveImageToGallery) return;
  for (const m of inbound) {
    if (mediaSaveSeen.has(m.id)) continue;
    mediaSaveSeen.add(m.id); // mark first: a failure must not retry every poll
    if (!effectiveMediaAutoSave(m.peer)) continue;
    try {
      const res = await fetch("/api/attachment?id=" + encodeURIComponent(mediaAttachId(m)), {
        headers: { Authorization: "Bearer " + sessionToken, "X-Control-Token": controlToken },
      });
      if (!res.ok) continue;
      const blob = await res.blob();
      window.AndroidShell.saveImageToGallery(await blobToBase64(blob), blob.type || "image/jpeg");
    } catch (_) { /* a failed save is not worth interrupting the chat for */ }
  }
}

// ---- global media auto-save toggle (You > Notifications) ----

// Android-only: the desktop/browser build has no gallery to copy into, and the
// native bridge it would call does not exist there.
function syncMediaSaveSection() {
  const sec = $("media-save-section");
  if (!sec) return;
  const supported = !!(window.AndroidShell && window.AndroidShell.saveImageToGallery);
  sec.hidden = !supported;
  if (!supported) return;
  const sw = $("media-save-switch");
  if (sw.selected !== myMediaAutoSave) sw.selected = myMediaAutoSave;
  $("media-save-state").textContent = myMediaAutoSave
    ? "On — photos are copied to your gallery"
    : "Off — photos stay inside Molepipe";
}

$("media-save-switch").addEventListener("change", async (e) => {
  const want = e.target.selected;
  const { ok, body } = await api("/api/profile", {
    method: "POST", body: JSON.stringify({ media_auto_save: want }),
  });
  // Trust the server's echo, not the switch: a failed write must not leave the
  // UI claiming photos are staying private when the backend disagrees.
  myMediaAutoSave = ok ? !!body.media_auto_save : myMediaAutoSave;
  syncMediaSaveSection();
  if (detailContent === "contact-info") renderCiSettings();
  if (!ok) showToast("Couldn't save that setting");
});
