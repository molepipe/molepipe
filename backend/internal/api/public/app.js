"use strict";

// Session token lives in memory only (not localStorage) so it disappears when
// the tab closes. Theme prefs are non-sensitive and do use localStorage.
let sessionToken = null;
let myName = "";
let myMailbox = "";
let myBackupBytes = 0; // group-image backup budget in bytes (0 = off)
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
const TOR_STALLED_MS = 45000; // connecting longer than this => "still connecting, check your network"
let torStallHint = "";     // last Arti log line, fetched on first stall detection
let appVersionInfo = null;  // cached /api/version (build metadata for the diagnostics snapshot)
let deviceRoleText = "";    // "primary"|"secondary" cached from loadDevices, for diagnostics
let lookupResult = null;
let currentTab = "chats";
let detailContent = null; // null | "chat" | "add" | "info" | "group-info"
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
async function api(path, options = {}) {
  const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
  if (controlToken) headers["X-Control-Token"] = controlToken;
  if (sessionToken) headers["Authorization"] = "Bearer " + sessionToken;
  const res = await fetch(path, Object.assign({}, options, { headers }));
  let body = {};
  try { body = await res.json(); } catch (_) {}
  return { ok: res.ok, status: res.status, body };
}

// ---------- confirm dialog ----------
// A promise-based modal confirmation. Every consequential action awaits this, so
// the warning is always an explicit popup the user must acknowledge — replacing
// the native window.confirm and the old "text that quietly expands below". Pass
// danger:true to paint the confirm button in the error colour for destructive
// actions. Resolves true on confirm, false on cancel / backdrop / Escape.
let confirmResolver = null;
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
  modal.hidden = false;
  setTimeout(() => cancel.focus(), 0);
  return new Promise((resolve) => {
    confirmResolver = (result) => {
      modal.hidden = true;
      confirmResolver = null;
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
function editDialog({ title, fields = [], values = {}, passwordFirst = false }) {
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
  // Error placeholder
  const errEl = document.createElement("p");
  errEl.className = "label error"; errEl.hidden = true;
  wrap.append(errEl);
  $("edit-dialog").hidden = false;
  $("bottomnav").hidden = true;
  // Focus first field
  setTimeout(() => { const first = wrap.querySelector("md-outlined-text-field"); if (first) first.focus(); }, 50);
  return new Promise((resolve) => {
    editDialogResolver = (result) => {
      $("edit-dialog").hidden = true;
      // Restore bottom nav (may have been hidden for the dialog overlay).
      const isWideD = window.matchMedia("(min-width: 900px)").matches;
      $("bottomnav").hidden = detailContent !== null && !isWideD;
      editDialogResolver = null;
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
// Subtle haptic tick where the platform has a vibrator; a silent no-op on
// desktop and in the headless harness. Guarded exactly like the long-press site.
function haptic(ms = 10) {
  try { navigator.vibrate && navigator.vibrate(ms); } catch (_) {}
}

const shortAccount = (a) => (a.length > 18 ? a.slice(0, 8) + "…" + a.slice(-6) : a);
function contactName(account) {
  const c = contacts.find((c) => c.account === account);
  return c && c.name ? c.name : shortAccount(account);
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
  const { ok, status, body } = await api("/api/status");
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

// showControlTokenError parks the app on a clear "reopen me from the app"
// message. Used when we boot without a usable control token (see refresh).
function showControlTokenError() {
  const el = $("loading");
  if (el) {
    el.textContent =
      "This page must be opened from the Molepipe app. Please relaunch the app to continue.";
  }
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
  backBtn.innerHTML = '<svg class="icon"><use href="#ic-back"/></svg>';
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

// Render an onion address with its first and last 4 base32 chars emphasized and
// the middle dimmed. Onion addresses are opaque high-entropy strings with no
// internal field structure, so we don't chunk them — the only check people do is
// comparing the leading/trailing chars against a known-good copy, and emphasis
// points the eye straight at those. The raw address is stashed in dataset.full;
// the Copy handler reads ONLY that, so this visual markup can't corrupt the copy.
function renderOnionAddress(el, full) {
  el.dataset.full = full;
  el.textContent = "";
  const dot = full.toLowerCase().lastIndexOf(".onion");
  const body = dot >= 0 ? full.slice(0, dot) : full;
  const tld = dot >= 0 ? full.slice(dot) : "";
  const add = (text, cls) => {
    if (!text) return;
    const s = document.createElement("span");
    s.className = cls; s.textContent = text; el.appendChild(s);
  };
  if (body.length > 8) {
    add(body.slice(0, 4), "addr-hi");
    add(body.slice(4, -4), "addr-mid");
    add(body.slice(-4), "addr-hi");
  } else {
    add(body, "addr-hi");
  }
  add(tld, "addr-tld");
}

async function showUnlocked() {
  const { ok, body } = await api("/api/identity");
  if (!ok) { sessionToken = null; return show("locked"); }
  renderOnionAddress($("account"), body.account_number);
  selfAccount = body.account_number;
  updateTor(body);
  show("unlocked");
  setTab("chats");
  await Promise.all([loadProfile(), loadContacts(), loadGroups(), loadRequests(), loadGroupInvites(), loadMessages(), loadDesktop()]);
  poll();
}

// ---------- navigation ----------
// showDetail controls the detail pane (chat / add / contact-info / placeholder).
// On mobile the detail pane overlays the sidebar; on desktop it's the right pane.
function showDetail(kind) {
  detailContent = kind;
  $("detail-placeholder").hidden = kind !== null;
  $("chat-screen").hidden = kind !== "chat";
  $("add-screen").hidden = kind !== "add";
  $("contact-info").hidden = kind !== "info";
  $("group-info").hidden = kind !== "group-info";
  $("chat-menu").hidden = true;
  $("group-menu").hidden = true;
  // The overflow menu is a contact menu for a 1:1 chat and a group menu for a
  // group chat; only the relevant one is reachable.
  $("chat-menu-btn").hidden = kind !== "chat";
  $("back-btn").hidden = kind === null;
  $("shell").classList.toggle("detail-open", kind !== null);
  // Hide bottom nav when a detail pane overlays the sidebar (mobile only;
  // on desktop the two panes sit side-by-side and bottomnav is always visible).
  const isWide = window.matchMedia("(min-width: 900px)").matches;
  $("bottomnav").hidden = kind !== null && !isWide;
  $("detail-title").textContent =
    kind === "chat" ? (chatKind === "group" ? groupName(currentGroup) : contactName(currentPeer)) :
    kind === "add" ? (currentAddMode === "group" ? "New group" : "Message someone") :
    kind === "info" ? "Account number" :
    kind === "group-info" ? "Group info" : "";
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
  $("fab-add").hidden = tab !== "chats";
  $("search-btn").hidden = tab !== "chats";
  if ($("header-gap")) $("header-gap").hidden = tab !== "chats";
  $("sidebar-title").textContent = TABS[tab];
  for (const t of ["chats", "requests", "you"]) $("tab-" + t).hidden = t !== tab;
  document.querySelectorAll(".navitem").forEach((n) => n.classList.toggle("active", n.dataset.tab === tab));
  if (tab === "you") { showYouPane(youPane); loadDevices(); loadPinState(); loadWipeState(); }
}
// You-tab sub-navigation: show one pane's wrappers, hide the rest. Toggles a
// class (not `hidden`), so cards keep their own hidden state within a pane.
// The last-shown pane is remembered so returning to the You tab lands where the
// user left off (a deep-link like "Share my code" overrides it explicitly).
let youPane = "profile";
function showYouPane(pane) {
  youPane = pane;
  document.querySelectorAll("#tab-you .you-tab").forEach((t) => t.classList.toggle("active", t.dataset.pane === pane));
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
function openContactInfo() {
  $("contact-info-account").textContent = currentPeer;
  showDetail("info");
}
function backAction() {
  // Info / group-info are sub-screens of an open chat: back returns to it.
  if (detailContent === "info" || detailContent === "group-info") { showDetail("chat"); return; }
  leaveChatRead(); // final read before we drop the chat, so it can't re-badge (item 4)
  currentPeer = null;
  currentGroup = null;
  chatKind = null;
  showDetail(null);
}

// ---------- data ----------
function updateTor(body) {
  torReady = !!(body.tor_enabled && body.tor_ready);
  // Older backends don't report tor_sendable; fall back to tor_ready so the
  // button isn't wedged on a mismatched pair. Newer backends set it true as
  // soon as outbound circuits are up — before the descriptor is published.
  const prevSendable = torSendable;
  torSendable = !!(body.tor_enabled && (body.tor_sendable ?? body.tor_ready));
  torBootstrapFrac = body.tor_bootstrap_frac ?? 0;
  torHsState = body.tor_hs_state ?? "";
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
    else if (body.tor_ready) el.textContent = "Onion service: online \u2014 reachable over Tor \u2713";
    // Bootstrapped enough to send, but our address isn't on the network yet:
    // you can message people now; their replies land once publishing finishes.
    else if (torSendable) el.textContent = "Onion service: publishing your address\u2026 you can send now; replies arrive once it's online";
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
    let state, label;
    if (!body.tor_enabled) {
      state = "offline"; label = "Offline";
    } else if (torHsState === "running") {
      state = "online"; label = "Online";
    } else if (torHsState === "publishing") {
      state = "connecting"; label = "Publishing\u2026";
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
    pill.className = "tor-pill " + state;
    const labelEl = pill.querySelector(".pill-label");
    if (labelEl) labelEl.textContent = label;
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
function poll() {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(async () => {
    if (!sessionToken) return;
    const { ok, status, body } = await api("/api/identity");
    // The session can be ended from outside this page: another tab locking, or
    // the desktop build's tray "Lock". Left unhandled, polling would stop and
    // the window would keep showing a conversation list for an account that is
    // locked and offline — so fall back to the lock screen when the token dies.
    if (status === 401) { sessionToken = null; return showLockScreen(); }
    if (!ok) return;
    updateTor(body);
    await Promise.all([loadProfile(), loadContacts(), loadGroups(), loadRequests(), loadGroupInvites(), loadMessages(), loadDesktop()]);
    reconcileOpenChatRead(); // after all loads, so contacts/groups are the fresh server copy
    poll();
  }, 2500);
}

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
  renderBackupState();
}

// renderMyAvatar paints the settings avatar from my own hash (cache-busted so a
// just-changed picture updates immediately rather than showing the cached image
// at the old hash — the hash IS the version, so a new hash is a new URL anyway,
// but this also refreshes after a Remove+re-add to the same bytes) and shows the
// Remove button only when a picture is set.
function renderMyAvatar() {
  const box = $("my-avatar");
  if (box) { box.innerHTML = ""; box.append(avatarNode(myAvatarHash, myName, null)); }
  const rm = $("avatar-remove-btn");
  if (rm) rm.hidden = !myAvatarHash;
}

// AVATAR_CAP_BYTES mirrors the backend's protocol.MaxAvatarBytes (64 KiB). The
// crop below almost always lands well under it; the loop drops quality if not.
const AVATAR_CAP_BYTES = 64 * 1024;

// processAvatar center-crops the chosen image to a square and downscales it to a
// small JPEG under the cap. All image work happens here in the client — the Go
// backend never decodes images (it's gomobile-portable), it only validates the
// type and size and stores the bytes.
async function processAvatar(file) {
  let bitmap;
  try { bitmap = await createImageBitmap(file); }
  catch (_) { throw new Error("Couldn't read that image."); }
  try {
    const side = Math.min(bitmap.width, bitmap.height);
    const sx = (bitmap.width - side) / 2, sy = (bitmap.height - side) / 2;
    const dim = Math.min(256, side); // 256px square is plenty for an avatar
    const canvas = document.createElement("canvas");
    canvas.width = dim; canvas.height = dim;
    canvas.getContext("2d").drawImage(bitmap, sx, sy, side, side, 0, 0, dim, dim);
    const toBlob = (q) => new Promise((res) => canvas.toBlob(res, "image/jpeg", q));
    let q = 0.85, blob = await toBlob(q);
    while (blob && blob.size > AVATAR_CAP_BYTES && q > 0.3) { q -= 0.15; blob = await toBlob(q); }
    if (!blob || blob.size > AVATAR_CAP_BYTES) throw new Error("That image is too large, even compressed.");
    return blob;
  } finally { if (bitmap.close) bitmap.close(); }
}

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
  renderContacts();
}
async function loadGroups() {
  const { ok, body } = await api("/api/groups");
  if (!ok) return;
  groups = body.groups || [];
  renderContacts();
  if (detailContent === "group-info") renderGroupInfo();
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
  const head = document.createElement("div");
  head.setAttribute("slot", "headline");
  const badge = document.createElement("span");
  badge.className = "group-avatar";
  badge.innerHTML = '<svg class="icon"><use href="#ic-group"/></svg>';
  head.append(badge, " ", g.name || "Group");
  const sub = document.createElement("div");
  sub.setAttribute("slot", "supporting-text");
  sub.textContent = lastGroupPreview(g.id) || (g.member_count + (g.member_count === 1 ? " member" : " members"));
  item.append(head, sub);
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
    const head = document.createElement("div");
    head.setAttribute("slot", "headline");
    head.className = "contact-headline";
    // Avatar leads the row (picture or initials), with the presence dot overlaid
    // on its corner for accepted contacts. Pending contacts show no presence.
    head.append(avatarNode(c.avatar_hash, c.name || shortAccount(c.account), accepted ? c.presence : null), " ");
    head.append(c.name || shortAccount(c.account));
    const sub = document.createElement("div");
    sub.setAttribute("slot", "supporting-text");
    // awaiting_accept means we accepted them but the message telling them so
    // hasn't reached them yet — from their side we're still just "pending", and
    // they can't message us until it lands. Say so rather than looking done.
    if (accepted && c.awaiting_accept) sub.textContent = "Accepted · still trying to tell them — they can't reply yet";
    else sub.textContent = accepted ? (lastMsgPreview(c.account) || "No messages yet") : "Request sent · waiting for them to accept";
    item.append(head, sub);

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
  $("no-contacts").hidden = orderedConversations().length > 0;
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
  const head = document.createElement("div");
  head.setAttribute("slot", "headline");
  head.className = "contact-headline";
  const name = c.name || shortAccount(c.account);
  head.append(avatarNode(c.avatar_hash, name, c.presence), " ", name);
  const sub = document.createElement("div");
  sub.setAttribute("slot", "supporting-text");
  sub.textContent = lastMsgPreview(c.account) || shortAccount(c.account);
  item.append(head, sub);
  return item;
}
// Names-only match: a contact's display name OR account number; a group's name.
function convMatches(it, q) {
  if (it.kind === "group") return (it.g.name || "Group").toLowerCase().includes(q);
  const c = it.c;
  return (c.name || "").toLowerCase().includes(q) || c.account.toLowerCase().includes(q);
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
}
function openSearch() {
  $("search-view").hidden = false;
  const i = $("search-input");
  i.value = "";
  renderSearchResults("");
  i.focus();
}
function closeSearch() { $("search-input").blur(); $("search-view").hidden = true; }

function renderRequests() {
  // Browser notification for new friend requests (desktop only; Android uses JNI callbacks).
  if (requests.length > prevRequestCount && prevRequestCount > 0 && "Notification" in window && Notification.permission === "granted") {
    const newReq = requests[requests.length - 1];
    new Notification("Friend request", { body: (newReq.name || "Someone") + " wants to connect with you" });
  }
  prevRequestCount = requests.length;
  const list = $("requests-list");
  list.innerHTML = "";
  for (const r of requests) {
    const row = document.createElement("div");
    row.className = "request-row";
    const info = document.createElement("div");
    const name = document.createElement("div"); name.className = "body"; name.textContent = r.name || "(no name)";
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
    const name = document.createElement("div"); name.className = "body"; name.textContent = c.name || shortAccount(c.account);
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
  for (const m of convo) {
    const row = document.createElement("div");
    row.className = "bubble-row " + (m.direction === "out" ? "out" : "in");
    row.dataset.msgId = m.id;
    const b = document.createElement("div");
    b.className = "bubble " + (m.direction === "out" ? "out" : "in") + (m.delivery === "failed" ? " failed" : "");
    if (m.reply_to) b.append(quoteElement(m.reply_to));
    if (m.kind === "image") { b.classList.add("image"); b.append(imageElement(m.id)); }
    else b.append(textNode(m.text));
    const t = document.createElement("div");
    t.className = "bubble-time";
    t.textContent = fmtTime(m.at);
    row.append(b, t);
    const rx = reactionsElement(m);
    if (rx) row.append(rx);

    // Delivery state is the backend's, read straight off the message.
    if (m.direction === "out" && m.delivery) {
      const status = document.createElement("div");
      status.className = "msg-status" + (m.delivery === "failed" ? " error" : "");
      if (m.delivery === "failed") {
        status.textContent = "Not delivered — " + (m.error || "couldn't send") + " · tap to retry";
        status.dataset.retry = m.id;
        status.style.cursor = "pointer";
      } else {
        status.textContent = "Sending…";
      }
      row.append(status);
      if (m.delivery === "failed" && m.relay_available) {
        const relay = document.createElement("button");
        relay.className = "relay-offer";
        relay.textContent = "Still trying — send via a friend's relay?";
        relay.dataset.relaySend = m.id;
        row.append(relay);
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
  let lastAuthor = null;
  for (const m of convo) {
    const out = m.direction === "out";
    const row = document.createElement("div");
    row.className = "bubble-row " + (out ? "out" : "in");
    row.dataset.msgId = m.id;
    if (!out && m.author !== lastAuthor) {
      const who = document.createElement("div");
      who.className = "bubble-author label muted";
      who.textContent = m.author_name || shortAccount(m.author || "");
      row.append(who);
    }
    const b = document.createElement("div");
    b.className = "bubble " + (out ? "out" : "in");
    if (m.reply_to) b.append(quoteElement(m.reply_to));
    if (m.kind === "image") { b.classList.add("image"); b.append(groupImageElement(m)); }
    else b.append(textNode(m.text));
    const t = document.createElement("div");
    t.className = "bubble-time";
    t.textContent = fmtTime(m.at);
    row.append(b, t);
    const rx = reactionsElement(m);
    if (rx) row.append(rx);
    box.append(row);
    lastAuthor = out ? null : m.author;
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
  else if (id.tor_sendable) reach = "publishing — can send, address not yet published";
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
    "Onion:    " + (id.tor_hs_state || "unknown") + " · bootstrap " + frac + "% · sendable=" + !!id.tor_sendable + " · reachable=" + !!id.tor_ready,
    "Reach:    " + reach,
  ].join("\n");
}

let diagPollTimer = null;

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

$("tor-pill").addEventListener("click", openDiagnostics);
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
  const b = $("view-phrase-copy"); b.textContent = "Copied!"; setTimeout(() => { b.textContent = "Copy"; }, 2000);
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
  const fb = $("diag-copy-feedback"); fb.hidden = false; setTimeout(() => { fb.hidden = true; }, 1500);
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
$("empty-paste-btn").addEventListener("click", () => {
  openAdd();
  setTimeout(() => $("find-account").focus(), 100);
});
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
  const acct = currentPeer;
  if (btn.dataset.action === "view") { openContactInfo(); return; }
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
$("contact-info-copy").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText(currentPeer); } catch (_) {}
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
  sessionToken = body.session_token;
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
  if (ok) { sessionToken = body.session_token; return showUnlocked(); }

  if (isAndroid && pinEnabled) {
    renderPinKeypad(); // Scramble keypad numbers on failed attempt
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
  if (status === 429) {
    err.textContent = "Too many attempts. Try again in " + (body.retry_after || 0) + "s, or use your password.";
  } else {
    const left = body.attempts_left;
    err.textContent = (body.error || "Incorrect PIN.") +
      (typeof left === "number" ? " " + left + " attempt" + (left === 1 ? "" : "s") + " left before PIN unlock is removed." : "");
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
  if (pinEnabled) $("edit-dialog").hidden = true;
}
$("edit-pin-btn").addEventListener("click", async () => {
  const result = await editDialog({
    title: "Set up PIN unlock",
    passwordFirst: true,
    fields: [
      { id: "pin", label: "New PIN (6+ digits)", type: "password", inputmode: "numeric" },
      { id: "pin2", label: "Confirm PIN", type: "password", inputmode: "numeric" },
    ],
  });
  if (!result) return;
  const password = result.password, code = result.pin;
  if (code !== result.pin2) return; // PINs don't match
  const { ok, body } = await api("/api/security", { method: "POST", body: JSON.stringify({ action: "pin-enable", password, code }) });
  if (!ok) {
    // Show error in the dialog — reopen with error message
    await editDialog({ title: "Set up PIN unlock", fields: [{ id: "_err", label: body.error || "Could not turn on PIN unlock.", type: "text" }] });
    return;
  }
  pinEnabled = true;
  renderPinState();
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
  sessionToken = null;
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
  // Prompt for password to confirm the destructive action.
  const password = window.prompt("Enter your password to confirm:");
  if (!password) return;
  const { ok: success, body } = await api("/api/delete-identity", {
    method: "POST",
    body: JSON.stringify({ password }),
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
    const btn = $("phrase-copy");
    btn.textContent = "Copied!";
    setTimeout(() => { btn.textContent = "Copy"; }, 2000);
  } catch {
    // Fallback for non-HTTPS contexts.
    const ta = document.createElement("textarea");
    ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    document.execCommand("copy"); document.body.removeChild(ta);
    const btn = $("phrase-copy");
    btn.textContent = "Copied!";
    setTimeout(() => { btn.textContent = "Copy"; }, 2000);
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
// Explainer panels carry the shared Back/Next footer; action steps and
// welcome/done own their own buttons.
const WIZ_FLOW = {
  privacy:  { back: "welcome",  next: "password" },
  contacts: { back: null,       next: "security" }, // no going back past account creation
  security: { back: "contacts", next: "notify" },
  notify:   { back: "security", next: "pin" },
  pin:      { back: "notify",   next: "done" },
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
// footer, and remember the spot (pre-account only).
function wizGoTo(step) {
  wizStep = step;
  document.querySelectorAll("#view-none .wiz-step").forEach(el => { el.hidden = true; });
  const panel = wizPanel(step);
  if (panel) panel.hidden = false;
  wizRenderProgress(step);
  const flow = WIZ_FLOW[step];
  $("wiz-nav").hidden = !flow;
  if (flow) { $("wiz-back").style.visibility = flow.back ? "visible" : "hidden"; }
  try {
    if (WIZ_RESUMABLE.has(step)) localStorage.setItem(WIZ_KEY, step);
    else localStorage.removeItem(WIZ_KEY);
  } catch (_) {}
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
// Back out of a branch to the welcome step.
$("to-create").addEventListener("click", () => wizGoTo("welcome"));
$("to-create-from-link").addEventListener("click", () => wizGoTo("welcome"));

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
    const b64 = await blobToBase64(await processAvatar(file));
    wizPendingAvatar = b64;
    // Show a preview: create a temporary object URL from the processed blob.
    const blob = await (await fetch("data:image/jpeg;base64," + b64)).blob();
    const url = URL.createObjectURL(blob);
    const box = $("wiz-my-avatar");
    box.innerHTML = "";
    const img = document.createElement("img"); img.src = url; img.alt = "Profile picture";
    img.style.cssText = "width:100%;height:100%;object-fit:cover;border-radius:50%";
    box.append(img);
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
// Replaces the old post-unlock modal. Same backend call (POST /api/security
// with action "pin-enable"), same password reuse from the onboarding session.
$("wiz-pin-save").addEventListener("click", async () => {
  const err = $("wiz-pin-error"); err.hidden = true;
  const code = $("wiz-pin-new").value;
  if (code !== $("wiz-pin-confirm").value) { err.textContent = "The two PINs don't match."; err.hidden = false; return; }
  if (!pendingPassword) { wizGoTo("done"); return; }
  const { ok, body } = await api("/api/security", { method: "POST", body: JSON.stringify({ action: "pin-enable", password: pendingPassword, code }) });
  if (!ok) { err.textContent = body.error || "Could not turn on PIN unlock."; err.hidden = false; return; }
  pinEnabled = true;
  if (typeof renderPinState === "function") renderPinState();
  $("wiz-pin-new").value = ""; $("wiz-pin-confirm").value = "";
  wizGoTo("done");
});
$("wiz-pin-skip").addEventListener("click", () => {
  $("wiz-pin-new").value = ""; $("wiz-pin-confirm").value = "";
  $("wiz-pin-error").hidden = true;
  wizGoTo("done");
});

// Finish: unlock into the app. PIN is already handled in the wizard now.
$("wiz-finish").addEventListener("click", async () => {
  const pw = pendingPassword;
  clearOnboardingSecrets();
  if (pw) await doUnlock(pw);
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
    sessionToken = res.body.session_token;
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
// can only be set from an unlocked session, so it can't go earlier). The
// onboarding password is held only for the life of this modal so the user need
// not retype it, then dropped. Skipping is a first-class choice — a PIN is just
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
  if (!ok) return;
  myName = body.display_name || name;
  $("display-name-text").textContent = myName || "(not set)";
  renderMyAvatar();
});
// Profile picture: pick → client crop/downscale → POST base64 to /api/profile.
$("avatar-btn").addEventListener("click", () => $("avatar-input").click());
$("avatar-input").addEventListener("change", async (e) => {
  const file = e.target.files && e.target.files[0];
  e.target.value = ""; // allow re-picking the same file
  if (!file) return;
  const err = $("avatar-error"); err.hidden = true;
  const btn = $("avatar-btn"); btn.setAttribute("disabled", "");
  try {
    const b64 = await blobToBase64(await processAvatar(file));
    const { ok, body } = await api("/api/profile", { method: "POST", body: JSON.stringify({ avatar: b64 }) });
    if (!ok) { err.textContent = (body && body.error) || "Couldn't set that picture."; err.hidden = false; return; }
    myAvatarHash = body.avatar_hash || "";
    renderMyAvatar();
  } catch (ex) {
    err.textContent = ex.message || "Couldn't read that image.";
    err.hidden = false;
  } finally {
    btn.removeAttribute("disabled");
  }
});
$("avatar-remove-btn").addEventListener("click", async () => {
  const { ok, body } = await api("/api/profile", { method: "POST", body: JSON.stringify({ avatar: "" }) });
  if (!ok) return;
  myAvatarHash = body.avatar_hash || "";
  renderMyAvatar();
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
  if (!ok) return;
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
  if (!ok) return;
  myBackupBytes = body.group_image_backup_bytes || 0;
  renderBackupState();
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
  const fb = $("copy-feedback"); fb.hidden = false; setTimeout(() => { fb.hidden = true; }, 1500);
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
  // Show preview when input looks like a valid onion address (ends with .onion, min 16 chars)
  if (val.length >= 16 && val.endsWith(".onion")) {
    preview.hidden = false;
    helpText.hidden = true;
    $("find-preview-name").textContent = val.slice(0, 16) + "…";
    // Render initials avatar
    const av = $("find-preview-avatar");
    av.innerHTML = "";
    av.append(avatarNode("", val, null));
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
  const { ok, body } = await api("/api/lookup", { method: "POST", body: JSON.stringify({ account }) });
  btn.disabled = false; btn.textContent = "Look up";
  if (!ok) { err.textContent = body.error || "Could not find that account."; err.hidden = false; return; }
  lookupResult = { account: body.account, display_name: body.display_name || "", avatar_hash: body.avatar_hash || "" };
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
  const { ok, body } = await api("/api/friend-requests/send", { method: "POST", body: JSON.stringify({ account: lookupResult.account, name: lookupResult.display_name }) });
  btn.disabled = false; btn.textContent = "Send friend request";
  if (!ok) { $("find-error").textContent = body.error || "Could not send request."; $("find-error").hidden = false; return; }
  lookupResult = null;
  await loadContacts();
  setTab("chats");
});
$("requests-list").addEventListener("click", async (e) => {
  const acc = e.target.closest("[data-accept]"), dec = e.target.closest("[data-decline]");
  if (acc) {
    const { ok, body } = await api("/api/friend-requests/accept", { method: "POST", body: JSON.stringify({ account: acc.dataset.accept }) });
    // Don't imply it's done when the other side hasn't heard. We keep retrying
    // in the background, but they stay stuck at "pending" until it lands.
    if (ok && body.notified === false) {
      const n = $("accept-notice");
      n.textContent = "Accepted — but we couldn't reach them just now. They won't be able to message you until we do; we'll keep trying in the background.";
      n.hidden = false;
      setTimeout(() => { n.hidden = true; }, 12000);
    }
  } else if (dec) await api("/api/friend-requests/decline", { method: "POST", body: JSON.stringify({ account: dec.dataset.decline }) });
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
      else if (m.friend_status === "none") { const b = document.createElement("md-text-button"); b.textContent = "Add friend"; b.dataset.gfriend = m.account; b.dataset.gname = m.name || ""; actions.append(b); }
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
    info.append(avatarNode(c.avatar_hash, c.name || shortAccount(c.account), null));
    const nm = document.createElement("div"); nm.className = "body";
    nm.textContent = c.name || shortAccount(c.account);
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
  const t = e.target.closest("[data-gmsg],[data-gfriend],[data-gacceptfriend],[data-gpromote],[data-gremove]");
  if (!t) return;
  if (t.dataset.gmsg) { setTab("chats"); openChat(t.dataset.gmsg); return; }
  t.setAttribute("disabled", "");
  if (t.dataset.gfriend) { await groupAction("/api/friend-requests/send", { account: t.dataset.gfriend, name: t.dataset.gname }); }
  else if (t.dataset.gacceptfriend) { await groupAction("/api/friend-requests/accept", { account: t.dataset.gacceptfriend }); await loadRequests(); }
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
    const label = document.createElement("span"); label.textContent = h.name || h.account;
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

function imageElement(id) {
  const img = document.createElement("img");
  img.className = "msg-image";
  img.alt = "Photo";
  const cached = imageURLs.get(id);
  if (cached) {
    img.src = cached;
  } else {
    img.classList.add("skeleton");
    fetchImage(id, img);
  }
  img.addEventListener("click", () => { if (img.src && !img.classList.contains("img-missing") && !img.classList.contains("skeleton")) openImageViewer(img.src); });
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
// (a QR isn't a photo), just fullscreen + zoom. Visibility is set on EVERY open so
// a prior QR view never leaves the actions hidden for the next photo.
function openImageViewer(src, opts = {}) {
  const isQR = opts.kind === "qr";
  ivSrc = src;
  ivIsQR = isQR;
  $("image-viewer-img").src = src;
  $("image-viewer-img").alt = isQR ? "QR code" : "Photo";
  $("image-viewer-actions").hidden = isQR;
  ivReset();
  ivNote(null);
  $("bottomnav").hidden = true;
  $("image-viewer").hidden = false;
}
function closeImageViewer() {
  $("image-viewer").hidden = true;
  $("bottomnav").hidden = false;
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
    const rect = ivStage.getBoundingClientRect();
    ivZoomTo(ivPinchStart.scale * (dist / ivPinchStart.dist),
      ivPinchStart.cx - rect.left, ivPinchStart.cy - rect.top);
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
        const rect = ivStage.getBoundingClientRect();
        ivZoomTo(ivZoom.scale > 1 ? 1 : 2.5, e.clientX - rect.left, e.clientY - rect.top);
        ivLastTap = 0;
      } else {
        ivLastTap = now;
      }
    }
    ivMultiTouched = false;
  }
}
ivStage.addEventListener("pointerup", ivPointerEnd);
ivStage.addEventListener("pointercancel", ivPointerEnd);
// Desktop wheel zoom.
ivStage.addEventListener("wheel", (e) => {
  e.preventDefault();
  const rect = ivStage.getBoundingClientRect();
  ivZoomTo(ivZoom.scale * (e.deltaY < 0 ? 1.15 : 0.87), e.clientX - rect.left, e.clientY - rect.top);
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

// processImage returns { blob, mime } for a 1:1 photo. A GIF is passed through
// byte-for-byte (the backend allowlists image/gif) — re-encoding to JPEG would
// flatten an animated GIF to a single static frame. Everything else is decoded,
// downscaled and re-encoded to JPEG under the cap.
async function processImage(file) {
  if (file.type === "image/gif") {
    if (file.size > IMAGE_CAP_BYTES) throw new Error("That GIF is too large to send — a GIF can't be shrunk without losing the animation.");
    return { blob: file, mime: "image/gif" };
  }
  let bitmap;
  try { bitmap = await createImageBitmap(file); }
  catch (_) { throw new Error("Couldn't read that image."); }
  try { return { blob: await encodeScaled(bitmap, 1600, IMAGE_CAP_BYTES), mime: "image/jpeg" }; }
  finally { if (bitmap.close) bitmap.close(); }
}

// processGroupImage makes the two payloads a group image needs: the full image
// (a GIF passed through to keep its animation, otherwise a downscaled JPEG) and a
// tiny low-quality JPEG thumbnail that fans out inline as a blurry preview. The
// thumb is always JPEG — createImageBitmap on a GIF gives its first frame, which
// is all a static preview needs.
async function processGroupImage(file) {
  const gif = file.type === "image/gif";
  if (gif && file.size > IMAGE_CAP_BYTES) throw new Error("That GIF is too large to send — a GIF can't be shrunk without losing the animation.");
  let bitmap;
  try { bitmap = await createImageBitmap(file); }
  catch (_) { throw new Error("Couldn't read that image."); }
  try {
    const full = gif ? file : await encodeScaled(bitmap, 1600, IMAGE_CAP_BYTES);
    const thumb = await encodeScaled(bitmap, 96, GROUP_THUMB_CAP_BYTES, 0.5);
    return { full, fullMime: gif ? "image/gif" : "image/jpeg", thumb, thumbMime: "image/jpeg" };
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
    let ok, body;
    if (toContact) {
      const { blob, mime } = await processImage(file);
      const b64 = await blobToBase64(blob);
      ({ ok, body } = await api("/api/messages/image", { method: "POST", body: JSON.stringify({ to: currentPeer, mime, data: b64 }) }));
    } else {
      const { full, fullMime, thumb, thumbMime } = await processGroupImage(file);
      const [fullB64, thumbB64] = await Promise.all([blobToBase64(full), blobToBase64(thumb)]);
      ({ ok, body } = await api("/api/groups/image", { method: "POST", body: JSON.stringify({ group: currentGroup, full_mime: fullMime, full_data: fullB64, thumb_mime: thumbMime, thumb_data: thumbB64 }) }));
    }
    if (!ok) { $("send-error").textContent = (body && body.error) || "Couldn't send the photo."; $("send-error").hidden = false; }
    else await loadMessages();
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
function openForwardPicker(payload) {
  pendingForward = payload;
  const list = $("forward-list");
  list.innerHTML = "";
  const add = (label, icon, onPick) => {
    const b = document.createElement("button");
    b.type = "button"; b.className = "forward-item";
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "icon");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", icon); svg.append(use);
    const span = document.createElement("span"); span.textContent = label;
    b.append(svg, span);
    b.addEventListener("click", onPick);
    list.append(b);
  };
  for (const c of contacts.filter((c) => c.status === "accepted")) {
    add(c.name || shortAccount(c.account), "#ic-person", () => doForward({ type: "contact", id: c.account }));
  }
  for (const g of groups) {
    add(g.name || "Group", "#ic-group", () => doForward({ type: "group", id: g.id }));
  }
  if (!list.children.length) {
    const p = document.createElement("p"); p.className = "body muted"; p.textContent = "No chats to forward to yet.";
    list.append(p);
  }
  $("forward-modal").hidden = false;
}
function closeForwardPicker() { $("forward-modal").hidden = true; pendingForward = null; }
$("forward-cancel").addEventListener("click", closeForwardPicker);
$("forward-modal").addEventListener("click", (e) => { if (e.target === $("forward-modal")) closeForwardPicker(); });

async function doForward(target) {
  const payload = pendingForward;
  closeForwardPicker();
  if (!payload) return;
  if (!torSendable) { $("send-error").textContent = "Still connecting to Tor — one moment, then you can forward."; $("send-error").hidden = false; return; }
  try {
    if (payload.kind === "text") {
      if (target.type === "contact") await api("/api/messages", { method: "POST", body: JSON.stringify({ to: target.id, text: payload.text }) });
      else await api("/api/groups/send", { method: "POST", body: JSON.stringify({ group: target.id, text: payload.text }) });
    } else {
      const blob = await (await fetch(payload.src)).blob();
      if (target.type === "contact") {
        const { blob: out, mime } = await processImage(blob);
        const b64 = await blobToBase64(out);
        await api("/api/messages/image", { method: "POST", body: JSON.stringify({ to: target.id, mime, data: b64 }) });
      } else {
        const { full, fullMime, thumb, thumbMime } = await processGroupImage(blob);
        const [fullB64, thumbB64] = await Promise.all([blobToBase64(full), blobToBase64(thumb)]);
        await api("/api/groups/image", { method: "POST", body: JSON.stringify({ group: target.id, full_mime: fullMime, full_data: fullB64, thumb_mime: thumbMime, thumb_data: thumbB64 }) });
      }
    }
    // Jump into the chat we forwarded to, so the sent copy is visible.
    if (target.type === "contact") openChat(target.id); else openGroup(target.id);
    await loadMessages();
  } catch (err) {
    $("send-error").textContent = (err && err.message) || "Couldn't forward that.";
    $("send-error").hidden = false;
  }
}

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
  $("select-delete").style.opacity = hasDeletable ? "1" : "0.4";
  $("select-delete").style.pointerEvents = hasDeletable ? "auto" : "none";
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
["password", "pin", "compose-text", "find-account", "display-name-input", "mailbox-input", "gib-input", "link-code-input", "create-password", "create-password2", "recover-password", "pin-password", "pin-new", "pin-confirm", "duress-password", "duress-code", "duress-code2"].forEach(submitOnEnter);

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
  // A confirm dialog is the top-most interaction: back/Escape cancels it.
  if (confirmOpen()) { confirmResolver(false); return true; }
  // 0. A modal dialog takes back before anything else.
  const relayOffer = $("relay-offer");
  if (relayOffer && !relayOffer.hidden) { closeRelayOffer(); return true; }
  // 1. Close chat overflow menu if open
  const menu = $("chat-menu");
  if (menu && !menu.hidden) {
    menu.hidden = true;
    return true;
  }
  // 2. Close open sub-boxes, modals, or forms
  const subBoxes = [
    { id: "edit-dialog", hide: () => { $("edit-dialog").hidden = true; editDialogResolver && editDialogResolver(false); } },
    { id: "link-new-box", hide: () => $("link-new-box").hidden = true },
    { id: "link-existing-form", hide: () => $("link-existing-form").hidden = true },
    { id: "duress-wizard", hide: () => $("duress-wizard").hidden = true },
    { id: "wipe-form", hide: () => $("wipe-form").hidden = true },
    { id: "recover-form", hide: () => { $("recover-form").hidden = true; $("create-view").hidden = false; } },
    { id: "phrase-view", hide: () => { clearOnboardingSecrets(); $("phrase-view").hidden = true; $("create-view").hidden = false; } },
    { id: "verify-view", hide: () => { clearOnboardingSecrets(); $("verify-view").hidden = true; $("create-view").hidden = false; } }
  ];
  for (const box of subBoxes) {
    const el = $(box.id);
    if (el && !el.hidden) {
      box.hide();
      return true;
    }
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
// Trade a one-time ?x= bootstrap token for the real one if that's how we were
// launched (cmd/server browser), then start. Without a control token every /api
// call is refused (see controlToken above), so skip the doomed status probe and
// tell the user how to recover.
exchangeControlToken().then(() => {
  if (controlToken) refresh();
  else showControlTokenError();
});

