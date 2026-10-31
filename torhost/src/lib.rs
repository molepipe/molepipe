//! torhost — the Android Tor implementation for Molepipe.
//!
//! A thin C-ABI shim over `arti-client` that HOSTS the account's v3 onion
//! service (publishing under our own pre-derived key so the .onion equals the
//! account number) and dials peer onion services. The Go backend links this as
//! a static library via cgo and drives it through the existing
//! `tor.OnionService` interface, so the onion secret key never leaves native
//! memory.
//!
//! Verified against arti-client 0.45.0 (Arti 1.7.0 era). The onion-service
//! HOSTING API is EXPERIMENTAL — see the exact-version pins in Cargo.toml.
//!
//! Key handling parity with desktop: `launch_onion_service_with_hsid` inserts
//! the key into Arti's native (on-disk) keystore under `data_dir/arti`. That
//! matches the desktop sidecar exactly (plaintext key on disk only while the
//! service runs); an in-memory keystore is not yet offered by arti-client (its
//! own TODO #1186). [`torhost_stop`] wipes the keystore so the key does not
//! outlive the session.
//!
//! # Safety
//! Every `*const c_char` must be a valid, NUL-terminated C string, and
//! `key_ptr`/`key_len` must describe a readable 64-byte buffer. Handles from
//! [`torhost_start`] must be freed exactly once with [`torhost_stop`], and
//! strings returned via out-params freed once with [`torhost_free_string`].

use std::collections::HashMap;
use std::collections::VecDeque;
use std::error::Error;
use std::ffi::{c_char, c_float, c_int, CStr, CString};
use std::fmt;
use std::fmt::Write as _;
use std::os::fd::{IntoRawFd, RawFd};
use std::path::PathBuf;
use std::ptr;
use std::slice;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use arti_client::config::{BoolOrAuto, CfgPath, TorClientConfigBuilder};
use arti_client::{DormantMode, TorClient, TorClientConfig};
use futures::stream::StreamExt;
use safelog::DisplayRedacted; // brings HsId::display_unredacted() into scope
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tor_cell::relaycell::msg::Connected;
use tor_hscrypto::pk::HsIdKeypair;
use tor_hsservice::status::{DescUploadRetryError, Problem, State};
use tor_hsservice::{handle_rend_requests, HsNickname, OnionServiceConfig, RunningOnionService};
use tor_llcrypto::pk::ed25519::ExpandedKeypair;
use tor_rtcompat::PreferredRuntime;
use tracing_core::Level;
use tracing_subscriber::filter::Targets;

// ---------------------------------------------------------------------------
// Log ring buffer — captures log:: output for the Go side to read.
// ---------------------------------------------------------------------------

// 400 rather than 200: a dial that fails against several peers at once pushes
// tens of lines through here in a second (one phone's log was ~190 of them), and
// at 200 that flood evicted the onion-service status transitions — the lines the
// ring exists to carry — before anyone could read them. Worst case is 400 * 512B.
const LOG_RING_CAP: usize = 400;

static LOG_RING: Mutex<Ring> = Mutex::new(Ring::new());

/// The log ring, plus just enough state to collapse an immediately repeated
/// message into one line with a count.
///
/// Deduplication is here rather than at each call site because the floods come
/// from the retry loops: an unreachable peer is re-dialled, and each attempt
/// logs the identical line. Collapsing runs keeps a fixed-size ring holding
/// something closer to a history than to the last few seconds of one retry.
struct Ring {
    lines: VecDeque<String>,
    /// Newest line as logged, without any "(xN)" suffix, for comparison.
    last: String,
    /// How many times `last` has repeated since it was first pushed.
    repeats: usize,
}

impl Ring {
    const fn new() -> Self {
        Self { lines: VecDeque::new(), last: String::new(), repeats: 0 }
    }

    fn push(&mut self, msg: String) {
        if msg == self.last {
            if let Some(back) = self.lines.back_mut() {
                self.repeats += 1;
                *back = format!("{} (x{})", self.last, self.repeats + 1);
                return;
            }
        }
        self.last.clear();
        self.last.push_str(&msg);
        self.repeats = 0;
        if self.lines.len() >= LOG_RING_CAP {
            self.lines.pop_front();
        }
        self.lines.push_back(msg);
    }
}

/// Cap on one ring line, so a single flood line can't blow up memory. 512 was
/// too tight: a descriptor-upload failure carries one cause chain per retry
/// attempt, and a real one got clipped mid-word at "Attempt 5: co" — the
/// diagnosis cut off exactly where it stopped repeating itself. 4096 holds a
/// full retry report; worst case for the ring is 400 * 4KB.
const LOG_LINE_MAX: usize = 4096;

/// Truncate to at most `max` BYTES, backing off to the nearest char boundary.
///
/// `String::truncate` panics mid-codepoint, and a panic here crosses the
/// extern "C" boundary as an abort. That was survivable while every line came
/// from our own ASCII format strings; it is not now that arti's tracing output
/// flows through the same cap, carrying remote-influenced strings we don't
/// control the encoding of.
fn truncate_chars(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
}

struct RingLogger;

impl log::Log for RingLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let mut msg = format!("[{}] {}", record.level(), record.args());
        truncate_chars(&mut msg, LOG_LINE_MAX);
        // Use unwrap_or_else to recover from a poisoned mutex instead of panicking.
        LOG_RING.lock().unwrap_or_else(|e| e.into_inner()).push(msg);
    }
    fn flush(&self) {}
}

static RING_LOGGER: RingLogger = RingLogger;

/// Install the ring logger once. Called from `ensure_logger`.
fn ensure_ring_logger() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = log::set_logger(&RING_LOGGER);
        log::set_max_level(log::LevelFilter::Info);
    });
}

// ---------------------------------------------------------------------------
// Tracing bridge — arti's OWN diagnostics into the same ring.
// ---------------------------------------------------------------------------
//
// Everything above carries only what *we* log through the `log` crate. arti
// instruments itself with `tracing` instead, and nothing in the resolved
// dependency graph enables tracing's `log` feature, so not one line of arti's
// internal diagnostics has ever reached tormsg.log. That gap is why an
// onion-service publish stall reads as a bare "intro point failure": the status
// layer hands us `Problem::Ipt` with an EMPTY error list, `describe_problem` has
// nothing to print, and the actual cause exists only in a tracing event.
//
// The bridge is OFF by default and must stay that way. arti at DEBUG is a
// firehose; the ring holds 400 lines and the Go side flushes it to an
// append-only tormsg.log every 5s. An always-on bridge would evict the
// onion-service status transitions the ring exists to carry — the same flood
// that already forced LOG_RING_CAP from 200 to 400 — and trade a diagnosis we
// have for one we want. Turn it on for a stalled publish, then turn it off.

/// Target+level filter for the bridge; `None` means the bridge emits nothing.
/// Default trace filter applied when `<data_dir>/trace_filter` does not exist.
/// Surfaces high-level onion service milestones (descriptor uploads, intro point
/// establishment, rate limits) and circuit timeout reports without the high-volume
/// debug noise of individual cell exchanges.
pub const DEFAULT_TRACE_FILTER: &str = "tor_hsservice=info,tor_circmgr::timeouts=info";

/// Held behind an `RwLock` rather than baked in at install time because the
/// interesting window is the publish attempt right after unlock. A filter that
/// could only be set after startup would miss it, and one compiled in could not
/// be narrowed when it turned out to be too wide.
static TRACE_FILTER: RwLock<Option<Targets>> = RwLock::new(None);

fn trace_filter_allows(target: &str, level: &Level) -> bool {
    match &*TRACE_FILTER.read().unwrap_or_else(|e| e.into_inner()) {
        Some(targets) => targets.would_enable(target, level),
        None => false,
    }
}

/// Parse and install a target filter, e.g. `tor_hsservice=debug` or
/// `tor_hsservice=debug,tor_circmgr=debug`. An empty spec or "off" turns the bridge off.
/// A spec that does not parse is logged and otherwise ignored, leaving the
/// previous filter in place — a typo must not silently disable the capture the
/// caller was asking for.
fn set_trace_filter(spec: &str) {
    let spec = spec.trim();
    let parsed = if spec.is_empty() || spec.eq_ignore_ascii_case("off") {
        None
    } else {
        match spec.parse::<Targets>() {
            Ok(targets) => Some(targets),
            Err(e) => {
                log::warn!("trace filter {spec:?} rejected: {e}");
                return;
            }
        }
    };
    let describe = match &parsed {
        Some(_) => spec.to_owned(),
        None => "off".to_owned(),
    };
    *TRACE_FILTER.write().unwrap_or_else(|e| e.into_inner()) = parsed;
    // Our `Layer::enabled` answer is cached per callsite as an `Interest`, which
    // is the whole reason the bridge costs nothing while off. That cache is now
    // stale: without this, enabling the filter would only take effect for
    // callsites arti happens to reach for the first time afterwards.
    tracing_core::callsite::rebuild_interest_cache();
    // Report both ceilings alongside the filter. tracing's `release_max_level_*`
    // features strip events at the macro site, where no subscriber, filter or
    // interest rebuild can recover them — so without STATIC_MAX in the log, a
    // capture that stays empty is ambiguous between "arti had nothing to say"
    // and "the events were never compiled in". Not enabled in this tree's
    // android release graph as of 2026-10-22, which is exactly the kind of
    // thing a dependency bump changes silently.
    log::warn!(
        "arti trace bridge: {describe} (compiled-in max {}, effective max {})",
        tracing::level_filters::STATIC_MAX_LEVEL,
        tracing_core::LevelFilter::current(),
    );
}

/// A tracing event rendered onto one ring line.
///
/// Fields are formatted through `Debug`, never `Display`: arti wraps addresses
/// and relay identities in `safelog::Sensitive`, whose `Debug` impl prints
/// `[scrubbed]` while safe logging is enabled (it is — nothing in this tree
/// calls `disable_safe_logging`). Reaching past that to a raw value would put
/// peer-identifying material into a file the user reads.
struct TraceFields(String);

impl tracing_core::field::Visit for TraceFields {
    fn record_debug(&mut self, field: &tracing_core::Field, value: &dyn fmt::Debug) {
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        // `message` is the event's prose and carries no useful key; every other
        // field is structured data worth labelling.
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        } else {
            let _ = write!(self.0, "{}={value:?}", field.name());
        }
    }
}

struct RingTraceLayer;

impl<S: tracing_core::Subscriber> tracing_subscriber::Layer<S> for RingTraceLayer {
    /// Consulted once per *callsite*, not once per event: the default
    /// `register_callsite` turns this answer into a cached `Interest`, so every
    /// target the filter rejects costs arti nothing per event thereafter.
    /// `set_trace_filter` rebuilds that cache when the filter changes.
    fn enabled(
        &self,
        md: &tracing_core::Metadata<'_>,
        _: tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        trace_filter_allows(md.target(), md.level())
    }

    fn on_event(
        &self,
        event: &tracing_core::Event<'_>,
        _: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let md = event.metadata();
        // Re-checked rather than trusted: a cached "always" Interest from a
        // wider filter outlives a narrowing until the next cache rebuild, and
        // a stale callsite must not keep writing after the bridge is off.
        if !trace_filter_allows(md.target(), md.level()) {
            return;
        }
        let mut fields = TraceFields(String::new());
        event.record(&mut fields);
        let mut msg = format!("[{}] {}: {}", md.level(), md.target(), fields.0);
        truncate_chars(&mut msg, LOG_LINE_MAX);
        LOG_RING.lock().unwrap_or_else(|e| e.into_inner()).push(msg);
    }
}

/// Install the tracing bridge once. Must run AFTER `ensure_ring_logger`.
///
/// The dispatcher primitive, not `SubscriberInitExt::try_init`: `try_init` also
/// calls
/// `tracing_log::LogTracer::init()` when tracing-subscriber's `tracing-log`
/// feature is on, which would reroute our own `log::` output through tracing.
/// Feature unification means we cannot be sure that feature is off (tor-rtmock
/// pulls tracing-subscriber in too), so we take the path that cannot do it. The
/// ordering is the second guard: with RingLogger already installed, a LogTracer
/// could not take the `log` global anyway.
fn ensure_trace_bridge() {
    use std::sync::Once;
    use tracing_subscriber::layer::SubscriberExt;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let subscriber = tracing_subscriber::registry().with(RingTraceLayer);
        // The error only means a global subscriber was already set — ignore it.
        let _ =
            tracing_core::dispatcher::set_global_default(tracing_core::Dispatch::new(subscriber));
    });
}

/// Apply the filter written to `<data_dir>/trace_filter`, if that file exists.
/// If absent, falls back to [`DEFAULT_TRACE_FILTER`]. A file containing "" or "off"
/// turns the bridge off.
fn apply_trace_filter_file(data_dir: &str) {
    let path = PathBuf::from(data_dir).join("trace_filter");
    if let Ok(spec) = std::fs::read_to_string(&path) {
        set_trace_filter(&spec);
    } else {
        set_trace_filter(DEFAULT_TRACE_FILTER);
    }
}

/// Opaque host handle returned to Go. Owns the Tokio runtime everything else
/// lives on, so dropping it (in [`torhost_stop`]) tears the client and service
/// down.
pub struct OnionHost {
    rt: Runtime,
    client: Arc<TorClient<PreferredRuntime>>,
    // Some in host mode (primary device); None in client-only mode (a secondary
    // device that dials out but must not publish the account onion).
    service: Option<Arc<RunningOnionService>>,
    // Additional concurrently-running onion services (rotation aliases), keyed by
    // a monotonic id handed back to Go. Each keeps the JoinHandle of its
    // rendezvous-forwarding task so stopping one aborts its forwarding and drops
    // its service WITHOUT touching the primary service or scrubbing the keystore
    // (which the primary shares). Used to run the new + old alias simultaneously
    // during a rotation's grace window.
    extra_services: HashMap<u64, ExtraService>,
    next_extra_id: u64,
    state_dir: PathBuf, // dataDir/arti — holds keystore/ and hss/
}

/// A rotation-alias onion service running alongside the primary. Dropping it
/// unpublishes the service; `forwarder.abort()` stops splicing inbound streams.
struct ExtraService {
    service: Arc<RunningOnionService>,
    forwarder: JoinHandle<()>,
}

/// Drive bootstrap in the background with retry + capped backoff, instead of a
/// single attempt whose error is swallowed. arti's `bootstrap()` is one-shot: if
/// the first call fails (no network at unlock), nothing re-drives it, so
/// `ready_for_traffic()` stays false and the app is wedged at "connecting" until
/// something else happens to call `bootstrap()` (a lazy dial on the send path).
/// This loop makes an offline-at-unlock self-heal — it keeps retrying (backoff
/// capped at 60s) until arti reports ready, so simply regaining the network
/// brings Tor up on its own.
///
/// The task is owned by the runtime inside [`OnionHost`]; dropping the host
/// (lock / [`torhost_stop`]) drops the runtime and aborts this loop, so it never
/// outlives a locked session. Must be called from within the runtime context
/// (both call sites are inside `rt.block_on`).
fn spawn_bootstrap(client: Arc<TorClient<PreferredRuntime>>) {
    tokio::spawn(async move {
        // Starts at one second, not ZERO: `Duration::ZERO * 2` is still ZERO, so
        // seeding this with ZERO turned the backoff below into a hot retry loop.
        let mut delay = Duration::from_secs(1);
        const MAX_DELAY: Duration = Duration::from_secs(60);
        loop {
            // A concurrent lazy dial may already have bootstrapped us — don't
            // call bootstrap() again once arti is ready for traffic.
            if client.bootstrap_status().ready_for_traffic() {
                return;
            }
            match client.bootstrap().await {
                Ok(()) => return,
                Err(e) => {
                    log::warn!("arti bootstrap failed (retrying in {:?}): {e}", delay);
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(MAX_DELAY);
                }
            }
        }
    });
}

/// Log every onion-service status transition, with the error behind it, into the
/// ring buffer the Go side reads.
///
/// Without this the app can see exactly one bit about its own service — what
/// [`torhost_ready`] reports, `State::is_fully_reachable()` — and that bit
/// collapses "still bootstrapping", "intro points are up but the descriptor
/// will not upload" (`DegradedUnreachable`) and "broken" into a single `false`.
/// A phone sat at `reachable=false` for twenty-two minutes with three live
/// intro points and no log on the device said why, because arti reports through
/// `tracing` while this shim only installs a `log` sink: every line in the Tor
/// log was this shim's own dial-failure warning. `current_problem()` carries
/// the publisher's real error — the HSDir upload retry chain — which is what
/// separates a slow publish from a failing one, and the watchdog's restart
/// decision rests on exactly that distinction.
fn spawn_status_watch(service: Arc<RunningOnionService>, nick: String) {
    let mut events = service.status_events();
    tokio::spawn(async move {
        // Log only on a real change. The stream is documented to coalesce
        // events and to be able to yield an item with no underlying transition,
        // so without this an unchanged status would be logged repeatedly. The
        // ring collapses identical consecutive lines anyway; this keeps them out
        // of logcat too.
        //
        let mut last = String::new();
        // See the `first` guard below.
        let mut first = true;
        // Whether Arti has ever reported this service reachable.
        //
        // Once it has, a later Bootstrapping is a descriptor REUPLOAD, not a
        // cold publish, and the difference is invisible in the state alone. The
        // publisher reports Bootstrapping for any of UploadScheduled /
        // AwaitingIpts / RateLimited, and `OnionServiceStatus::state` lets
        // Bootstrapping on either component outrank the other's Running — so a
        // routine descriptor refresh on a live service renders identically to
        // never having published at all. Measured on a phone on 2026-10-20: 24
        // such dips in 12 minutes, with the descriptor live, the intro points
        // established and peers served throughout, because the intro-point set
        // was still below target and every change to it schedules a reupload.
        // Logging both cases as "Bootstrapping" is what made a healthy service
        // look like a failing one.
        let mut published_once = false;
        while let Some(status) = events.next().await {
            let state = status.state();
            update_publish_latch(&mut published_once, state);
            let mut line = render_state(state, published_once);
            if let Some(problem) = status.current_problem() {
                line.push_str(" — ");
                line.push_str(&describe_problem(problem));
            }
            // Drop a LEADING Shutdown. The stream yields the service's current
            // status first, and a service that has not finished starting reports
            // Shutdown (`OnionServiceStatus::new_shutdown`), so logging it opens
            // every launch with a teardown that never happened.
            //
            // Matched on the state, not the rendered string. The first attempt
            // at this seeded `last` with "Shutdown" and was defeated in the
            // field the same day: arti had attached a stale problem from the
            // previous service's teardown, the line read "Shutdown — intro
            // point failure", and a string compare could not see it. The state
            // cannot acquire a suffix.
            if first {
                first = false;
                if matches!(state, State::Shutdown) {
                    last = line;
                    continue;
                }
            }
            if line == last {
                continue;
            }
            last.clear();
            last.push_str(&line);
            // warn!, not info!: each of these is either a transition the single
            // ready bit cannot express, or the error sitting behind it.
            log::warn!("onion service [{nick}]: {line}");
        }
    });
}

/// Fold one status into the publish latch described in [`spawn_status_watch`].
///
/// Set on either reachable state. **Cleared** on `Shutdown`/`Broken`: the
/// publication the latch describes is then gone, so a later `Bootstrapping` is a
/// genuine cold publish again, and keeping the latch would reintroduce the same
/// lie in the opposite direction — claiming a publication through a real restart
/// — in the one case where that matters most. Every other state leaves it alone;
/// those are the dips the rendering exists to explain.
///
/// Split out from the stream loop only so the transition rules are testable
/// without a live onion service.
fn update_publish_latch(published_once: &mut bool, state: State) {
    match state {
        State::Running | State::DegradedReachable => *published_once = true,
        State::Shutdown | State::Broken => *published_once = false,
        _ => {}
    }
}

/// Render a service state for the log, given whether this service has published
/// at least once since it last shut down.
///
/// The wording claims only that — not that the descriptor is still live. The
/// latch cannot know whether a publication has since expired; it knows a
/// Bootstrapping here is a refresh of one rather than a first attempt.
///
/// Only `Bootstrapping` is ambiguous, and only after a publish; see the
/// `published_once` comment in [`spawn_status_watch`] for why the two cases are
/// indistinguishable in the state alone.
fn render_state(state: State, published_once: bool) -> String {
    if published_once && matches!(state, State::Bootstrapping) {
        // State name first, so the line still greps as the state it is.
        "Bootstrapping (reupload — already published once)".into()
    } else {
        format!("{state:?}")
    }
}

/// Render a [`Problem`] as one line, including the cause chain.
///
/// `Problem` has no `Display`, and the `Display` on the payload errors stops at
/// a summary — `DescUploadRetryError` prints "Ran out of retries" and keeps the
/// actual failure in the `RetryError` it wraps, which is not a `source()`, so a
/// plain chain walk would throw away the whole diagnosis. Match the variants to
/// reach it.
fn describe_problem(problem: &Problem) -> String {
    match problem {
        Problem::Runtime(e) => format!("fatal: {}", fmt_error_chain(e)),
        // The error lists can be empty — arti reports e.g. a transient
        // Problem::Ipt with no errors during startup — so don't print a count
        // of zero followed by a dangling colon.
        Problem::DescriptorUpload(errs) if errs.is_empty() => "descriptor upload failed".into(),
        Problem::DescriptorUpload(errs) => format!(
            "descriptor upload failed ({}): {}",
            errs.len(),
            errs.iter().map(describe_upload_error).collect::<Vec<_>>().join(" | ")
        ),
        Problem::Ipt(errs) if errs.is_empty() => "intro point failure".into(),
        Problem::Ipt(errs) => format!(
            "intro point failure ({}): {}",
            errs.len(),
            errs.iter().map(|e| fmt_error_chain(e)).collect::<Vec<_>>().join(" | ")
        ),
        // Problem is #[non_exhaustive]: a variant added by a future arti still
        // gets logged, just without the hand-written detail.
        other => format!("{other:?}"),
    }
}

/// One descriptor-upload failure, unwrapped to the retry report inside it.
fn describe_upload_error(err: &DescUploadRetryError) -> String {
    // The wrapped RetryError's Display is the useful part: it names what we were
    // trying to do, how many attempts failed, and each attempt's cause chain.
    match err {
        DescUploadRetryError::FatalError(r) => format!("fatal: {}", one_line(&r.to_string())),
        DescUploadRetryError::MaxRetryCountExceeded(r) => {
            format!("out of retries: {}", one_line(&r.to_string()))
        }
        DescUploadRetryError::Timeout(r) => format!("timeout: {}", one_line(&r.to_string())),
        other => fmt_error_chain(other),
    }
}

/// Format an error and its `source()` chain as a single line.
fn fmt_error_chain(err: &dyn Error) -> String {
    let mut out = err.to_string();
    let mut src = err.source();
    while let Some(s) = src {
        out.push_str(": ");
        out.push_str(&s.to_string());
        src = s.source();
    }
    one_line(&out)
}

/// Fold a multi-line error report onto one line. `RetryError` lists its attempts
/// one per line; the ring buffer and the Go log are both line-oriented, so a
/// multi-line entry would be split across unrelated-looking log lines.
fn one_line(s: &str) -> String {
    s.split('\n').map(str::trim).filter(|p| !p.is_empty()).collect::<Vec<_>>().join("; ")
}

/// Start the onion service. Returns a heap handle (null on failure) and, on
/// success, writes a newly-allocated C string with the ".onion" address (no
/// port) to `out_onion` — free it with [`torhost_free_string`].
///
/// `local_port` is the loopback port of the Go public listener that inbound
/// onion streams are forwarded to.
///
/// # Safety
/// See the crate-level safety note.
#[no_mangle]
pub unsafe extern "C" fn torhost_start(
    data_dir: *const c_char,
    nickname: *const c_char,
    key_ptr: *const u8,
    key_len: usize,
    local_port: u16,
    out_onion: *mut *mut c_char,
) -> *mut OnionHost {
    // catch_unwind prevents panics from crossing the extern "C" boundary (UB).
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        torhost_start_inner(data_dir, nickname, key_ptr, key_len, local_port, out_onion)
    })) {
        Ok(ptr) => ptr,
        Err(_) => {
            log::error!("torhost_start panicked");
            ptr::null_mut()
        }
    }
}

unsafe fn torhost_start_inner(
    data_dir: *const c_char,
    nickname: *const c_char,
    key_ptr: *const u8,
    key_len: usize,
    local_port: u16,
    out_onion: *mut *mut c_char,
) -> *mut OnionHost {
    if data_dir.is_null() || nickname.is_null() || key_ptr.is_null() || key_len != 64 {
        return ptr::null_mut();
    }
    let data_dir = match CStr::from_ptr(data_dir).to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => return ptr::null_mut(),
    };
    let nickname = match CStr::from_ptr(nickname).to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => return ptr::null_mut(),
    };
    let mut key_bytes = [0u8; 64];
    key_bytes.copy_from_slice(slice::from_raw_parts(key_ptr, 64));

    let result = match start_inner(&data_dir, &nickname, key_bytes, local_port) {
        Ok((host, onion)) => {
            if !out_onion.is_null() {
                if let Ok(c) = CString::new(onion) {
                    *out_onion = c.into_raw();
                }
            }
            Box::into_raw(Box::new(host))
        }
        Err(e) => {
            log_start_error(&data_dir, e.as_ref());
            ptr::null_mut()
        }
    };
    // Zero the key material from the stack so it cannot survive in a core dump.
    unsafe { std::ptr::write_volatile(&mut key_bytes as *mut _, [0u8; 64]); }
    result
}

/// Install a process-default rustls CryptoProvider exactly once. rustls 0.23
/// requires this before any TLS ClientConfig is built; arti's tor-rtcompat
/// panics otherwise (and the panic aborts across our extern "C" boundary).
fn ensure_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // The error only means a provider was already installed — ignore it.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Route Rust `log` crate output to Android logcat AND the in-memory ring
/// buffer once. The ring buffer is read by the Go side via
/// [`torhost_log_count`]/[`torhost_log_line`].
fn ensure_logger() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        ensure_ring_logger();
        // After ensure_ring_logger, deliberately — see ensure_trace_bridge.
        ensure_trace_bridge();
        #[cfg(target_os = "android")]
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag("torhost"),
        );
    });
}

/// Pre-warm one-time global state (logger + rustls crypto provider) at app
/// startup, so the first [`torhost_start`] call does not pay the ~20–100ms
/// init cost on the unlock path.  Safe to call multiple times; all work is
/// guarded by `Once`.
///
/// # Safety
/// No parameters — always safe.
#[no_mangle]
pub extern "C" fn torhost_prewarm() {
    ensure_logger();
    ensure_crypto_provider();
}

/// Set the arti tracing filter at runtime, e.g. `"tor_hsservice=debug"` or
/// `"tor_hsservice=debug,tor_circmgr=debug"`; `""` turns the bridge off. An
/// unparseable spec leaves the current filter alone.
///
/// Normally the filter comes from `<data_dir>/trace_filter` at start instead,
/// which is what covers the publish attempt right after unlock. This exists for
/// turning a capture off (or widening it) without a restart, once a stalled
/// device is already running.
///
/// # Safety
/// `spec` must be NULL or a valid, NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn torhost_set_trace_filter(spec: *const c_char) {
    ensure_logger();
    let spec = if spec.is_null() {
        ""
    } else {
        match CStr::from_ptr(spec).to_str() {
            Ok(s) => s,
            Err(_) => return,
        }
    };
    set_trace_filter(spec);
}

/// Write a start failure (with its cause chain) to data_dir/torhost_error.log,
/// so a failure has a diagnosable cause instead of only a null return —
/// startOnion on the Go side just logs "failed to start" without the reason.
fn log_start_error(data_dir: &str, err: &dyn Error) {
    use std::os::unix::fs::OpenOptionsExt;
    let mut msg = format!("torhost start failed: {err}");
    let mut src = err.source();
    while let Some(s) = src {
        msg.push_str(&format!("\n  caused by: {s}"));
        src = s.source();
    }
    let path = std::path::Path::new(data_dir).join("torhost_error.log");
    let _ = std::fs::OpenOptions::new()
        .create(true).truncate(true).write(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, msg.as_bytes()));
}

/// Scrub all files in a directory tree (recursively) with random data, then
/// remove the entire tree. This defeats forensic recovery of onion key material
/// on flash/SSD where simple unlink does not overwrite data blocks.
fn scrub_and_remove(dir: std::path::PathBuf) {
    if !dir.exists() {
        return;
    }
    // First pass: recursively scrub all files at any depth.
    let _ = scrub_dir_recursive(&dir);
    // Second pass: remove the now-scrubbed tree.
    let _ = std::fs::remove_dir_all(&dir);
}

/// Recursively walk a directory and overwrite every regular file with random data.
fn scrub_dir_recursive(dir: &std::path::Path) -> Result<(), Box<dyn Error>> {
    use std::io::Read;
    let mut rng = std::fs::File::open("/dev/urandom")?;
    for entry in std::fs::read_dir(dir)?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scrub_dir_recursive(&path)?;
        } else if path.is_file() {
            let size = std::fs::metadata(&path)?.len();
            if size > 0 {
                if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&path) {
                    let mut buf = vec![0u8; size.min(4096) as usize];
                    let mut written = 0u64;
                    while written < size {
                        let chunk = (size - written).min(buf.len() as u64) as usize;
                        if rng.read_exact(&mut buf[..chunk]).is_ok() {
                            let _ = std::io::Write::write_all(&mut f, &buf[..chunk]);
                        }
                        written += chunk as u64;
                    }
                    let _ = f.sync_all();
                }
            }
        }
    }
    Ok(())
}

/// Loosen arti's adaptive circuit-build timeout for a phone-grade link.
///
/// Arti fits a Pareto distribution to its own circuit build times and sets the
/// timeout at the `cbtquantile` percentile of that fit, defaulting to the
/// consensus value of 80. On a desktop link the 80th percentile sits far above
/// the median and the cost of a timeout is small. On this phone it does not:
/// measured over 1000 samples from `arti/state/circuit_timeouts.json`, builds
/// ran p50 2495 ms / p80 3065 ms / p95 3565 ms, and the fitted timeout came out
/// at 2864 ms — under the p80 of the raw samples, so roughly **29% of builds
/// that would have completed were abandoned instead**.
///
/// That is affordable for an ordinary stream, which just retries. It is not
/// affordable for publishing the onion descriptor: several HSDir uploads must
/// land, and a run of failures showed up as `Tried to upload a hidden service
/// descriptor 14 times, but all attempts failed; … could not build circuit to
/// HsDir: Circuit took too long to build`, turning an unlock into an 8-minute
/// wait before the address was reachable.
///
/// The estimator also censors its own input: only builds that beat the current
/// timeout are recorded, so a timeout set too low on a slow link keeps the
/// sampled tail short and holds itself down. Raising the quantile lets the
/// longer builds finish and be measured, which lets the estimate float up to
/// where this network actually lives.
///
/// Against the same samples, `cbtquantile = 95` yields a 3494 ms timeout that
/// 94.2% of builds beat, up from 70.8%. We stop at 95 rather than 99 because
/// `cbtclosequantile` — the point at which a late circuit is abandoned outright
/// instead of merely declared timed out — defaults to 99 and the abandon
/// threshold is `max`ed against the timeout threshold; equal values would
/// collapse the two-stage design into one. The adaptive fit is left in place:
/// this moves where on the curve we sit, not whether we measure.
///
/// Trade-off: deviating from a consensus parameter makes this client's circuit
/// timing distinguishable from a default-configured one. It is local behaviour
/// (how long we hold a pending circuit), not anything published, and accepted
/// here as the cost of an onion address that publishes in reasonable time.
///
/// # Why a floor is needed as well as a quantile
///
/// Raising the quantile fixed the ordinary case and left the one that actually
/// delays publication untouched. Of every upload-attempt failure in the device
/// log, 96.6% (14617 of 15124) is not a circuit *build* at all: it is the
/// one-hop extension of a pooled stem circuit onto the chosen HSDir. The two
/// are distinguishable in the log because the extend path maps its timeout to
/// `CircTimeout(Some(unique_id))` and the error format prints that id, while a
/// stem build carries `None` and prints none — `Circuit 0.3 took too long` is
/// an extend, `Circuit took too long` is a build.
///
/// That extension derives its own budget from `Action::ExtendCircuit { 3, 4 }`,
/// which scales to `(build_scale(4) - build_scale(3)) * 2 = 8` against a
/// reference `BuildCircuit { 3 }` of 12 — so it gets **0.667x** the base
/// timeout, not more, to reach a relay it is not permitted to choose. With the
/// emulator's measured 1556 ms base that is ~1037 ms, and it fails essentially
/// every time while 95.6% of ordinary builds beat the same base. Each miss then
/// enters exponential backoff against a 300 s per-HSDir ceiling with no status
/// event until the ceiling is hit, which is the 390-435 s of silence before
/// `DegradedReachable — descriptor upload failed (6)`.
///
/// `cbtmintimeout` floors the estimate (consensus default 10 ms, range
/// `[10, i32::MAX]`, so there is effectively no floor today). A floor was
/// clearly needed; 6000 ms was the first attempt, and it turned out to sit
/// *inside* the live distribution rather than clear of it.
///
/// # What the on-device measurement showed
///
/// The 2026-10-22 capture (`tor_circmgr::timeouts=trace`, 206 builds on the
/// phone) is unambiguous. Successful builds, bucketed by whole second of
/// `delay`:
///
/// ```text
/// 1s: 34   2s: 76   3s: 39   4s: 22   5s: 6
/// ```
///
/// and every one of the 29 timeouts landed at `delay=6.00x`, with
/// `have_seen_recent_activity=true` throughout and spread across hops
/// (hop 0: 5, hop 1: 17, hop 2: 7). Nothing failed at 7 s, 10 s or 20 s —
/// because with the floor at 6000 ms nothing was permitted to reach them. The
/// success curve climbs to 5 s and is sheared off exactly where the floor sits,
/// so 14% of all builds were being converted into failures by the deadline
/// itself, including seven that had already reached the significant hop and
/// were all but finished.
///
/// The collateral damage is worse than the lost builds. A 6 s guillotine on the
/// first hop also makes a working guard look unreachable —
/// `tor_guardmgr::guard: Could not connect to guard … Retrying in 29s` — so
/// guards churn, and every HS circuit, which needs a guard before it can reach
/// an HSDir at all, inherits the churn. Over the same period the phone failed
/// 66% of its HSDir uploads (73 of 110) while the emulator, on the same account
/// and the same HSDir ring, failed 16% (3 of 19) and reached `Running` in 10 s
/// against the phone's 9m35s. The relays were never the problem.
///
/// # Why the floor censors its own correction
///
/// `timeouts/pareto.rs:549-550` floors *both* thresholds against `min_timeout`:
/// the timeout threshold and the abandon threshold alike. Tor's two-stage design
/// wants them to differ — at the timeout you stop waiting but keep the circuit
/// alive to observe how long it would have taken, which is how the estimator
/// learns its own tail. When both clamp to the same 6000 ms the circuit is
/// killed at the instant it times out, so no build above 6 s is ever recorded,
/// so p95 stays near 3.5 s, so the floor keeps binding. That is why the
/// distribution above is censored rather than merely truncated — and it also
/// defeats the `cbtquantile` reasoning earlier in this comment: choosing 95 over
/// 99 to keep the two stages distinct achieves nothing while a floor set above
/// both fitted thresholds collapses them anyway.
///
/// So this is self-correcting rather than a fitted constant. At 30000 ms the
/// estimator finally observes the real tail; if p95 rises past 30 s the floor
/// stops binding and the adaptive fit takes over again, which is the designed
/// behaviour. 30 s is not arbitrary either — it is arti's own `min_timeout` for
/// the same "in case our estimate is ridiculously low" purpose in
/// `tor-hsservice`'s `estimate_upload_timeout` (`publish/reactor.rs:382`).
///
/// Trade-off: the floor applies to every circuit, so a genuinely dead path is
/// now held 30 s before being abandoned instead of 6 s. That is bounded by the
/// publisher's own `OVERALL_UPLOAD_TIMEOUT` of 5 minutes
/// (`publish/reactor.rs:130`), which is wall-clock and unchanged either way, so
/// the worst case costs fewer retries rather than more time.
///
/// This value is falsifiable, and the next capture settles it: if successes now
/// appear with `delay` between 6 s and 30 s, the deadline was converting live
/// circuits into failures and the change is confirmed. If instead all timeouts
/// simply re-pin at exactly 30 s with no successes above 6 s, those circuits
/// were genuinely dead, the floor only wasted more time per attempt, and this
/// should be reverted rather than raised further.
fn apply_mobile_net_params(cfg: &mut TorClientConfigBuilder) {
    cfg.override_net_params().insert("cbtquantile".into(), 95);
    cfg.override_net_params().insert("cbtmintimeout".into(), 30000);
}

fn start_inner(
    data_dir: &str,
    nickname: &str,
    key_bytes: [u8; 64],
    local_port: u16,
) -> Result<(OnionHost, String), Box<dyn Error>> {
    ensure_logger();
    apply_trace_filter_file(data_dir);
    ensure_crypto_provider();

    // Clean up any error log from a previous failed start attempt.
    let _ = std::fs::remove_file(std::path::Path::new(data_dir).join("torhost_error.log"));

    // Rebuild the HS identity keypair from our expanded 64 bytes (canonical
    // reduced scalar ‖ prefix — the ed25519-expanded@spec.torproject.org form
    // the Go side derives). from_secret_key_bytes reduces mod L, a no-op on our
    // already-canonical scalar.
    let expanded = ExpandedKeypair::from_secret_key_bytes(key_bytes)
        .ok_or("invalid expanded onion secret key")?;
    let id_keypair = HsIdKeypair::from(expanded);

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;

    let arti_dir = PathBuf::from(data_dir).join("arti");
    let state_dir = arti_dir.clone();
    let nick = HsNickname::new(nickname.to_string())?;

    // Keep all Arti state (including the keystore) under our data dir, and
    // enable the keystore — without it, launch reports KeystoreRequired.
    // Both state_dir AND cache_dir must be set explicitly: Android has no $HOME
    // or XDG dirs, so arti's default path resolution fails ("unable to determine
    // HOME directory"). cache/ holds the non-secret consensus cache and is a
    // sibling of the keystore/hss that torhost_stop wipes.
    let mut cfg = TorClientConfig::builder();
    cfg.storage()
        .state_dir(CfgPath::new_literal(arti_dir))
        .cache_dir(CfgPath::new_literal(state_dir.join("cache")))
        .keystore()
        .enabled(BoolOrAuto::Explicit(true));
    // Android's per-app storage does not satisfy fs-mistrust's Unix ownership /
    // permission model, so it would reject the app data dir and fail before any
    // network activity. Disable those checks: the directory is already
    // app-private — created 0700, owned by the app uid, isolated by the Android
    // sandbox — so the guarantee mistrust provides is already given by the OS.
    // SECURITY NOTE: On rooted devices, the Android sandbox can be bypassed,
    // making this a defense-in-depth trade-off. The onion key file written to
    // this directory is plaintext; on a rooted device an attacker with shell
    // access can read it. This is documented and accepted: the threat model
    // excludes rooted devices (same as the PIN/device-key offline attack surface).
    cfg.storage().permissions().dangerously_trust_everyone();
    apply_mobile_net_params(&mut cfg);
    let cfg = cfg.build()?;

    let (client, service, onion) = rt.block_on(async {
        // create_unbootstrapped returns immediately; Tor bootstraps in the
        // background (spawned below). This is what keeps startOnion — and the
        // unlock/create HTTP response that blocks on it — from hanging 30-60s
        // while Tor comes up, which otherwise freezes the UI. It honours the
        // OnionService.Start contract ("does not block on bootstrap"); readiness
        // is reported separately via torhost_ready.
        let client = TorClient::builder().config(cfg).create_unbootstrapped()?;
        let svc_cfg = OnionServiceConfig::builder().nickname(nick).build()?;
        let (service, rend_stream) = client
            .launch_onion_service_with_hsid(svc_cfg, id_keypair)?
            .ok_or("onion service disabled in config")?;

        let onion = service
            .onion_address()
            .ok_or("onion service has no address yet")?
            .display_unredacted()
            .to_string();

        // Bootstrap proactively in the background rather than lazily on first
        // circuit use, so the service publishes as soon as possible — with retry
        // + backoff so an offline-at-unlock self-heals when the network returns.
        spawn_bootstrap(client.clone());

        // Report what the service itself thinks it is doing. Nothing else does:
        // torhost_ready exposes a single reachability bit, and arti's own
        // diagnostics go to `tracing`, which this shim does not subscribe to.
        spawn_status_watch(service.clone(), nickname.to_string());

        // Forward inbound rendezvous streams to the local Go public listener:
        // accept each request and splice it to 127.0.0.1:local_port. This is the
        // mobile equivalent of the desktop Arti config's proxy_ports forwarding.
        tokio::spawn(async move {
            let mut streams = handle_rend_requests(rend_stream);
            while let Some(request) = streams.next().await {
                tokio::spawn(async move {
                    // Dial the local listener FIRST, then accept: otherwise a
                    // failed local connect leaves us having already told the peer
                    // "connected" and immediately dropping them, rather than
                    // declining cleanly.
                    let mut local = match tokio::net::TcpStream::connect(("127.0.0.1", local_port)).await {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    let onion_stream = match request.accept(Connected::new_empty()).await {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    let mut onion_io = onion_stream.compat();
                    let _ = tokio::io::copy_bidirectional(&mut onion_io, &mut local).await;
                });
            }
        });

        Ok::<_, Box<dyn Error>>((client, service, onion))
    })?;

    Ok((
        OnionHost { rt, client, service: Some(service), extra_services: HashMap::new(), next_extra_id: 1, state_dir },
        onion,
    ))
}

/// Start Tor in client-only mode: bootstrap a TorClient for dialing peer onion
/// services WITHOUT publishing our own. A secondary device uses this — it must
/// not advertise the account address (that would collide with the primary on
/// the HSDir hashring) but still needs a transport to send messages and sync.
/// Returns a handle (null on failure).
///
/// # Safety
/// `data_dir` must be a valid, NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn torhost_start_client(data_dir: *const c_char) -> *mut OnionHost {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        torhost_start_client_inner(data_dir)
    })) {
        Ok(ptr) => ptr,
        Err(_) => {
            log::error!("torhost_start_client panicked");
            ptr::null_mut()
        }
    }
}

unsafe fn torhost_start_client_inner(data_dir: *const c_char) -> *mut OnionHost {
    if data_dir.is_null() {
        return ptr::null_mut();
    }
    let data_dir = match CStr::from_ptr(data_dir).to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => return ptr::null_mut(),
    };
    match start_client_inner(&data_dir) {
        Ok(host) => Box::into_raw(Box::new(host)),
        Err(e) => {
            log_start_error(&data_dir, e.as_ref());
            ptr::null_mut()
        }
    }
}

fn start_client_inner(data_dir: &str) -> Result<OnionHost, Box<dyn Error>> {
    ensure_logger();
    apply_trace_filter_file(data_dir);
    ensure_crypto_provider();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let arti_dir = PathBuf::from(data_dir).join("arti");
    let state_dir = arti_dir.clone();

    // Client mode must not carry the account onion key. Sweep any key material a
    // previous primary session left in this data dir BEFORE bootstrapping, so a
    // device demoted from primary to secondary never leaves the key on disk
    // (desktop parity: StartClient's removeKeyMaterial). Doing it here keeps the
    // promise self-contained rather than depending on the startup sweep.
    scrub_and_remove(state_dir.join("keystore"));
    scrub_and_remove(state_dir.join("hss"));

    // Same storage layout as host mode; we simply never launch a service, so no
    // HS key is inserted and the keystore stays empty on a secondary device.
    // Both state_dir AND cache_dir must be set explicitly: Android has no $HOME
    // or XDG dirs, so arti's default path resolution fails ("unable to determine
    // HOME directory"). cache/ holds the non-secret consensus cache and is a
    // sibling of the keystore/hss that torhost_stop wipes.
    let mut cfg = TorClientConfig::builder();
    cfg.storage()
        .state_dir(CfgPath::new_literal(arti_dir))
        .cache_dir(CfgPath::new_literal(state_dir.join("cache")))
        .keystore()
        .enabled(BoolOrAuto::Explicit(true));
    // Android's per-app storage does not satisfy fs-mistrust's Unix ownership /
    // permission model, so it would reject the app data dir and fail before any
    // network activity. Disable those checks: the directory is already
    // app-private — created 0700, owned by the app uid, isolated by the Android
    // sandbox — so the guarantee mistrust provides is already given by the OS.
    cfg.storage().permissions().dangerously_trust_everyone();
    apply_mobile_net_params(&mut cfg);
    let cfg = cfg.build()?;

    // Unbootstrapped + background bootstrap, so StartClient does not block the
    // secondary device's unlock on Tor coming up (see start_inner).
    let client = rt.block_on(async {
        let client = TorClient::builder().config(cfg).create_unbootstrapped()?;
        // Retry + backoff (not one-shot): an offline-at-unlock self-heals when the
        // network returns, instead of staying !dialable until a lazy dial forces it.
        spawn_bootstrap(client.clone());
        Ok::<_, Box<dyn Error>>(client)
    })?;
    Ok(OnionHost { rt, client, service: None, extra_services: HashMap::new(), next_extra_id: 1, state_dir })
}

/// Report whether the service descriptor has been published and is reachable.
///
/// # Safety
/// `h` must be a live handle from [`torhost_start`].
#[no_mangle]
pub unsafe extern "C" fn torhost_ready(h: *const OnionHost) -> c_int {
    if h.is_null() {
        return 0;
    }
    let host = &*h;
    match &host.service {
        // Host mode: reachable once the descriptor is published — Running
        // (fully) or DegradedReachable (enough intro points, descriptor up to
        // date). Every other state reports not-ready. This is the library
        // equivalent of the desktop sidecar keying readiness off the
        // "reuploading descriptor" log line.
        Some(service) => match service.status().state() {
            State::Running | State::DegradedReachable => 1,
            _ => 0,
        },
        // Client-only mode: this reports that bootstrap COMPLETED once (there is
        // no descriptor to publish). It is a one-shot signal, not live circuit
        // health — arti-client does not expose a cheap synchronous liveness
        // check here, and create_bootstrapped already blocked until bootstrap.
        None => 1,
    }
}

/// Report the onion service's own view of its state, as an opaque code the Go
/// side maps back to a named state. Codes (keep in step with
/// `tor.ServiceState` in backend/internal/tor/service.go):
///
///   0 unknown (no handle, or client-only mode — nothing is being published)
///   1 shutdown   2 bootstrapping   3 degraded-unreachable
///   4 running    5 degraded-reachable   6 recovering   7 broken
///
/// This exists for the publish watchdog. [`torhost_ready`] answers "can peers
/// reach me", which is the right question for the UI and the wrong one for
/// deciding whether to restart the service: a `false` there covers both "arti
/// is mid-publish and making progress" and "arti has given up", and restarting
/// in the first case throws away every in-flight HSDir upload and starts the
/// several-minute publish over. One observed restart discarded 14 in-flight
/// upload attempts and cost 6m35s. With the state readable, the watchdog can
/// restart only where a restart is the remedy.
///
/// # Safety
/// `h` must be a live handle from [`torhost_start`].
#[no_mangle]
pub unsafe extern "C" fn torhost_service_state(h: *const OnionHost) -> c_int {
    if h.is_null() {
        return 0;
    }
    let host = &*h;
    let Some(service) = &host.service else {
        return 0;
    };
    match service.status().state() {
        State::Shutdown => 1,
        State::Bootstrapping => 2,
        State::DegradedUnreachable => 3,
        State::Running => 4,
        State::DegradedReachable => 5,
        State::Recovering => 6,
        State::Broken => 7,
        // State is #[non_exhaustive]. An unrecognised state reports unknown,
        // which the Go side treats as "no opinion" and falls back to its
        // pre-existing timer-and-peer-traffic rule.
        _ => 0,
    }
}

/// Report whether the client has bootstrapped enough to build OUTBOUND circuits
/// — i.e. we can dial peer onion services to SEND. This is independent of, and
/// goes true well before, [`torhost_ready`] (which reports our own descriptor
/// being published for INBOUND reachability): bootstrap completes before the
/// service publishes. Sending only needs an outbound circuit, so the Go side
/// gates the send button on this, not on `torhost_ready`. `ready_for_traffic()`
/// is a synchronous snapshot of arti's bootstrap progress (no runtime needed).
///
/// # Safety
/// `h` must be a live handle from [`torhost_start`] or [`torhost_start_client`].
#[no_mangle]
pub unsafe extern "C" fn torhost_dialable(h: *const OnionHost) -> c_int {
    if h.is_null() {
        return 0;
    }
    let host = &*h;
    if host.client.bootstrap_status().ready_for_traffic() {
        return 1;
    }
    // ready_for_traffic normally goes true before publication, but if our
    // descriptor is already published we are certainly dialable — fall back to
    // the service state so a published (host-mode) service is never stuck
    // non-sendable, mirroring the desktop sidecar's OR of both markers.
    if let Some(service) = &host.service {
        if matches!(
            service.status().state(),
            State::Running | State::DegradedReachable
        ) {
            return 1;
        }
    }
    0
}

/// Toggle dormant mode on the Tor client. When `dormant` is non-zero, the
/// client enters `DormantMode::Soft` — proactive background tasks (preemptive
/// circuit building, directory fetches) are suspended, conserving CPU and
/// battery. Existing circuits and TCP connections stay alive. When `dormant`
/// is zero, the client returns to `DormantMode::Normal` and resumes proactive
/// work automatically.
///
/// This is called from Android when the app transitions between foreground and
/// background, so Tor stops doing unnecessary work while the screen is off
/// but remains reachable on existing circuits.
///
/// # Safety
/// `h` must be a live handle from [`torhost_start`] or [`torhost_start_client`].
#[no_mangle]
pub unsafe extern "C" fn torhost_set_dormant(h: *const OnionHost, dormant: c_int) {
    if h.is_null() {
        return;
    }
    let host = &*h;
    let mode = if dormant != 0 {
        DormantMode::Soft
    } else {
        DormantMode::Normal
    };
    host.client.set_dormant(mode);
}

/// Dial a peer onion service. `onion_host_port` is like "abcd….onion:80".
/// Returns a connected socket fd Go owns (wrap with os.NewFile + net.FileConn),
/// or -1 on error. Arti's DataStream is a Tor-circuit stream with no OS fd, so
/// we bridge it to one end of a UnixStream pair and hand the other end to Go.
///
/// `timeout_ms` bounds the connect: without it a dial to a dead/unreachable
/// onion blocks the calling (Go) thread for however long Arti's own timeouts
/// take, and the Go caller's context deadline — which is the real budget — is
/// ignored. Go derives this from that deadline. 0 means "use Arti's default"
/// (Go never passes 0 for a real dial; it returns early instead). The
/// bidirectional-copy task is spawned only AFTER connect succeeds, so a
/// timed-out connect leaves nothing running to leak.
///
/// # Safety
/// `h` must be a live handle; `onion_host_port` a valid C string.
#[no_mangle]
pub unsafe extern "C" fn torhost_dial(
    h: *const OnionHost,
    onion_host_port: *const c_char,
    timeout_ms: u64,
) -> RawFd {
    if h.is_null() || onion_host_port.is_null() {
        return -1;
    }
    let host = &*h;
    let target = match CStr::from_ptr(onion_host_port).to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => return -1,
    };
    match host.rt.block_on(dial_inner(&host.client, &target, timeout_ms)) {
        Ok(fd) => fd,
        Err(e) => {
            log::warn!("torhost dial failed for {target}: {e}");
            -1
        }
    }
}

async fn dial_inner(
    client: &TorClient<PreferredRuntime>,
    target: &str,
    timeout_ms: u64,
) -> Result<RawFd, Box<dyn Error>> {
    let connect = client.connect(target);
    let onion_stream = if timeout_ms == 0 {
        connect.await?
    } else {
        // A hung circuit build must not pin the Go thread past its budget.
        tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), connect)
            .await??
    };
    let (ours, theirs) = tokio::net::UnixStream::pair()?;
    tokio::spawn(async move {
        let mut onion_io = onion_stream.compat();
        let mut ours = ours;
        let _ = tokio::io::copy_bidirectional(&mut onion_io, &mut ours).await;
    });
    // Hand Go a blocking std fd it fully owns.
    let std_stream = theirs.into_std()?;
    std_stream.set_nonblocking(false)?;
    Ok(std_stream.into_raw_fd())
}

/// Stop the service, drop the client and runtime, and wipe the keystore so the
/// onion key does not outlive the session (desktop parity).
///
/// # Safety
/// `h` must be a handle from [`torhost_start`]; invalid after this call.
#[no_mangle]
pub unsafe extern "C" fn torhost_stop(h: *mut OnionHost) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unsafe { torhost_stop_inner(h) }
    }));
}

unsafe fn torhost_stop_inner(h: *mut OnionHost) {
    if h.is_null() {
        return;
    }
    let OnionHost { rt, client, service, extra_services, next_extra_id: _, state_dir } = *Box::from_raw(h);
    // Abort each alias forwarder and drop its service so no rotation alias
    // outlives the session; the keystore/hss scrub below covers their keys too.
    for (_, es) in extra_services {
        es.forwarder.abort();
        drop(es.service);
    }
    // Drop the service and client so their background tasks wind down, then
    // BOUND the runtime teardown. Dropping the Runtime implicitly would block
    // until every spawned copy task finished — e.g. an idle peer connection from
    // torhost_dial — which could be never; and this runs on the path Android's
    // onDestroy blocks on. Same bounded-shutdown rule, one layer down.
    drop(service);
    drop(client);
    rt.shutdown_timeout(std::time::Duration::from_secs(3));
    // Wipe key material so the onion key does not outlive the session (desktop
    // parity: both the keystore and the hss runtime state, matching the desktop
    // sidecar's removeKeyMaterial). Overwrite files before unlink to defeat
    // forensic recovery on flash/SSD (wear-leveling).
    scrub_and_remove(state_dir.join("keystore"));
    scrub_and_remove(state_dir.join("hss"));
}

/// Stop only the onion service, keeping the TorClient and runtime alive for a
/// fast restart. This avoids the 3-second shutdown penalty and the full
/// re-bootstrap on re-unlock: the bootstrapped client stays warm, and only a
/// new onion service needs to be launched (~0.5s vs ~15s cold start).
/// Wipes the keystore so the onion key does not outlive the session.
///
/// # Safety
/// `h` must be a live handle from [`torhost_start`] or [`torhost_start_client`].
#[no_mangle]
pub unsafe extern "C" fn torhost_stop_service(h: *mut OnionHost) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unsafe { torhost_stop_service_inner(h) }
    }));
}

unsafe fn torhost_stop_service_inner(h: *mut OnionHost) {
    if h.is_null() {
        return;
    }
    let host = &mut *h;
    host.service = None;
    // Skip the blanket keystore/hss scrub while rotation aliases are live: those
    // dirs now also hold the aliases' key material, and scrubbing them here (this
    // runs on lock-grace teardown and on the publish watchdog's primary restart)
    // would wipe live aliases' on-disk keys. The primary key sitting on disk for
    // the rest of an ACTIVE session is acceptable — torhost_stop scrubs
    // everything at session end regardless. With no aliases, behaviour is
    // unchanged (scrub now, so the primary key never outlives its service).
    if host.extra_services.is_empty() {
        scrub_and_remove(host.state_dir.join("keystore"));
        scrub_and_remove(host.state_dir.join("hss"));
    }
}

/// Launch a new onion service on an existing (bootstrapped) TorClient. This is
/// the fast path for re-unlock: the client is already bootstrapped from a
/// previous session or pre-warm, so we only need to register the service and
/// publish the descriptor (~1-8s) instead of bootstrapping from scratch (~15s).
///
/// Returns 1 on success (and writes the .onion address to `out_onion`), 0 on
/// failure. The handle must already have a live TorClient (from a prior
/// `torhost_start` or `torhost_start_client` call whose service was stopped
/// via `torhost_stop_service`).
///
/// # Safety
/// `h` must be a live handle; `nickname` a valid C string; `key_ptr`/`key_len`
/// must describe a readable 64-byte buffer.
#[no_mangle]
pub unsafe extern "C" fn torhost_start_service(
    h: *mut OnionHost,
    nickname: *const c_char,
    key_ptr: *const u8,
    key_len: usize,
    local_port: u16,
    out_onion: *mut *mut c_char,
) -> c_int {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unsafe { torhost_start_service_inner(h, nickname, key_ptr, key_len, local_port, out_onion) }
    })) {
        Ok(r) => r,
        Err(_) => {
            log::error!("torhost_start_service panicked");
            0
        }
    }
}

unsafe fn torhost_start_service_inner(
    h: *mut OnionHost,
    nickname: *const c_char,
    key_ptr: *const u8,
    key_len: usize,
    local_port: u16,
    out_onion: *mut *mut c_char,
) -> c_int {
    if h.is_null() || nickname.is_null() || key_ptr.is_null() || key_len != 64 {
        return 0;
    }
    let host = &mut *h;
    if host.service.is_some() {
        return 0; // already running
    }
    let nickname = match CStr::from_ptr(nickname).to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => return 0,
    };
    let mut key_bytes = [0u8; 64];
    key_bytes.copy_from_slice(slice::from_raw_parts(key_ptr, 64));

    let expanded = match ExpandedKeypair::from_secret_key_bytes(key_bytes) {
        Some(k) => k,
        None => {
            unsafe { std::ptr::write_volatile(&mut key_bytes as *mut _, [0u8; 64]); }
            return 0;
        }
    };
    // Zero key material from the stack after use.
    unsafe { std::ptr::write_volatile(&mut key_bytes as *mut _, [0u8; 64]); }
    let id_keypair = HsIdKeypair::from(expanded);
    // Kept for the status-watch label: HsNickname::new consumes the String.
    let nick_label = nickname.clone();
    let nick = match HsNickname::new(nickname) {
        Ok(n) => n,
        Err(_) => return 0,
    };

    let local_port_u16 = local_port;
    let result = host.rt.block_on(async {
        let svc_cfg = OnionServiceConfig::builder().nickname(nick).build()?;
        let (service, rend_stream) = host
            .client
            .launch_onion_service_with_hsid(svc_cfg, id_keypair)?
            .ok_or("onion service disabled in config")?;

        let onion = service
            .onion_address()
            .ok_or("onion service has no address yet")?
            .display_unredacted()
            .to_string();

        spawn_status_watch(service.clone(), nick_label);

        // Forward inbound rendezvous streams to the local Go public listener.
        tokio::spawn(async move {
            let mut streams = handle_rend_requests(rend_stream);
            while let Some(request) = streams.next().await {
                tokio::spawn(async move {
                    let mut local =
                        match tokio::net::TcpStream::connect(("127.0.0.1", local_port_u16)).await {
                            Ok(c) => c,
                            Err(_) => return,
                        };
                    let onion_stream = match request.accept(Connected::new_empty()).await {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    let mut onion_io = onion_stream.compat();
                    let _ = tokio::io::copy_bidirectional(&mut onion_io, &mut local).await;
                });
            }
        });

        Ok::<_, Box<dyn Error>>((service, onion))
    });

    match result {
        Ok((service, onion)) => {
            host.service = Some(service);
            if !out_onion.is_null() {
                if let Ok(c) = CString::new(onion) {
                    *out_onion = c.into_raw();
                }
            }
            1
        }
        Err(e) => {
            log::warn!("torhost_start_service failed: {e}");
            0
        }
    }
}

/// Launch an ADDITIONAL onion service (a rotation alias) alongside the primary,
/// on the existing bootstrapped TorClient. Unlike [`torhost_start_service`] this
/// does NOT touch the primary `service` slot: it registers a new service, spawns
/// its own rendezvous-forwarder (whose JoinHandle is retained so it can be
/// aborted), and returns a fresh non-zero id. Returns 0 on failure.
///
/// `nickname` MUST be distinct from the primary's and from every other live
/// alias — arti keys hidden-service state by nickname, so a collision would
/// clobber another service's descriptor. The Go side allocates per-alias
/// nicknames. `local_port` is the loopback port inbound streams are spliced to
/// (a dedicated alias listener, not necessarily the primary's).
///
/// # Safety
/// `h` must be a live handle with a bootstrapped client (from `torhost_start` or
/// `torhost_start_client`); `nickname` a valid C string; `key_ptr`/`key_len` a
/// readable 64-byte buffer.
#[no_mangle]
pub unsafe extern "C" fn torhost_start_extra_service(
    h: *mut OnionHost,
    nickname: *const c_char,
    key_ptr: *const u8,
    key_len: usize,
    local_port: u16,
    out_onion: *mut *mut c_char,
) -> u64 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unsafe { torhost_start_extra_service_inner(h, nickname, key_ptr, key_len, local_port, out_onion) }
    })) {
        Ok(id) => id,
        Err(_) => {
            log::error!("torhost_start_extra_service panicked");
            0
        }
    }
}

unsafe fn torhost_start_extra_service_inner(
    h: *mut OnionHost,
    nickname: *const c_char,
    key_ptr: *const u8,
    key_len: usize,
    local_port: u16,
    out_onion: *mut *mut c_char,
) -> u64 {
    if h.is_null() || nickname.is_null() || key_ptr.is_null() || key_len != 64 {
        return 0;
    }
    let host = &mut *h;
    let nickname = match CStr::from_ptr(nickname).to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => return 0,
    };
    let mut key_bytes = [0u8; 64];
    key_bytes.copy_from_slice(slice::from_raw_parts(key_ptr, 64));

    let expanded = match ExpandedKeypair::from_secret_key_bytes(key_bytes) {
        Some(k) => k,
        None => {
            unsafe { std::ptr::write_volatile(&mut key_bytes as *mut _, [0u8; 64]); }
            return 0;
        }
    };
    unsafe { std::ptr::write_volatile(&mut key_bytes as *mut _, [0u8; 64]); }
    let id_keypair = HsIdKeypair::from(expanded);
    // Kept for the status-watch label: HsNickname::new consumes the String.
    let nick_label = nickname.clone();
    let nick = match HsNickname::new(nickname) {
        Ok(n) => n,
        Err(_) => return 0,
    };

    let result = host.rt.block_on(async {
        let svc_cfg = OnionServiceConfig::builder().nickname(nick).build()?;
        let (service, rend_stream) = host
            .client
            .launch_onion_service_with_hsid(svc_cfg, id_keypair)?
            .ok_or("onion service disabled in config")?;

        let onion = service
            .onion_address()
            .ok_or("onion service has no address yet")?
            .display_unredacted()
            .to_string();

        spawn_status_watch(service.clone(), nick_label);

        // Forward inbound rendezvous streams to this alias's local listener.
        // Retain the JoinHandle so torhost_stop_service_by_id can abort it.
        let forwarder = tokio::spawn(async move {
            let mut streams = handle_rend_requests(rend_stream);
            while let Some(request) = streams.next().await {
                tokio::spawn(async move {
                    let mut local = match tokio::net::TcpStream::connect(("127.0.0.1", local_port)).await {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    let onion_stream = match request.accept(Connected::new_empty()).await {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    let mut onion_io = onion_stream.compat();
                    let _ = tokio::io::copy_bidirectional(&mut onion_io, &mut local).await;
                });
            }
        });

        Ok::<_, Box<dyn Error>>((service, forwarder, onion))
    });

    match result {
        Ok((service, forwarder, onion)) => {
            let id = host.next_extra_id;
            host.next_extra_id += 1;
            host.extra_services.insert(id, ExtraService { service, forwarder });
            if !out_onion.is_null() {
                if let Ok(c) = CString::new(onion) {
                    *out_onion = c.into_raw();
                }
            }
            id
        }
        Err(e) => {
            log::warn!("torhost_start_extra_service failed: {e}");
            0
        }
    }
}

/// Stop and drop a single rotation alias started by
/// [`torhost_start_extra_service`], by its id. Aborts the alias's forwarder and
/// drops its service (which unpublishes the descriptor). Does NOT scrub the
/// keystore — the primary service and other aliases share it; the alias key is
/// deterministically re-derivable from the seed and is cleared wholesale at
/// session end by [`torhost_stop`]. A no-op if the id is unknown.
///
/// # Safety
/// `h` must be a live handle from [`torhost_start`] or [`torhost_start_client`].
#[no_mangle]
pub unsafe extern "C" fn torhost_stop_service_by_id(h: *mut OnionHost, id: u64) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if h.is_null() {
            return;
        }
        let host = unsafe { &mut *h };
        if let Some(es) = host.extra_services.remove(&id) {
            es.forwarder.abort();
            drop(es.service);
        }
    }));
}

/// Report the bootstrap completion as a fraction from 0.0 (just started) to
/// 1.0 (fully bootstrapped). This is a synchronous snapshot — no runtime
/// needed — and covers both circuit bootstrap and directory readiness.
///
/// # Safety
/// `h` must be a live handle from [`torhost_start`] or [`torhost_start_client`].
#[no_mangle]
pub unsafe extern "C" fn torhost_bootstrap_frac(h: *const OnionHost) -> c_float {
    if h.is_null() {
        return 0.0;
    }
    let host = &*h;
    host.client.bootstrap_status().as_frac()
}

/// Return the number of lines currently in the log ring buffer.
#[no_mangle]
pub extern "C" fn torhost_log_count() -> c_int {
    let ring = LOG_RING.lock().unwrap_or_else(|e| e.into_inner());
    ring.lines.len() as c_int
}

/// Return the Nth line from the log ring buffer (0 = oldest). The caller must
/// free the returned string with [`torhost_free_string`]. Returns null if the
/// index is out of range.
///
/// # Safety
/// `idx` must be in range [0, torhost_log_count()).
#[no_mangle]
pub unsafe extern "C" fn torhost_log_line(idx: c_int) -> *mut c_char {
    let ring = LOG_RING.lock().unwrap_or_else(|e| e.into_inner());
    match ring.lines.get(idx as usize) {
        Some(line) => match CString::new(line.as_str()) {
            Ok(c) => c.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        None => ptr::null_mut(),
    }
}

/// Free a C string returned by this library.
///
/// # Safety
/// `s` must be a string from this library, freed exactly once.
#[no_mangle]
pub unsafe extern "C" fn torhost_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // An override arti does not recognize is not an error: from_map logs it at
    // debug level and keeps the consensus default. So assert the round trip —
    // our key reaches the parameter arti's Pareto estimator reads, with the
    // value we asked for and not a bounds-clamped one.
    #[test]
    fn mobile_net_params_reach_the_circuit_timeout_estimator() {
        let mut cfg = TorClientConfig::builder();
        apply_mobile_net_params(&mut cfg);

        let mut map = tor_netdoc::doc::netstatus::NetParams::new();
        for (k, v) in cfg.override_net_params().iter() {
            map.set(k.clone(), *v);
        }
        let params = tor_netdir::params::NetParameters::from_map(&map);

        assert_eq!(
            params.cbt_timeout_quantile.as_percent().get(),
            95,
            "cbtquantile did not take effect; arti is still using its default"
        );
        // Left at the consensus default on purpose: the abandon threshold is
        // max'd against the timeout threshold, so raising ours to meet it would
        // collapse arti's two-stage timeout into one. That only preserves the
        // distinction while both fitted thresholds exceed cbt_min_timeout,
        // though — pareto.rs:549-550 floors both against it, so a floor set
        // above both collapses them whatever the quantiles say. See
        // apply_mobile_net_params for why that matters.
        assert_eq!(params.cbt_abandon_quantile.as_percent().get(), 99);

        // The floor is what the 2026-10-22 capture actually moved, and it is
        // the one value a silent bounds clamp would defeat: the permitted range
        // is [10, i32::MAX] ms, so assert 30000 survives the round trip whole.
        assert_eq!(
            std::time::Duration::try_from(params.cbt_min_timeout).unwrap(),
            std::time::Duration::from_secs(30),
            "cbtmintimeout did not take effect; builds will be cut at arti's default floor"
        );
    }

    // The ring is the only place a diagnostic can be lost silently: an evicted
    // line looks exactly like a line that was never written.
    #[test]
    fn ring_collapses_only_consecutive_repeats() {
        let mut r = Ring::new();
        r.push("dial failed".into());
        r.push("dial failed".into());
        r.push("dial failed".into());
        assert_eq!(r.lines.len(), 1);
        assert_eq!(r.lines.back().unwrap(), "dial failed (x3)");

        // An interleaved message must not be swallowed into the count, and must
        // reset it — otherwise a later repeat would claim attempts it never had.
        r.push("status: Running".into());
        r.push("dial failed".into());
        r.push("dial failed".into());
        let lines: Vec<_> = r.lines.iter().cloned().collect();
        assert_eq!(lines, vec!["dial failed (x3)", "status: Running", "dial failed (x2)"]);
    }

    // A line is capped mid-flight, and String::truncate panics mid-codepoint —
    // which aborts the process across the extern "C" boundary. arti's tracing
    // output is not guaranteed ASCII, so this is a live path, not a hypothetical.
    #[test]
    fn truncate_chars_never_splits_a_codepoint() {
        // "aéb" is 4 bytes: 'é' occupies 1..3, so a cap of 2 lands inside it
        // and has to back off to 1.
        let mut s = String::from("aéb");
        truncate_chars(&mut s, 2);
        assert_eq!(s, "a");

        // On a boundary (3 is where 'b' starts), cut exactly there.
        let mut s = String::from("aéb");
        truncate_chars(&mut s, 3);
        assert_eq!(s, "aé");

        // Under the cap, untouched.
        let mut s = String::from("aéb");
        truncate_chars(&mut s, 64);
        assert_eq!(s, "aéb");

        // A line made entirely of multibyte characters must not go negative
        // looking for a boundary.
        let mut s = String::from("日本語");
        truncate_chars(&mut s, 2);
        assert_eq!(s, "");
    }

    // One test rather than several: TRACE_FILTER is process-global, so parallel
    // tests mutating it would race each other.
    //
    // The default matters as much as the capture does. arti at DEBUG is a
    // firehose into a 400-line ring, so a bridge that emitted anything before
    // being asked would evict the onion-service status transitions the ring
    // exists to carry.
    #[test]
    fn the_bridge_emits_only_what_the_filter_allows() {
        fn ring_find(needle: &str) -> Option<String> {
            let ring = LOG_RING.lock().unwrap_or_else(|e| e.into_inner());
            ring.lines.iter().find(|l| l.contains(needle)).cloned()
        }

        ensure_trace_bridge();

        set_trace_filter("");
        assert!(!trace_filter_allows("tor_hsservice", &Level::DEBUG));
        tracing::debug!(target: "tor_hsservice", "silent while the bridge is off");
        assert_eq!(ring_find("silent while the bridge is off"), None);

        set_trace_filter("tor_hsservice=debug");
        assert!(trace_filter_allows("tor_hsservice", &Level::DEBUG));
        // Child modules of an enabled target come along — ipt_mgr is the one
        // that knows why intro-point establishment stalled.
        assert!(trace_filter_allows("tor_hsservice::ipt_mgr", &Level::WARN));
        // Below the requested level, and unrelated targets, stay out.
        assert!(!trace_filter_allows("tor_hsservice", &Level::TRACE));
        assert!(!trace_filter_allows("tor_circmgr", &Level::DEBUG));

        tracing::debug!(target: "tor_hsservice", attempt = 3, "establishing intro point");
        let line = ring_find("establishing intro point")
            .expect("an allowed tracing event never reached the ring");
        assert!(line.starts_with("[DEBUG] tor_hsservice: "), "{line}");
        // Structured fields carry the detail the prose leaves out.
        assert!(line.contains("attempt=3"), "{line}");

        // A typo must not silently end a capture that is already running.
        set_trace_filter("tor_hsservice=notalevel");
        assert!(trace_filter_allows("tor_hsservice", &Level::DEBUG));

        set_trace_filter("off");
        assert!(!trace_filter_allows("tor_hsservice", &Level::DEBUG));

        set_trace_filter(DEFAULT_TRACE_FILTER);
        assert!(trace_filter_allows("tor_hsservice", &Level::INFO));
        assert!(!trace_filter_allows("tor_hsservice", &Level::DEBUG));
        assert!(trace_filter_allows("tor_circmgr::timeouts", &Level::INFO));
        assert!(!trace_filter_allows("tor_circmgr", &Level::INFO));

        set_trace_filter("");
        assert!(!trace_filter_allows("tor_hsservice", &Level::DEBUG));
    }

    #[test]
    fn ring_evicts_oldest_at_capacity() {
        let mut r = Ring::new();
        for i in 0..LOG_RING_CAP + 10 {
            r.push(format!("line {i}"));
        }
        assert_eq!(r.lines.len(), LOG_RING_CAP);
        assert_eq!(r.lines.front().unwrap(), "line 10");
    }

    // A RetryError prints its attempts one per line; the Go side logs the ring
    // line by line, so a multi-line entry would arrive as several lines that
    // each look like a separate event.
    // The whole point of the reupload rendering: the same state, before and
    // after a publish, means opposite things.
    #[test]
    fn a_bootstrapping_after_publishing_renders_as_a_reupload() {
        // Before any publish, Bootstrapping means exactly what it says.
        assert_eq!(render_state(State::Bootstrapping, false), "Bootstrapping");

        let after = render_state(State::Bootstrapping, true);
        assert!(
            after.starts_with("Bootstrapping"),
            "an existing `grep Bootstrapping` over tormsg.log must still match: {after}"
        );
        assert!(after.contains("reupload"), "{after}");
        assert_ne!(
            after,
            render_state(State::Bootstrapping, false),
            "the two cases must stay distinguishable in the log"
        );

        // Every other state must render identically either way. The latch
        // explains one benign state; it must never rewrite a real problem
        // (DegradedUnreachable, Broken) into reassurance.
        for st in [
            State::Shutdown,
            State::DegradedUnreachable,
            State::Running,
            State::DegradedReachable,
            State::Recovering,
            State::Broken,
        ] {
            assert_eq!(
                render_state(st, true),
                render_state(st, false),
                "{st:?} must not be affected by the publish latch"
            );
        }
    }

    // The latch describes one publication, so it has to die with it. Mirrors the
    // match in spawn_status_watch; a stale `true` would report a live descriptor
    // through a genuine cold restart.
    #[test]
    fn shutdown_or_broken_clears_the_publish_latch() {
        for (states, want) in [
            (vec![State::Running], true),
            (vec![State::DegradedReachable], true),
            (vec![State::Running, State::Shutdown], false),
            (vec![State::Running, State::Broken], false),
            // A dip through a transient state keeps it: these are exactly the
            // reuploads the rendering exists to explain.
            (vec![State::Running, State::Bootstrapping], true),
            (vec![State::Running, State::DegradedUnreachable], true),
            (vec![State::Running, State::Recovering], true),
            // ...and it re-arms after a real restart republishes.
            (vec![State::Running, State::Shutdown, State::Running], true),
        ] {
            let mut published_once = false;
            for st in &states {
                update_publish_latch(&mut published_once, *st);
            }
            assert_eq!(published_once, want, "{states:?}");
        }
    }

    #[test]
    fn one_line_folds_multiline_reports() {
        let got = one_line("Tried to upload 3 times:\n  attempt 1: timeout\n\n  attempt 2: no path");
        assert_eq!(got, "Tried to upload 3 times:; attempt 1: timeout; attempt 2: no path");
    }
}
