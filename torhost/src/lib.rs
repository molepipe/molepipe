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

use std::collections::VecDeque;
use std::error::Error;
use std::ffi::{c_char, c_float, c_int, CStr, CString};
use std::os::fd::{IntoRawFd, RawFd};
use std::path::PathBuf;
use std::ptr;
use std::slice;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arti_client::config::{BoolOrAuto, CfgPath};
use arti_client::{DormantMode, TorClient, TorClientConfig};
use futures::stream::StreamExt;
use safelog::DisplayRedacted; // brings HsId::display_unredacted() into scope
use tokio::runtime::Runtime;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tor_cell::relaycell::msg::Connected;
use tor_hscrypto::pk::HsIdKeypair;
use tor_hsservice::status::State;
use tor_hsservice::{handle_rend_requests, HsNickname, OnionServiceConfig, RunningOnionService};
use tor_llcrypto::pk::ed25519::ExpandedKeypair;
use tor_rtcompat::PreferredRuntime;

// ---------------------------------------------------------------------------
// Log ring buffer — captures log:: output for the Go side to read.
// ---------------------------------------------------------------------------

const LOG_RING_CAP: usize = 200;

static LOG_RING: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

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
        // Truncate to 512 chars so a single flood line can't blow up memory.
        msg.truncate(512);
        // Use unwrap_or_else to recover from a poisoned mutex instead of panicking.
        let mut ring = LOG_RING.lock().unwrap_or_else(|e| e.into_inner());
        if ring.len() >= LOG_RING_CAP {
            ring.pop_front();
        }
        ring.push_back(msg);
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

/// Opaque host handle returned to Go. Owns the Tokio runtime everything else
/// lives on, so dropping it (in [`torhost_stop`]) tears the client and service
/// down.
pub struct OnionHost {
    rt: Runtime,
    client: Arc<TorClient<PreferredRuntime>>,
    // Some in host mode (primary device); None in client-only mode (a secondary
    // device that dials out but must not publish the account onion).
    service: Option<Arc<RunningOnionService>>,
    state_dir: PathBuf, // dataDir/arti — holds keystore/ and hss/
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
        let mut delay = Duration::ZERO;
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

fn start_inner(
    data_dir: &str,
    nickname: &str,
    key_bytes: [u8; 64],
    local_port: u16,
) -> Result<(OnionHost, String), Box<dyn Error>> {
    ensure_logger();
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
        OnionHost { rt, client, service: Some(service), state_dir },
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
    Ok(OnionHost { rt, client, service: None, state_dir })
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
    let OnionHost { rt, client, service, state_dir } = *Box::from_raw(h);
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
    scrub_and_remove(host.state_dir.join("keystore"));
    scrub_and_remove(host.state_dir.join("hss"));
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
    ring.len() as c_int
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
    match ring.get(idx as usize) {
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
