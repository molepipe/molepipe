#ifndef TORHOST_H
#define TORHOST_H

#include <stdint.h>
#include <stddef.h>

/* C ABI of the torhost Rust shim (see torhost/src/lib.rs). Onion-service
 * HOSTING and dialing over arti-client, linked into the gomobile build as a
 * static library. The onion secret key is passed in as raw bytes and never
 * leaves native memory. */

/* Opaque handle to a running onion host (Rust-owned). */
typedef void *torhost_handle;

/* Start hosting the onion service under the given 64-byte expanded secret key
 * (canonical reduced scalar || prefix), forwarding inbound streams to
 * 127.0.0.1:local_port. On success returns a non-NULL handle and writes a
 * malloc'd ".onion" C string to *out_onion (free with torhost_free_string).
 * Returns NULL on failure. */
torhost_handle torhost_start(const char *data_dir, const char *nickname,
                             const uint8_t *key_ptr, size_t key_len,
                             uint16_t local_port, char **out_onion);

/* Start Tor in client-only mode (dial out, do not publish an onion service).
 * A secondary device uses this. Returns a non-NULL handle or NULL on failure. */
torhost_handle torhost_start_client(const char *data_dir);

/* 1 if the service descriptor is published and reachable (INBOUND), else 0. */
int torhost_ready(torhost_handle h);

/* 1 if the client has bootstrapped enough to build OUTBOUND circuits (dial
 * peers to send), else 0. Goes true before torhost_ready; sending needs only
 * this. */
int torhost_dialable(torhost_handle h);

/* Dial "abcd....onion:80"; returns a connected socket fd the caller owns, or
 * -1 on failure. timeout_ms bounds the connect (0 = use Arti's default) so a
 * dial to a dead onion cannot block the caller past its context deadline. */
int torhost_dial(torhost_handle h, const char *onion_host_port, uint64_t timeout_ms);

/* Stop the service, free the handle, and wipe the keystore. */
void torhost_stop(torhost_handle h);

/* Stop only the onion service, keeping the TorClient and runtime alive for a
 * fast restart. Wipes the keystore. The handle remains valid. */
void torhost_stop_service(torhost_handle h);

/* Launch a new onion service on an existing (bootstrapped) TorClient. Returns 1
 * on success (and writes the .onion address to *out_onion), 0 on failure. The
 * handle must have a live TorClient from a prior torhost_start or
 * torhost_start_client call whose service was stopped with torhost_stop_service.
 */
int torhost_start_service(torhost_handle h, const char *nickname,
                          const uint8_t *key_ptr, size_t key_len,
                          uint16_t local_port, char **out_onion);

/* Launch an ADDITIONAL onion service (a rotation alias) alongside the primary,
 * on the existing bootstrapped TorClient. Unlike torhost_start_service this does
 * NOT touch the primary service slot. `nickname` MUST be distinct from the
 * primary's and every other live alias (arti keys HS state by nickname).
 * Returns a non-zero id on success (writing the .onion to *out_onion), or 0 on
 * failure. Stop it with torhost_stop_service_by_id. */
uint64_t torhost_start_extra_service(torhost_handle h, const char *nickname,
                                     const uint8_t *key_ptr, size_t key_len,
                                     uint16_t local_port, char **out_onion);

/* Stop and drop a single rotation alias by the id returned from
 * torhost_start_extra_service. Aborts its forwarder and unpublishes it; does not
 * scrub the shared keystore. No-op if the id is unknown. */
void torhost_stop_service_by_id(torhost_handle h, uint64_t id);

/* The onion service's own state, as an opaque code (0 unknown / no service,
 * 1 shutdown, 2 bootstrapping, 3 degraded-unreachable, 4 running,
 * 5 degraded-reachable, 6 recovering, 7 broken). Distinguishes "mid-publish
 * and progressing" from "given up", which torhost_ready's single bit cannot;
 * the publish watchdog needs that to avoid restarting a working publish. */
int torhost_service_state(torhost_handle h);

/* Bootstrap fraction (0.0 just started .. 1.0 fully bootstrapped). */
float torhost_bootstrap_frac(torhost_handle h);

/* Log ring buffer — recent torhost log lines for the frontend. */
int torhost_log_count(void);
char *torhost_log_line(int idx);

/* Free a C string returned by torhost_start. */
void torhost_free_string(char *s);

/* Pre-warm one-time global state (logger + rustls crypto provider) at app
 * startup so the first torhost_start does not pay the init cost. Safe to
 * call multiple times. */
void torhost_prewarm(void);

/* Set the arti tracing filter, e.g. "tor_hsservice=debug" (or several, comma
 * separated); "" or NULL turns it off, which is the default. arti reports its
 * internals through `tracing`, not `log`, so without a filter none of them
 * reach the log ring — which is why an onion-service publish stall shows up as
 * a bare "intro point failure" with no cause. Leave it off outside a
 * diagnosis: arti at DEBUG floods the 400-line ring and evicts the status
 * transitions. Normally set from <data_dir>/trace_filter at start instead, so
 * the capture covers the publish attempt right after unlock; this entry point
 * is for changing it on an already-running device. */
void torhost_set_trace_filter(const char *spec);

/* Toggle dormant mode. When dormant is non-zero, proactive background tasks
 * (preemptive circuit building, directory fetches) are suspended, conserving
 * CPU and battery. Existing connections stay alive. When dormant is zero,
 * the client resumes normal operation. Called from Android on fg/bg. */
void torhost_set_dormant(torhost_handle h, int dormant);

#endif /* TORHOST_H */
