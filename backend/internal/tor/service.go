// Package tor is the Tor-integration seam. It holds the OnionService interface
// and the pure derivation of a v3 onion-service identity key from our Ed25519
// signing key. It deliberately contains NO process spawning or OS assumptions —
// the desktop Arti sidecar (which shells out) lives in a separate package that
// only the desktop entrypoint imports, so this package stays portable to the
// eventual gomobile Android build.
package tor

import "context"

// OnionService publishes an onion service that forwards inbound Tor requests to
// a local address. Desktop implements this with an Arti sidecar; a future
// Android build supplies its own implementation over the same interface.
type OnionService interface {
	// Start publishes the service under the given onion key, forwarding the
	// virtual port to localAddr (e.g. "127.0.0.1:54321"), and returns the
	// .onion address. Start does not block on descriptor publication; the
	// service becomes reachable a short time later — see Ready.
	Start(ctx context.Context, key OnionKey, localAddr string) (onion string, err error)
	// StartClient brings Tor up WITHOUT publishing an onion service, for a
	// device that must dial out but must not advertise the account address.
	// A secondary device needs this: it still sends messages and syncs, and
	// Tor's SOCKS proxy is what carries that — so "don't publish" cannot mean
	// "don't run Tor", which would leave the device with no transport at all.
	StartClient(ctx context.Context) error
	// Ready reports whether the onion service descriptor has been published and
	// the service is reachable over Tor. It is false for a period after Start.
	// Ready gates INBOUND reachability only — whether peers can dial US (to
	// deliver messages or reply). It is NOT a prerequisite for sending.
	Ready() bool
	// Dialable reports whether outbound Tor circuits can be built yet — i.e. the
	// client has bootstrapped enough to reach peer onion services. Sending a
	// message dials the RECIPIENT's onion and completes over that single
	// outbound stream (challenge → sealed payload); it never needs our own
	// descriptor to be published. So send is gated on Dialable, not Ready, and
	// Dialable goes true well before Ready during startup (bootstrap finishes
	// before descriptor publication). In client-only mode Dialable == Ready.
	Dialable() bool
	// Dialer returns a dialer for connecting outbound to peer onion services.
	// Valid only while the service is running.
	Dialer() Dialer
	// Sweep removes any key material persisted by a previous run before the
	// service is started (e.g. after a crash that skipped Stop). Called at
	// startup while locked, so a leftover key never outlives its session.
	Sweep() error
	// Stop tears the service down.
	Stop() error
	// BootstrapFrac returns a rough fraction (0.0 to 1.0) of how far along
	// the Tor client's bootstrapping is. 0 = just started, 1 = fully ready.
	// Returns 0 when the service is not running.
	BootstrapFrac() float32
	// LogLines returns the most recent Tor log lines (Rust arti + Go backend).
	// Used by the frontend to display a connection log. May be nil.
	LogLines() []string
}
