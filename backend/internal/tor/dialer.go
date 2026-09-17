package tor

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/net/proxy"
)

// Dialer opens a TCP connection to a peer onion service. Desktop implements it
// over Arti's SOCKS proxy; a future Android build can implement it over Arti's
// library dialer. It is pure Go (no os/exec), so it stays in the portable core.
type Dialer interface {
	// DialOnion connects to onionHostPort, e.g. "abcd…xyz.onion:80".
	DialOnion(ctx context.Context, onionHostPort string) (net.Conn, error)
}

// SocksDialer dials onion services through a Tor SOCKS5 proxy. It sends the
// onion HOSTNAME to the proxy for resolution (SOCKS5h) — resolving a .onion
// locally is impossible, so the name must go to Arti.
type SocksDialer struct {
	// Addr is the loopback address of the SOCKS proxy (from Sidecar.SocksAddr).
	Addr string
}

// DialOnion dials the onion address through the SOCKS proxy.
func (d SocksDialer) DialOnion(ctx context.Context, onionHostPort string) (net.Conn, error) {
	if d.Addr == "" {
		return nil, fmt.Errorf("tor SOCKS proxy not available (is the onion service running?)")
	}
	// nil auth, proxy.Direct as the underlying dialer (unused: SOCKS resolves).
	dialer, err := proxy.SOCKS5("tcp", d.Addr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("build socks dialer: %w", err)
	}
	if cd, ok := dialer.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, "tcp", onionHostPort)
	}
	return dialer.Dial("tcp", onionHostPort)
}
