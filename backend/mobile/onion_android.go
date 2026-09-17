//go:build android

package mobile

import (
	"github.com/molepipe/molepipe/backend/internal/tor"
	"github.com/molepipe/molepipe/backend/internal/tor/artihost"
)

// newOnionService wires the Arti-backed onion host (the torhost Rust shim, via
// cgo) as the tor.OnionService for Android builds. See the seam note in
// mobile.go.
func newOnionService(dataDir string) tor.OnionService {
	return artihost.New(dataDir)
}
