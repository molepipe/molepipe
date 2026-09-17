//go:build !android

package mobile

import "github.com/molepipe/molepipe/backend/internal/tor"

// newOnionService returns nil off Android: the backend runs Tor-disabled, which
// keeps the host build and mobile_test.go free of any cgo/Arti dependency. The
// real implementation is in onion_android.go. See the seam note in mobile.go.
func newOnionService(dataDir string) tor.OnionService {
	_ = dataDir
	return nil
}
