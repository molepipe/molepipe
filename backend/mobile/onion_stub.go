//go:build !android && !ios

package mobile

import "github.com/molepipe/molepipe/backend/internal/tor"

// newOnionService returns nil off Android and iOS: the backend runs Tor-disabled,
// which keeps the host build and mobile_test.go free of any cgo/Arti
// dependency. The real implementations are in onion_android.go and onion_ios.go.
// See the seam note in mobile.go.
func newOnionService(dataDir string) tor.OnionService {
	_ = dataDir
	return nil
}
