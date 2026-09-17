//go:build !linux

package desktop

import (
	"errors"
	"os"
	"path/filepath"
)

// Start-at-login is implemented for Linux, which is what this project builds
// and tests. The others are stubs rather than errors at the call site: the UI
// asks Supported() and hides the toggle, so nothing here is ever reached in
// normal use — but Enabled/Set stay honest if something calls them anyway.
//
// A Windows Run key and a macOS LaunchAgent are the natural implementations
// when those builds exist.

// Supported reports whether start-at-login can be offered here.
func Supported() bool { return false }

func defaultDir() (string, error) {
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cfg, "autostart"), nil
}

// Enabled always reports off: with no mechanism, nothing can be enabled.
func (a *Autostart) Enabled() (bool, error) { return false, nil }

// Set refuses rather than pretending to have done something.
func (a *Autostart) Set(on bool) error {
	if !on {
		// Turning off what was never on is a no-op, not a failure — this is the
		// path the wipes take, and they must not report an error here.
		return nil
	}
	return errors.New("start at login is not implemented on this platform")
}
