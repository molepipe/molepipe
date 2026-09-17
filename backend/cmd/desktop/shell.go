package main

import (
	"log"
	"os/exec"
	"runtime"

	"github.com/molepipe/molepipe/backend/internal/desktop"
)

// shell implements api.Desktop: the settings that only exist when there is a
// desktop shell around the server. Registering it is what makes the
// start-at-login toggle appear in the You tab; cmd/server registers nothing and
// the toggle stays hidden.
type shell struct {
	autostart *desktop.Autostart
	// broken records that we could not work out where autostart entries live
	// at all. The toggle is then reported unavailable rather than shown and
	// then failing on click.
	broken bool
}

func newShell(args ...string) *shell {
	a, err := desktop.New(args...)
	if err != nil {
		log.Printf("start-at-login unavailable: %v", err)
		return &shell{broken: true}
	}
	return &shell{autostart: a}
}

func (s *shell) AutostartAvailable() bool { return !s.broken && desktop.Supported() }

func (s *shell) AutostartEnabled() (bool, error) {
	if !s.AutostartAvailable() {
		return false, nil
	}
	return s.autostart.Enabled()
}

func (s *shell) SetAutostart(on bool) error {
	if !s.AutostartAvailable() {
		return errUnsupported
	}
	return s.autostart.Set(on)
}

// OpenExternal opens an http(s) URL in the user's default browser. The scheme
// has already been validated by the api server; this only launches the platform
// opener and does not block on it. Independent of autostart, so it works even
// when that is unavailable.
func (s *shell) OpenExternal(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
