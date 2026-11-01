// Package porthint remembers the loopback port the control UI was last served
// on, so the next process can ask for the same one.
//
// This exists because the UI is a web page served over loopback and its
// localStorage is keyed by ORIGIN — and the origin includes the port. With an
// OS-assigned port every restart gets a brand-new, empty localStorage and
// strands the previous one on disk, so the theme, accent, PIN-shuffle and
// notification preferences (and a half-finished setup wizard's resume point)
// silently revert to defaults on every reinstall, reboot, OS kill or restart.
// The abandoned stores pile up too, one per launch.
//
// It is a shared package rather than a helper in each front end because it was
// previously implemented on the Android side only: desktop bound ":0" every
// launch and quietly reset its settings each time. Two copies of this is how
// that happened, so there is one copy and both callers use it.
//
// Pinning the port costs nothing in security. 127.0.0.1 is shared between apps
// on Android, so what keeps another process off /api is the capability token in
// the bootstrap URL, never the port being hard to guess — a port is trivially
// discoverable either way.
//
// Everything here is advisory: a missing, unreadable or stale hint just means
// an OS-assigned port and one round of reset preferences. No error is returned
// for that reason — there is no caller action for "could not remember a port".
package porthint

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// File is the hint's name inside the data directory. Changing it orphans every
// existing install's pinned port (one reset each), so it does not change.
const File = "port"

// Read returns the remembered port as a bare number ("54321"), or "" if there
// is nothing usable to reuse.
func Read(dataDir string) string {
	b, err := os.ReadFile(filepath.Join(dataDir, File))
	if err != nil {
		return ""
	}
	p := strings.TrimSpace(string(b))
	// Only ever hand a plain port number to net.Listen. The file is inside the
	// app's own data directory, but it is still parsed rather than trusted:
	// anything else in it would otherwise be concatenated straight into a
	// listen address. Ports below 1024 are rejected as well as unparseable
	// ones — they need privileges this process does not have, so a hint naming
	// one can only ever fail to bind.
	n, err := strconv.Atoi(p)
	if err != nil || n < 1024 || n > 65535 {
		return ""
	}
	return p
}

// Write records the port actually bound. Silent on failure, by design: losing
// the hint costs one round of reset preferences, which is not worth failing a
// successful startup over.
func Write(dataDir, port string) {
	if port == "" {
		return
	}
	_ = os.WriteFile(filepath.Join(dataDir, File), []byte(port), 0o600)
}

// Addr builds the listen address to try first: the remembered port if there is
// one, otherwise an OS-assigned port. The second return reports whether a hint
// was actually used, which is what tells a caller whether a bind failure is
// worth retrying on ":0" — see the package comment on advisory behaviour.
func Addr(dataDir string) (addr string, hinted bool) {
	if p := Read(dataDir); p != "" {
		return "127.0.0.1:" + p, true
	}
	return "127.0.0.1:0", false
}
