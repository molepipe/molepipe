// Package desktop holds the OS glue the packaged desktop build needs: a
// start-at-login entry, and a native notification for telling the user the app
// is still running after its window is closed.
//
// It is deliberately outside internal/api. The api package is the portable
// core that a future gomobile build compiles, and none of this belongs there —
// but api does reference the autostart entry in one place (the wipe paths), for
// the reason given on RemoveEntry.
//
// Nothing here touches keys, messages, or the identity.
package desktop

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// EntryName is the autostart file this app owns. Named after the app, not the
// account, so it says nothing about who uses the machine.
const EntryName = "molepipe.desktop"

// Autostart is a start-at-login entry for one installation of the app.
//
// Exec is stored rather than assumed because the launch command has to survive
// the ways this app actually gets installed: unpacked from a tarball into an
// arbitrary folder, and run against a chosen -data-dir. An entry that launched
// a moved binary, or the right binary against the wrong data directory, would
// be worse than no entry at all — it would start a second, empty account.
type Autostart struct {
	// Dir is the directory holding autostart entries. Empty means the OS
	// default; tests set it explicitly.
	Dir string
	// Exec is the absolute path of the binary to launch.
	Exec string
	// Args are the arguments it needs — in practice -data-dir, when the app is
	// not running against the default one.
	Args []string
}

// New builds an Autostart for the currently running executable, carrying args
// forward so a login launch lands on the same data directory as this one.
func New(args ...string) (*Autostart, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate this executable: %w", err)
	}
	// Resolve symlinks so an entry written today still points at the real
	// binary after the symlink that launched it is replaced or removed.
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	dir, err := defaultDir()
	if err != nil {
		return nil, err
	}
	return &Autostart{Dir: dir, Exec: exe, Args: args}, nil
}

// Path is the entry's location on disk.
func (a *Autostart) Path() string { return filepath.Join(a.Dir, EntryName) }

// RemoveEntry deletes any autostart entry this app owns, wherever it lives.
//
// This exists to be called from the wipe paths, and it is the reason the api
// package imports this one. The entry sits OUTSIDE the data directory, so
// erasing the account would otherwise leave a file called "Molepipe"
// pointing at a data directory on a machine whose owner has just told the app
// to remove every trace of itself. After a duress wipe that is not untidiness,
// it is the wipe announcing itself.
//
// Best-effort by design: a missing entry, a missing directory, or a platform
// with no such concept are all success. It ignores Exec entirely — the goal is
// that no entry survives, including one written by an installation that has
// since moved.
func RemoveEntry() error {
	dir, err := defaultDir()
	if err != nil {
		return nil
	}
	a := &Autostart{Dir: dir}
	if err := os.Remove(a.Path()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// command is the full launch command line, quoted for a desktop entry's Exec
// key. Paths chosen by the user (an unpack folder, a -data-dir) can contain
// spaces, so quoting is not optional.
func (a *Autostart) command() string {
	parts := make([]string, 0, len(a.Args)+1)
	for _, p := range append([]string{a.Exec}, a.Args...) {
		parts = append(parts, quoteExec(p))
	}
	return strings.Join(parts, " ")
}

// quoteExec quotes one argument per the Desktop Entry spec: reserved
// characters mean the string must be quoted, and inside quotes a backslash and
// a double quote must each be escaped with a backslash.
func quoteExec(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n\"'\\><~|&;$*?#()`") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", `$`, `\$`)
	return `"` + r.Replace(s) + `"`
}
