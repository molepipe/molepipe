// Package datalock guards a data directory against being opened by two running
// instances at once.
//
// Sharing a data directory is not a partial-degradation failure, it is silent
// corruption: both instances derive the SAME identity and onion key, so two Tor
// services publish competing descriptors for one address (making it
// intermittently unreachable), and both write full snapshots of messages.enc,
// so whichever saves last erases the other's contacts and history. None of that
// announces itself — it surfaces later as "my friend accepted but it never came
// back", which is a very long way from the cause.
//
// The lock is advisory and covers concurrently running processes only. It is
// not a security boundary.
package datalock

import (
	"fmt"
	"os"
	"path/filepath"
)

// lockFile is the sentinel inside the data dir.
const lockFile = ".lock"

// ErrLocked reports that another live instance holds the directory.
type ErrLocked struct {
	Dir string
}

func (e *ErrLocked) Error() string {
	return fmt.Sprintf("data directory %s is already in use by another running instance —"+
		" start the second instance with its own directory, e.g. -data-dir %s",
		e.Dir, filepath.Join(os.TempDir(), "tormsg-second"))
}

// Acquire takes the lock on dir, creating the directory if needed. The returned
// release function drops it. If another live process holds it, Acquire returns
// an *ErrLocked and takes nothing.
func Acquire(dir string) (release func() error, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	return acquire(dir, filepath.Join(dir, lockFile))
}
