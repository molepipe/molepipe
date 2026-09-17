//go:build unix

package datalock

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// acquire uses flock, which the kernel releases automatically when the process
// exits — including on a crash or SIGKILL. That matters more than it sounds:
// a PID-file scheme leaves a stale lock behind after a hard kill, and a user
// who has just been told "already in use" when nothing is running will delete
// the file by hand and learn to ignore the warning.
func acquire(dir, path string) (func() error, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, &ErrLocked{Dir: dir}
		}
		return nil, fmt.Errorf("lock data dir: %w", err)
	}
	// Record who holds it, purely so a human reading the directory can tell.
	// Nothing depends on this content being accurate.
	_ = f.Truncate(0)
	fmt.Fprintf(f, "%d\n", os.Getpid())

	return func() error {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return f.Close()
	}, nil
}
