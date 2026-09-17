//go:build !unix

package datalock

import (
	"fmt"
	"os"
)

// acquire falls back to an exclusive-create lock file on platforms without
// flock. This cannot distinguish a live holder from one left behind by a crash,
// so it errs towards refusing — a false "already in use" is recoverable by
// deleting the file, while a false success is silent data corruption.
func acquire(dir, path string) (func() error, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if os.IsExist(err) {
		return nil, &ErrLocked{Dir: dir}
	}
	if err != nil {
		return nil, fmt.Errorf("create lock file: %w", err)
	}
	fmt.Fprintf(f, "%d\n", os.Getpid())
	return func() error {
		err := f.Close()
		if rmErr := os.Remove(path); err == nil {
			err = rmErr
		}
		return err
	}, nil
}
