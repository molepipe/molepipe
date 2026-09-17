// Package wipe removes files by overwriting their contents before unlinking.
//
// The honest scope of this: it defeats casual recovery of a deleted file, and
// nothing stronger. On copy-on-write filesystems (btrfs, ZFS, APFS) an
// overwrite is written to new blocks and the originals survive until the
// filesystem reuses them; on SSDs, wear levelling means the same. This raises
// the bar. It is not a guarantee and must never be described to a user as one.
//
// The only real defence against physical-media forensics is that the data was
// encrypted at rest in the first place — which, in this app, it always is.
package wipe

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// File overwrites path with random bytes, flushes, then unlinks it. A missing
// file is not an error: the goal is "this is gone", and it already is.
func File(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() {
		return Dir(path)
	}
	if err := scrub(path, info.Size()); err != nil {
		return err
	}
	return os.Remove(path)
}

// Scrub overwrites path's contents in place without unlinking it, so the file
// keeps its identity. Used where a file must be replaced rather than removed
// and the replacement has to land in the same place.
func Scrub(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return scrub(path, info.Size())
}

// Truncate scrubs a file's contents and empties it, keeping the file in place.
// For a log the process still has open: unlinking would leave the old inode
// being written to invisibly, and would also make the data directory differ
// from a fresh install's.
func Truncate(path string) error {
	if err := Scrub(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return f.Close()
}

// Dir wipes every regular file beneath root, then removes the tree.
func Dir(root string) error {
	var firstErr error
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // keep going; a file we can't stat is one we can't scrub
		}
		if info.Mode().IsRegular() {
			if err := scrub(p, info.Size()); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return nil
	})
	if err != nil && firstErr == nil {
		firstErr = err
	}
	if err := os.RemoveAll(root); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func scrub(path string, size int64) error {
	if size <= 0 {
		return nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_SYNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	written, err := io.CopyN(f, rand.Reader, size)
	if err != nil {
		return err
	}
	if written != size {
		return fmt.Errorf("scrub: wrote %d of %d bytes", written, size)
	}
	return nil
}
