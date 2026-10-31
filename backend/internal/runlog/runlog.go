// Package runlog opens the run log with a bounded size.
//
// The run log is this project's primary diagnostic: the native Tor status
// transitions, descriptor-upload failures and dial failures are mirrored into
// it (see artihost.startLogDrain), and on a phone it is the only place they
// exist. It was also append-only, so on a device left running it simply grew —
// 16.6 MB in one observed case, inside the app's own data directory.
//
// Rotation here is deliberately two generations and no more. The diagnoses this
// log is kept for are multi-day: working out that an onion service stopped
// publishing at a particular hour, and that the same signature recurred on
// earlier days, needed roughly a week of history in one file. A tight cap would
// have destroyed exactly the evidence that made that answer possible.
//
// Size it by the *floor*, not the ceiling. Two generations of MaxBytes do not
// guarantee 2*MaxBytes of history: the moment after a rotation the previous
// generation holds MaxBytes and the live file is empty, so the guaranteed window
// is MaxBytes and only approaches twice that just before the next rotation. The
// observed growth that prompted this was 16.6 MB across 8 days, so MaxBytes is
// 16 MiB — a guaranteed week, a 32 MiB ceiling — and not 8, which would have
// guaranteed only about half the window the diagnosis actually consumed.
//
// Both generations name the accounts this device talks to, so both are wiped by
// an account removal and by a duress wipe. The live file is truncated in place
// (this process holds it open) and the rotated one is removed outright, because
// a fresh install has no rotated log and a leftover empty one would mark the
// directory as used. See api.wipeAccountFiles, which is the only other place
// that has to know this file exists.
package runlog

import (
	"os"
	"sync"

	"github.com/molepipe/molepipe/backend/internal/wipe"
)

// MaxBytes is the size at which the live log rotates, and so also the amount of
// history the run log is guaranteed to hold. Two generations are kept, so it
// occupies at most twice this on disk. See the package comment on why this is
// sized by the guaranteed floor rather than the ceiling.
const MaxBytes = 16 << 20

// RotatedPath returns the path of the single previous generation of the run log
// at path. It is the one source of truth for the suffix: the wipe has to remove
// this file, and a second spelling of ".1" is how that gets missed.
func RotatedPath(path string) string { return path + ".1" }

// File is an append-only run log that rotates once it passes a size limit.
// It is safe for concurrent use: the log package serialises its own writes, but
// Close can race with a drain goroutine still logging.
type File struct {
	mu   sync.Mutex
	fh   *os.File
	path string
	max  int64
	size int64
	// Size at which rotation is next attempted. Normally max; after a rotation
	// that failed it is pushed out by another max, because the retry is the
	// expensive part (it scrubs a whole generation) and the caller is a log
	// statement. Without this, one unrenameable file turns every subsequent log
	// line into a fresh multi-MiB scrub.
	nextAt int64
	// Rotations attempted, for the test that proves the deferral above works.
	attempts int
}

// Open opens (or creates) the run log at path, rotating it once it exceeds
// max bytes. A max of zero or less disables rotation, which is what tests that
// only care about the log's contents want.
func Open(path string, max int64) (*File, error) {
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	// Start from the real size, not zero: the process restarts far more often
	// than the log rotates, and a counter that began at zero on every launch
	// would let an already-oversized file grow without bound.
	var size int64
	if st, err := fh.Stat(); err == nil {
		size = st.Size()
	}
	return &File{fh: fh, path: path, max: max, size: size, nextAt: max}, nil
}

// Path returns the live log's path.
func (f *File) Path() string { return f.path }

// Write appends to the live log, rotating first if it has grown past the limit.
//
// A rotation that fails is reported as a successful write: the caller is a log
// statement, and losing diagnostics to a failed housekeeping step would be a
// worse outcome than a log that overshoots its cap. The next attempt is deferred
// by another max bytes rather than made on the following line — see nextAt.
func (f *File) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fh == nil {
		return 0, os.ErrClosed
	}
	n, err := f.fh.Write(p)
	f.size += int64(n)
	if err != nil || f.max <= 0 || f.size < f.nextAt {
		return n, err
	}
	// The wipe truncates this file underneath us, so the counter can overstate
	// what is really on disk. Confirm against the file before rotating, and take
	// the chance to resynchronise.
	if st, serr := f.fh.Stat(); serr == nil {
		f.size = st.Size()
		if f.size < f.nextAt {
			return n, nil
		}
	}
	f.attempts++
	if rerr := f.rotate(); rerr != nil {
		// Overshoot the cap rather than scrub a generation on every line.
		f.nextAt = f.size + f.max
	} else {
		f.nextAt = f.max
	}
	return n, nil
}

// rotate replaces the live log with an empty one, keeping a single previous
// generation. The caller holds mu. On any failure it still leaves f.fh open on
// f.path, so logging survives a rotation that could not complete.
func (f *File) rotate() error {
	rotated := RotatedPath(f.path)
	if err := f.fh.Close(); err != nil {
		f.reopen()
		return err
	}
	// Scrub the generation being discarded rather than just unlinking it: it
	// holds the same peer addresses the wipe goes to the trouble of overwriting.
	if err := wipe.File(rotated); err != nil {
		f.reopen()
		return err
	}
	if err := os.Rename(f.path, rotated); err != nil {
		f.reopen()
		return err
	}
	f.reopen()
	return nil
}

// reopen reattaches f.fh to f.path, resynchronising the size counter. A failure
// leaves f.fh nil, which turns subsequent writes into os.ErrClosed rather than
// a nil dereference.
func (f *File) reopen() {
	fh, err := os.OpenFile(f.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		f.fh = nil
		f.size = 0
		return
	}
	f.fh = fh
	f.size = 0
	if st, err := fh.Stat(); err == nil {
		f.size = st.Size()
	}
}

// Close closes the live log. Writes after it return os.ErrClosed.
func (f *File) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fh == nil {
		return nil
	}
	err := f.fh.Close()
	f.fh = nil
	return err
}
