package mailbox

import (
	"errors"
	"testing"
)

// TestBackupMessageCeilingOverridesMessageCap covers the Phase B split of the
// per-blob backup ceiling from the tiny message ceiling: a group image is far
// larger than MaxMessage, so MaxBackupMessage must govern it independently. With
// MaxBackupMessage set, a blob between MaxMessage and MaxBackupMessage is accepted
// (it would be refused if the message ceiling still applied) and one past
// MaxBackupMessage is refused.
func TestBackupMessageCeilingOverridesMessageCap(t *testing.T) {
	s := newStore(t, Caps{MaxMessage: 4, MaxBackupBytes: 1 << 20, MaxBackupMessage: 16})
	bob := acct(t)
	s.CheckIn(bob)

	// 10 bytes: over the 4-byte message ceiling, under the 16-byte backup ceiling.
	if err := s.DropOffBackup(bob, "aa", []byte("0123456789"), 0); err != nil {
		t.Fatalf("blob within backup ceiling but over message ceiling: %v", err)
	}
	// 17 bytes: over the backup ceiling.
	if err := s.DropOffBackup(bob, "bb", []byte("0123456789abcdefg"), 0); !errors.Is(err, ErrOverCap) {
		t.Fatalf("blob over backup ceiling: got %v, want ErrOverCap", err)
	}
}

// TestBackupBlobLargerThanWholeBudget: a single blob bigger than the whole budget
// can never fit and is refused up front rather than evicting everything to no avail.
func TestBackupBlobLargerThanWholeBudget(t *testing.T) {
	s := newStore(t, Caps{MaxBackupBytes: 5})
	bob := acct(t)
	s.CheckIn(bob)

	if err := s.DropOffBackup(bob, "aa", []byte("way too big"), 0); !errors.Is(err, ErrOverCap) {
		t.Fatalf("blob larger than whole budget: got %v, want ErrOverCap", err)
	}
}
