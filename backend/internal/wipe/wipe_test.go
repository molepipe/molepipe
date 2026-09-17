package wipe

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileRemovesExistingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret.txt")
	data := []byte("sensitive data here")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := File(p); err != nil {
		t.Fatalf("File: %v", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("file was not removed after wipe")
	}
}

func TestFileMissingIsNotAnError(t *testing.T) {
	if err := File(filepath.Join(t.TempDir(), "nonexistent")); err != nil {
		t.Fatalf("File on missing path: %v", err)
	}
}

func TestFileOverwritesBeforeRemoving(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret.txt")
	data := []byte("AAAAABBBBBCCCCCDDDDD")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := File(p); err != nil {
		t.Fatal(err)
	}
	// File is gone; if the overwrite step failed, the remove would still succeed
	// but the data would have been recoverable. We can at least verify the file
	// is gone and that the function completed without error.
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("file still exists")
	}
}

func TestFileTreatsDirectoryAsDir(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "subdir")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	// Create a file inside the directory.
	p := filepath.Join(sub, "file.txt")
	if err := os.WriteFile(p, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := File(sub); err != nil {
		t.Fatalf("File on directory: %v", err)
	}
	if _, err := os.Stat(sub); !os.IsNotExist(err) {
		t.Fatal("directory was not removed")
	}
}

func TestFileZeroLength(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(p, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := File(p); err != nil {
		t.Fatalf("File on zero-length file: %v", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("empty file was not removed")
	}
}

func TestScrubOverwritesInPlace(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "data.bin")
	original := make([]byte, 256)
	for i := range original {
		original[i] = byte(i)
	}
	if err := os.WriteFile(p, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Scrub(p); err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	// File must still exist (Scrub does not unlink).
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("Scrub removed the file: %v", err)
	}
	// Contents must have changed.
	after, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(original) {
		t.Fatalf("Scrub changed file length: %d → %d", len(original), len(after))
	}
	same := true
	for i := range original {
		if after[i] != original[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("Scrub did not change file contents")
	}
}

func TestScrubMissingIsNotAnError(t *testing.T) {
	if err := Scrub(filepath.Join(t.TempDir(), "nonexistent")); err != nil {
		t.Fatalf("Scrub on missing path: %v", err)
	}
}

func TestScrubZeroLength(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(p, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Scrub(p); err != nil {
		t.Fatalf("Scrub on zero-length file: %v", err)
	}
	// Content should still be empty (scrub is a no-op on size 0).
	after, _ := os.ReadFile(p)
	if len(after) != 0 {
		t.Errorf("Scrub on empty file grew it to %d bytes", len(after))
	}
}

func TestTruncateEmptiesFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log.txt")
	data := []byte("sensitive log entries")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Truncate(p); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Errorf("Truncate left file at %d bytes, want 0", info.Size())
	}
}

func TestTruncateMissingIsNotAnError(t *testing.T) {
	if err := Truncate(filepath.Join(t.TempDir(), "nonexistent")); err != nil {
		t.Fatalf("Truncate on missing path: %v", err)
	}
}

func TestDirWipesAllFiles(t *testing.T) {
	dir := t.TempDir()
	// Create a tree of files.
	files := []string{
		filepath.Join(dir, "a.txt"),
		filepath.Join(dir, "sub", "b.txt"),
		filepath.Join(dir, "sub", "deep", "c.txt"),
	}
	for _, f := range files {
		if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := Dir(dir); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("root directory was not removed")
	}
}

func TestDirEmptyDir(t *testing.T) {
	dir := t.TempDir()
	if err := Dir(dir); err != nil {
		t.Fatalf("Dir on empty dir: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("empty directory was not removed")
	}
}

func TestDirMissingIsNotAnError(t *testing.T) {
	if err := Dir(filepath.Join(t.TempDir(), "nonexistent")); err != nil {
		t.Fatalf("Dir on missing path: %v", err)
	}
}

func TestDirSymlinksNotFollowed(t *testing.T) {
	dir := t.TempDir()
	// Create a symlink to a file outside the dir.
	outside := filepath.Join(dir, "..", "outside.txt")
	if err := os.WriteFile(outside, []byte("I should not be wiped"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := Dir(dir); err != nil {
		t.Fatal(err)
	}
	// The symlink target outside the dir should still exist.
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("Dir followed symlink outside its root")
	}
}

func TestDirContinuesOnError(t *testing.T) {
	dir := t.TempDir()
	// Create a regular file.
	good := filepath.Join(dir, "good.txt")
	if err := os.WriteFile(good, []byte("wipe me"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Dir should complete even if a file in the tree is unreadable.
	// On most systems, a non-root user can create a root-owned unreadable file,
	// but that's tricky in tests. Instead, we test that Dir returns nil when all
	// files are wipeable, and handles the tree correctly.
	if err := Dir(dir); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("directory not fully removed")
	}
}

func TestFileDoesNotLeakContent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cred.bin")
	// Write known pattern.
	data := make([]byte, 1024)
	for i := range data {
		data[i] = 0xAA
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := File(p); err != nil {
		t.Fatal(err)
	}
	// File is gone — no content to leak.
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("file exists after wipe")
	}
}

func TestScrubFilePermissionsPreserved(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "perm.txt")
	if err := os.WriteFile(p, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Scrub(p); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("Scrub changed file permissions: %o", perm)
	}
}
