package mobile

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/api"
	"github.com/molepipe/molepipe/backend/internal/datalock"
)

// The package uses process-global state (one backend per process), so these
// tests must not run in parallel and each must Stop what it starts.

func TestStartRejectsEmptyDataDir(t *testing.T) {
	// An empty dir must be refused, never silently fall back to a desktop OS
	// config directory (identity.NewStore's default) that Android has no access
	// to. This is the plan's "must not assume a desktop filesystem layout".
	if _, err := Start(""); err == nil {
		_ = Stop(0)
		t.Fatal("Start(\"\") should error, not inherit the desktop default dir")
	}
	if IsRunning() {
		t.Fatal("a rejected Start must leave the backend not running")
	}
}

func TestStartStopLifecycleAndIdempotence(t *testing.T) {
	dir := t.TempDir()

	url, err := Start(dir)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer Stop(0)

	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Fatalf("URL = %q, want a loopback http URL", url)
	}
	if !IsRunning() {
		t.Fatal("IsRunning should be true after Start")
	}
	if URL() != url {
		t.Fatalf("URL() = %q, want %q", URL(), url)
	}
	if PublicAddr() == "" {
		t.Fatal("PublicAddr should be set after Start")
	}

	// A second Start while running returns the same URL and does not re-bind.
	url2, err := Start(dir)
	if err != nil {
		t.Fatalf("second Start: %v", err)
	}
	if url2 != url {
		t.Fatalf("idempotent Start returned %q, want %q", url2, url)
	}

	if err := Stop(0); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if IsRunning() {
		t.Fatal("IsRunning should be false after Stop")
	}
	// Stop is idempotent.
	if err := Stop(0); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

func TestStopReleasesDataLock(t *testing.T) {
	dir := t.TempDir()

	if _, err := Start(dir); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// While running, the directory is locked against a second holder.
	if rel, err := datalock.Acquire(dir); err == nil {
		_ = rel()
		_ = Stop(0)
		t.Fatal("data dir should be locked while the backend runs")
	}

	if err := Stop(0); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// Stop must release the lock, or the app can never restart in the same dir.
	rel, err := datalock.Acquire(dir)
	if err != nil {
		t.Fatalf("data dir still locked after Stop: %v", err)
	}
	_ = rel()
}

func TestLogGoesToDataDirNotStderr(t *testing.T) {
	// The duress / account-removal wipe truncates dataDir/LogFileName; a log that
	// escaped to stderr (logcat on Android) would survive the wipe and name the
	// accounts you talked to. Prove Start routes the log into the data dir and
	// that a subsequent log line lands there.
	dir := t.TempDir()

	if _, err := Start(dir); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer Stop(0)

	log.Print("mobile-test-marker-line")

	data, err := os.ReadFile(filepath.Join(dir, api.LogFileName))
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), "mobile-test-marker-line") {
		t.Fatalf("log line did not reach %s; got:\n%s", api.LogFileName, data)
	}
}
