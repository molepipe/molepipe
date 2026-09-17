package torsidecar

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/tor"
)

// Sweep must delete a leftover onion key (and HS runtime state) from a prior
// run, while keeping the non-secret consensus cache.
func TestSweepRemovesStaleKeyKeepsCache(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "state", "keystore", "hss", "molepipe", tor.KeystoreFileName)
	hssState := filepath.Join(dir, "state", "hss", "molepipe", "ipts.json")
	cacheFile := filepath.Join(dir, "cache", "dir.sqlite3")
	for _, f := range []string{keyPath, hssState, cacheFile} {
		if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	s := New("arti", dir, "molepipe")
	if err := s.Sweep(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Error("stale onion key survived Sweep")
	}
	if _, err := os.Stat(hssState); !os.IsNotExist(err) {
		t.Error("stale HS runtime state survived Sweep")
	}
	if _, err := os.Stat(cacheFile); err != nil {
		t.Error("consensus cache should be kept, but was removed")
	}
}

func TestRenderConfig(t *testing.T) {
	cfg := renderConfig("/data/state", "/data/cache", "molepipe", "127.0.0.1:54321")

	for _, want := range []string{
		`state_dir = "/data/state"`,
		`cache_dir = "/data/cache"`,
		`[onion_services."molepipe"]`,
		`proxy_ports = [["80", "127.0.0.1:54321"]]`,
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q\n---\n%s", want, cfg)
		}
	}
}

// Paths with characters that would break TOML must be quoted safely.
func TestRenderConfigQuotesPaths(t *testing.T) {
	cfg := renderConfig(`/data/with"quote`, "/c", "nick", "127.0.0.1:1")
	if !strings.Contains(cfg, `state_dir = "/data/with\"quote"`) {
		t.Errorf("path not escaped:\n%s", cfg)
	}
}
