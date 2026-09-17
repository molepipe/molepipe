package version

import (
	"testing"
)

func TestVersionDefault(t *testing.T) {
	// When built without -ldflags, Version should be "dev".
	if Version == "" {
		t.Fatal("Version must not be empty")
	}
}

func TestBuildInfo(t *testing.T) {
	info := BuildInfo()
	if len(info) == 0 {
		t.Fatal("BuildInfo returned empty map")
	}
	if info["version"] == "" {
		t.Error("BuildInfo version is empty")
	}
	if info["go_version"] == "" {
		t.Error("BuildInfo go_version is empty")
	}
	if info["os"] == "" {
		t.Error("BuildInfo os is empty")
	}
	if info["arch"] == "" {
		t.Error("BuildInfo arch is empty")
	}
}
