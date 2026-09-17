// Package version holds the application version, set at build time via -ldflags.
//
// Usage:
//
//	go build -ldflags="-X github.com/molepipe/molepipe/backend/internal/version.Version=1.2.3"
package version

import (
	"runtime"
	"strconv"
)

// Version is the semantic version string, injected at build time.
// Falls back to "dev" when running from `go run` or `go test` without -ldflags.
var Version = "dev"

// GitCommit is the git commit hash, injected at build time.
var GitCommit = "unknown"

// VersionCode is a monotonic integer build number, injected at build time as a
// string (ldflags -X can only set strings). It is the DESKTOP source of truth
// for "which build is this" — the update check compares it against the signed
// manifest's latest.version_code. Falls back to "0" without -ldflags.
//
// On Android this stamp is NOT authoritative: build-aar.sh runs standalone and
// can carry a stale value, so the running code is injected at startup from the
// platform's PackageInfo.longVersionCode instead (see the api server's update
// handler). Trusting this stamp on Android would silently compare against the
// wrong build — the exact failure UPDATE_CHANNEL.md's step 6 warns about.
var VersionCode = "0"

// Code parses VersionCode, returning 0 (never a prompt-triggering value) when it
// is unset or malformed. A build number is meaningless as anything but an int.
func Code() int {
	n, err := strconv.Atoi(VersionCode)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// BuildInfo returns the version and build metadata as a JSON-serializable map.
func BuildInfo() map[string]string {
	return map[string]string{
		"version":      Version,
		"git_commit":   GitCommit,
		"version_code": strconv.Itoa(Code()),
		"go_version":   runtime.Version(),
		"os":           runtime.GOOS,
		"arch":         runtime.GOARCH,
	}
}
