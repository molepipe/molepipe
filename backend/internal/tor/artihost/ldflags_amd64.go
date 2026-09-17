//go:build android && amd64

package artihost

// Link the x86_64 (emulator) torhost static library built into lib/amd64/.
// See ldflags_arm64.go for notes on the extra system libs.

// #cgo LDFLAGS: -L${SRCDIR}/lib/amd64 -ltorhost -lm -ldl -llog
import "C"
