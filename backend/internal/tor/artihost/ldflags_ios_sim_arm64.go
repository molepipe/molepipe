//go:build ios && arm64

package artihost

// Link the arm64 torhost static library for iOS Simulator builds. The Rust shim
// is cross-compiled by ios/build-torhost.sh into lib/iossim-arm64/. See
// ldflags_ios_arm64.go for notes on system libs.

// #cgo LDFLAGS: -L${SRCDIR}/lib/iossim-arm64 -ltorhost -lm -ldl
import "C"
