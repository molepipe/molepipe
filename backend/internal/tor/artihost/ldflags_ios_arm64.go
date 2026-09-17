//go:build ios && arm64

package artihost

// Link the arm64 torhost static library for iOS device builds. The Rust shim is
// cross-compiled by ios/build-torhost.sh into lib/ios-arm64/. The extra system
// libs are what a Rust staticlib needs on iOS (libm for math, libdl for dlopen).
// -llog is Android-only and omitted here.

// #cgo LDFLAGS: -L${SRCDIR}/lib/ios-arm64 -ltorhost -lm -ldl
import "C"
