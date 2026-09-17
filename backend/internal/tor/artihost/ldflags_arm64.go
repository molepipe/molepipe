//go:build android && arm64

package artihost

// Link the arm64 torhost static library that android/build-aar.sh builds with
// cargo-ndk into lib/arm64/. The extra system libs are what a Rust staticlib
// needs from the Android NDK (libm/libdl for std, liblog for Android logging).
// If the first real link reports missing symbols, this line is where to add
// them (e.g. -lc++_shared).

// #cgo LDFLAGS: -L${SRCDIR}/lib/arm64 -ltorhost -lm -ldl -llog
import "C"
