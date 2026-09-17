#!/usr/bin/env bash
#
# Cross-compile the torhost Rust shim (arti-client) to static libraries for iOS
# device (aarch64-apple-ios) and iOS Simulator (aarch64-apple-ios-sim). The
# resulting .a files are placed where the Go cgo ldflags expect them:
#   backend/internal/tor/artihost/lib/ios-arm64/libtorhost.a
#   backend/internal/tor/artihost/lib/iossim-arm64/libtorhost.a
#
# Prerequisites (macOS only):
#   - Rust toolchain with iOS targets:
#       rustup target add aarch64-apple-ios aarch64-apple-ios-sim
#   - Xcode with iOS SDK (for the linker)
#
# This script does NOT need cargo-ndk — Apple targets use the standard cargo
# cross-compilation pipeline (rustc invokes the platform linker directly).
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
artihost_lib="$repo_root/backend/internal/tor/artihost/lib"

echo "== stage 1: install iOS Rust targets =="
rustup target add aarch64-apple-ios aarch64-apple-ios-sim 2>/dev/null || true

echo "== stage 2: cargo build torhost per iOS target =="

targets=("aarch64-apple-ios:ios-arm64" "aarch64-apple-ios-sim:iossim-arm64")
for entry in "${targets[@]}"; do
  IFS=':' read -r triple dest_abi <<<"$entry"
  echo "-- $triple"
  cd "$repo_root/torhost"
  cargo build --release --target "$triple"
  dest="$artihost_lib/$dest_abi"
  mkdir -p "$dest"
  cp "target/$triple/release/libtorhost.a" "$dest/libtorhost.a"
  echo "   -> $dest/libtorhost.a"
done

echo "== done: static libraries ready =="
echo "   $artihost_lib/ios-arm64/libtorhost.a"
echo "   $artihost_lib/iossim-arm64/libtorhost.a"
