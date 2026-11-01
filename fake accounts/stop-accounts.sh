#!/usr/bin/env bash
# Stop all fake-account molepipe instances + their arti sidecars.
set -u
for p in $(pgrep -f "fake-accounts/[A-Za-z_]*/arti/arti.tom[l]"); do kill "$p" 2>/dev/null; done
for p in $(pgrep -f "tooling/molepipe-serve[r]"); do kill "$p" 2>/dev/null; done
echo "stopped"
