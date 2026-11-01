#!/usr/bin/env bash
# Start fake-account molepipe instances (host-side, one data dir each) and
# refresh harness.json (port + control token) so run.py/cdp tooling can attach.
# Usage: ./start-accounts.sh [name ...]   (default: all)
set -u
cd /tmp/molepipe/tooling || exit 1
ALL="Quinton Sassy Hannah Bob_Annderson Monty Consuela Peter_File Summer Donny Clive_Bixby Richmond Liam Clarence Juliana Mike_Nolan"
NAMES="${*:-$ALL}"
for n in $NAMES; do
  python3 - "$n" <<'EOF'
import sys, os
sys.path.insert(0, "/tmp/molepipe/tooling")
import mp
name = sys.argv[1]
if not os.path.isdir(mp.WORK + "/" + name):
    print(f"skip {name} (no data dir)"); raise SystemExit
try:
    mp.Instance.connect(name).get("/api/status")
    print(f"{name} already running")
except Exception:
    i = mp.Instance(name); i.start()
    i.unlock()
    print(f"{name} started on port {i.port} ({(i.account or '')[:12]})")
EOF
done
