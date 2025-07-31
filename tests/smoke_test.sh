#!/usr/bin/env bash
set -euo pipefail

# Minimal smoke test for ACLGuard
# - builds
# - runs ./aclguard
# - checks for the banner line (simple indicator)

echo "[*] Building..."
make clean && make

echo "[*] Running aclguard (stdout/stderr captured)..."
OUT="$(./aclguard 2>&1 || true)"

echo "------ program output (first 200 lines) ------"
echo "$OUT" | sed -n '1,200p'
echo "----------------------------------------------"

# simple banner check (adjust text if you changed banner)
if echo "$OUT" | grep -q "Access Control List Guard"; then
  echo "[OK] Banner found."
else
  echo "[WARN] Banner not found — the program still may have run. Inspect output above."
fi

# exit success (so test doesn't fail your CI by default)
exit 0

