#!/usr/bin/env bash
# Negative demo: 300 valid + 200 corrupted commit txs -> guest panics -> no proof can exist.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
BIN=$ROOT/target/release
export RISC0_DEV_MODE=${RISC0_DEV_MODE:-1}
LOG=${FAIL_LOG:-$ROOT/target/quorum_fail.log}

[ -x "$BIN/zkq-prove" ] && [ -f fixtures/quorum_fail.bin ] || scripts/build.sh

echo "== prove fixtures/quorum_fail.bin (must fail; log: $LOG)"
if "$BIN/zkq-prove" --fixture fixtures/quorum_fail.bin --out "$ROOT/fixtures/quorum_fail.proof.json" >"$LOG" 2>&1; then
    echo "ERROR: prover produced a proof for an insufficient quorum"; exit 1
fi
# Load-bearing: the ONLY acceptable failure is the guest's quorum panic
# ("quorum not reached: N valid distinct commits, need 451").
grep -m1 -o "quorum not reached: [^\"]*" "$LOG" \
    || { echo "ERROR: prover failed for a reason other than quorum (see $LOG)"; tail -5 "$LOG"; exit 1; }
echo "quorum not reached: proof impossible"
