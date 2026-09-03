#!/usr/bin/env bash
# Builds crypto/ and runs every check. Exit code non-zero on any failure.
set -euo pipefail
CRYPTO=$(cd "$(dirname "$0")/.." && pwd)
ROOT=$(dirname "$CRYPTO")
BUILD=$CRYPTO/build
VEC=$CRYPTO/tests/vectors
LOG=$BUILD/run_tests.log
mkdir -p "$BUILD" "$VEC"

make -C "$CRYPTO" -j"$(nproc)" all tests > "$BUILD/build.log" 2>&1
: > "$LOG"

fail=0
run() {
  echo "== $*" >> "$LOG"
  if out=$("$@" 2>&1); then echo "$out" >> "$LOG"; echo "$out" | grep -E '^(check_|gen_vectors|official)'
  else echo "$out" >> "$LOG"; echo "FAILED: $*"; echo "$out" | tail -n 20; fail=1; fi
}

run "$BUILD/gen_vectors" "$VEC" "$CRYPTO/seeds/computor_seeds.txt" "$CRYPTO/seeds/arbitrator_seed.txt"
run "$BUILD/check_port"      "$VEC/schnorrq_vectors.txt"
run "$BUILD/check_k12"       "$VEC/k12_vectors.txt"
run "$BUILD/check_keys"      "$VEC/keygen_vectors.txt"
run "$BUILD/check_roundtrip" "$VEC/sign_vectors.txt"
run "$BUILD/check_bulk"

# derive_keys output must match the committed seeds/*.txt files.
if [ -f "$CRYPTO/seeds/computor_pubkeys.txt" ]; then
  echo "== derive_keys vs seeds/computor_pubkeys.txt" | tee -a "$LOG"
  if "$BUILD/derive_keys" "$CRYPTO/seeds/computor_seeds.txt" | diff -q - "$CRYPTO/seeds/computor_pubkeys.txt" >> "$LOG"; then
    echo "computor_pubkeys.txt: identical ($(wc -l < "$CRYPTO/seeds/computor_pubkeys.txt") lines)"
  else echo "FAILED: computor_pubkeys.txt differs"; fail=1; fi
fi
if [ -f "$CRYPTO/seeds/arbitrator_pubkey.txt" ]; then
  if "$BUILD/derive_keys" "$CRYPTO/seeds/arbitrator_seed.txt" | diff -q - "$CRYPTO/seeds/arbitrator_pubkey.txt" >> "$LOG"; then
    echo "arbitrator_pubkey.txt: identical"
  else echo "FAILED: arbitrator_pubkey.txt differs"; fail=1; fi
fi

# gen_fixture smoke: build a 451-commit ZKQFIX02 fixture, re-verify it; a bad one must be rejected.
echo "== gen_fixture / check_fixture" | tee -a "$LOG"
ARB=$(awk '{print $2}' "$CRYPTO/seeds/arbitrator_pubkey.txt")
GEN="$BUILD/gen_fixture --seeds $CRYPTO/seeds/computor_seeds.txt --arbitrator-seed $CRYPTO/seeds/arbitrator_seed.txt --epoch 999 --commits 451"
if $GEN --message "Hello ZK, this is Qubic!" --out "$BUILD/smoke_ok.bin" >> "$LOG" 2>&1 \
   && out=$("$BUILD/check_fixture" "$BUILD/smoke_ok.bin" "$ARB" 2>&1); then echo "$out" >> "$LOG"; echo "$out" | grep -E '^fixture OK'
else echo "FAILED: gen_fixture/check_fixture smoke"; fail=1; fi
if $GEN --message "Hello ZK, this is Qubic!" --bad-commits 1 --out "$BUILD/smoke_bad.bin" >> "$LOG" 2>&1 \
   && ! "$BUILD/check_fixture" "$BUILD/smoke_bad.bin" "$ARB" >> "$LOG" 2>&1; then echo "check_fixture rejects --bad-commits 1"
else echo "FAILED: bad fixture not rejected"; fail=1; fi

# Optional cross-check against qubic-cli (identity only; cli prints no hex).
CLI=${QUBIC_CLI:-qubic-cli}   # optional cross-check, skipped if not in PATH
if CLIPATH=$(command -v "$CLI" 2>/dev/null) && [ -f "$CLIPATH" ]; then
  echo "== qubic-cli cross-check" | tee -a "$LOG"
  for seed in "$(head -n1 "$CRYPTO/seeds/computor_seeds.txt")" "$(head -n1 "$CRYPTO/seeds/arbitrator_seed.txt")"; do
    ours=$(printf '%s\n' "$seed" | "$BUILD/derive_keys" /dev/stdin | awk '{print $3}')
    cli=$("$CLI" -seed "$seed" -showkeys | awk '/^Identity:/{print $2}')
    if [ "$ours" = "$cli" ]; then echo "qubic-cli identity match: $cli"; else echo "FAILED: qubic-cli $cli != ours $ours"; fail=1; fi
  done
else
  echo "qubic-cli not found at $CLI (skipped)"
fi

if [ "$fail" -ne 0 ]; then echo "RESULT: FAIL (see $LOG)"; exit 1; fi
echo "RESULT: ALL PASS (log: $LOG)"
