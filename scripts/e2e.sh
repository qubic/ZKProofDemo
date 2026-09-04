#!/usr/bin/env bash
# End-to-end: build -> cargo test -> execute all fixtures (no proof) -> positive demo (+ attest if
# RISC0_DEV_MODE=0 and VERIFIER set) -> negative demo.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
export RISC0_DEV_MODE=${RISC0_DEV_MODE:-1}

scripts/build.sh
echo "== cargo test"
TLOG=target/e2e_cargo_test.log
RISC0_BUILD_LOCKED=1 cargo test --release --locked >"$TLOG" 2>&1 || { tail -40 "$TLOG"; echo "cargo test FAILED"; exit 1; }
grep -E "^test result" "$TLOG"
echo "== execute fixtures (no proof)"
target/release/run_fixture
GEN="crypto/build/gen_fixture --seeds crypto/seeds/computor_seeds.txt --arbitrator-seed crypto/seeds/arbitrator_seed.txt --epoch 999 --message"
echo "== replay check: commits carrying another queryId must be rejected"
$GEN "Hello ZK, this is Qubic!" --commits 500 --replay-query --out target/replay_query.bin >/dev/null
target/release/run_fixture --fixture target/replay_query.bin --expect-fail
echo "== wrong-digest check: 300 commits to K12(reply) + 200 to another digest must be rejected"
$GEN "Hello ZK, this is Qubic!" --commits 500 --wrong-digest 200 --out target/wrong_digest.bin >/dev/null
target/release/run_fixture --fixture target/wrong_digest.bin --expect-fail
scripts/demo_quorum_ok.sh
scripts/demo_quorum_fail.sh
echo "E2E OK"
