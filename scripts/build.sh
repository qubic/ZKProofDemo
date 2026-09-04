#!/usr/bin/env bash
# Builds guest + host (release, locked) + crypto/ tools, regenerates the demo fixtures, prints IMAGE_ID.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
LOG=${BUILD_LOG:-$ROOT/target/build.log}
mkdir -p target fixtures

echo "== cargo build --release --locked (log: $LOG)"
unset RISC0_SKIP_BUILD; RISC0_BUILD_LOCKED=1 cargo build --release --locked >"$LOG" 2>&1 || { tail -n 40 "$LOG"; echo "build failed, see $LOG"; exit 1; }
echo "== make crypto/ (gen_fixture, check_fixture, derive_keys)"
make -C crypto -j"$(nproc)" all >"$ROOT/target/crypto_build.log" 2>&1 || { tail -n 40 target/crypto_build.log; exit 1; }

GEN="crypto/build/gen_fixture --seeds crypto/seeds/computor_seeds.txt --arbitrator-seed crypto/seeds/arbitrator_seed.txt --epoch 999 --message"
$GEN "Hello ZK, this is Qubic!" --commits 500 --out fixtures/quorum_ok.bin
$GEN "Hello ZK, this is Qubic!" --commits 500 --bad-commits 200 --out fixtures/quorum_fail.bin
echo "IMAGE_ID: $(target/release/image_id --short)"
