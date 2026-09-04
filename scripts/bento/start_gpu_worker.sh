#!/usr/bin/env bash
# GPU box: one prove agent per GPU against BENTO_INFRA_HOST. Env: GPUS="0,2" selects, DRY_RUN=1.
# Copy the agent here first:  scp $BENTO_AGENT root@<box>:/root/bento/agent
# then run with:              BENTO_AGENT=/root/bento/agent scripts/bento/start_gpu_worker.sh
# Prove workers also need groth16 keys: rzup install risc0-groth16 (wraps ride the prove stream).
#
# VRAM per prove agent (free VRAM check below warns under 6 GB):
#   SEGMENT_PO2 20 (1M cycles)  ~3-5 GB
#   SEGMENT_PO2 21 (2M cycles)  ~9 GB
set -euo pipefail
. "$(dirname "$0")/../lib/config.sh"
. "$(dirname "$0")/common.sh"

if [ ! -x "$BENTO_AGENT" ]; then
    echo "missing agent binary: $BENTO_AGENT"
    src=$(sed -n 's/^BENTO_AGENT=//p' "$ZKQ_CONFIG")
    echo "copy it:  scp $src root@<this-box>:/root/bento/agent   (from a box that built bento)"
    echo "then:     BENTO_AGENT=/root/bento/agent $0"
    exit 1
fi
command -v nvidia-smi >/dev/null || { echo "nvidia-smi missing: no GPUs here"; exit 1; }
pids=$(bento_agent_pids)
if [ -n "$pids" ]; then
    echo "agents already running (pids: $(echo $pids | tr '\n' ' ')); run stop.sh first"
    [ "$DRY_RUN" = 1 ] || exit 1
fi

if [ -n "${GPUS:-}" ]; then gpus=${GPUS//,/ }; else gpus=$(bento_gpus); fi
[ -n "$gpus" ] || { echo "no GPUs found"; exit 1; }

run mkdir -p "$BENTO_LOG_DIR"
bento_export_env
echo "== infra: $BENTO_INFRA_HOST (postgres:5432 redis:6379 minio:9000; creds from config)"
for g in $gpus; do
    free=$(nvidia-smi --query-gpu=memory.free --format=csv,noheader,nounits -i "$g" 2>/dev/null || echo 0)
    name=$(nvidia-smi --query-gpu=name --format=csv,noheader -i "$g" 2>/dev/null || echo unknown)
    echo "GPU$g $name free ${free} MiB"
    [ "$free" -ge 6144 ] || echo "WARN GPU$g: < 6 GB free (po2 $SEGMENT_PO2 needs 3-9 GB, see header)"
    start_bg "prove_gpu$g" env CUDA_VISIBLE_DEVICES="$g" "$BENTO_AGENT" -t prove
done
echo "worker up: $(echo $gpus | wc -w) prove agent(s) -> $BENTO_INFRA_HOST. logs: $BENTO_LOG_DIR"
