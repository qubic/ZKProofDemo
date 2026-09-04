#!/usr/bin/env bash
# Infra host: docker infra + rest_api :8081 + aux/exec/join/snark agents + 1 prove per GPU.
# Env: DRY_RUN=1 prints commands. Logs $BENTO_LOG_DIR/*.log, pids $BENTO_LOG_DIR/pids.
set -euo pipefail
. "$(dirname "$0")/../lib/config.sh"
. "$(dirname "$0")/common.sh"
# infra ports bind to BENTO_INFRA_HOST (loopback for single box); override with BENTO_BIND
export BENTO_BIND=${BENTO_BIND:-$BENTO_INFRA_HOST}

for b in "$BENTO_AGENT" "$BENTO_REST_API"; do
    [ -x "$b" ] || { echo "missing binary: $b (see docs/BENTO.md, build)"; exit 1; }
done
pids=$(bento_agent_pids)
if [ -n "$pids" ]; then
    echo "agents already running (pids: $(echo $pids | tr '\n' ' ')); run stop.sh first"
    [ "$DRY_RUN" = 1 ] || exit 1
fi

run mkdir -p "$BENTO_LOG_DIR"
bento_export_env 127.0.0.1
echo "== infra (docker compose)"
run docker compose -f "$BENTO_COMPOSE" up -d

echo "== waiting for postgres/redis/minio health"
for svc in postgres redis minio; do
    if [ "$DRY_RUN" = 1 ]; then echo "+ wait healthy: $svc"; continue; fi
    for _ in $(seq 1 60); do
        cid=$(docker compose -f "$BENTO_COMPOSE" ps -q "$svc")
        st=$(docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null || echo starting)
        [ "$st" = healthy ] && break
        sleep 2
    done
    [ "$st" = healthy ] || { echo "$svc not healthy after 120s"; exit 1; }
    echo "$svc healthy"
done

echo "== rest_api + agents"
start_bg rest_api "$BENTO_REST_API" --bind-addr "${BENTO_BIND:-$BENTO_INFRA_HOST}:8081" --snark-timeout 3600
# aux is MANDATORY: refreshes stream counters; without it tasks sit 'ready' forever
start_bg aux   "$BENTO_AGENT" -t aux --monitor-requeue
start_bg exec  "$BENTO_AGENT" -t exec --segment-po2 "$SEGMENT_PO2"
start_bg join  "$BENTO_AGENT" -t join
start_bg snark "$BENTO_AGENT" -t snark
for g in $(bento_gpus); do
    start_bg "prove_gpu$g" env CUDA_VISIBLE_DEVICES="$g" "$BENTO_AGENT" -t prove
done

echo "bento server up. client env:"
echo "BONSAI_API_URL=http://$BENTO_INFRA_HOST:8081 BONSAI_API_KEY=<from config>"
