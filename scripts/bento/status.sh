#!/usr/bin/env bash
# Bento status: rest_api health, local agents, GPUs, taskdb (infra host), VERSION LOCK check.
# Exit 1 on version mismatch. DRY_RUN=1 prints remote/db commands instead.
set -euo pipefail
. "$(dirname "$0")/../lib/config.sh"
. "$(dirname "$0")/common.sh"

echo "== rest_api $BONSAI_API_URL/health"
if [ "$DRY_RUN" = 1 ]; then echo "+ curl -sf -m 5 $BONSAI_API_URL/health"
else curl -sf -m 5 "$BONSAI_API_URL/health" && echo " OK" || echo "UNREACHABLE"; fi

echo "== local agents ($BENTO_AGENT)"
pgrep -af "$BENTO_AGENT_RE" | grep -oE -- '-t [a-z]+' | sort | uniq -c || echo "none"
echo "rest_api: $(pgrep -fc "$BENTO_REST_RE" || true)"

if command -v nvidia-smi >/dev/null; then
    echo "== GPUs (index, name, util %, mem used/total MiB)"
    nvidia-smi --query-gpu=index,name,utilization.gpu,memory.used,memory.total --format=csv,noheader
fi

pg=$(bento_pg_container)
if [ -n "$pg" ] || [ "$DRY_RUN" = 1 ]; then
    echo "== taskdb tasks by type/state"
    q="select (select k from jsonb_object_keys(task_def) k limit 1) type, state, count(*) from tasks group by 1,2 order by 1,2;"
    run docker exec "${pg:-<postgres>}" psql -U "$BENTO_PG_USER" -d "$BENTO_PG_DB" -c "$q"
    echo "== taskdb jobs by state / streams"
    run docker exec "${pg:-<postgres>}" psql -U "$BENTO_PG_USER" -d "$BENTO_PG_DB" \
        -c "select state, count(*) from jobs group by 1;" \
        -c "select worker_type, ready, running from streams;"
fi

echo "== VERSION LOCK (agent risc0-zkvm == Cargo.lock)"
lock=$(grep -A1 'name = "risc0-zkvm"' "$ZKQ_ROOT/Cargo.lock" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
if [ -r "$BENTO_AGENT" ]; then
    agent=$(strings "$BENTO_AGENT" | grep -oE 'risc0-zkvm-[0-9]+\.[0-9.]+' | sed 's/risc0-zkvm-//' | sort -u | tr '\n' ' ' || true)
else
    agent="<agent not readable: $BENTO_AGENT>"
fi
echo "Cargo.lock risc0-zkvm: $lock | agent: ${agent:-<none found>}"
if [ "$(echo $agent)" = "$lock" ]; then
    echo "VERSION LOCK OK"
else
    echo "VERSION LOCK MISMATCH: agent embeds '${agent:-?}', client pins '$lock'."
    echo "  proving would fail with 'control_id mismatch' / 'verify lift: proof is invalid'."
    echo "  fix: rebuild bento at risc0 $lock (docs/BENTO.md), never cargo update the client."
    exit 1
fi
