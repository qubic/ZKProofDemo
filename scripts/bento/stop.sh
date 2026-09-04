#!/usr/bin/env bash
# Stop agents + rest_api (pid file, then pkill fallback). Docker infra stays unless KEEP_INFRA=0.
set -euo pipefail
. "$(dirname "$0")/../lib/config.sh"
. "$(dirname "$0")/common.sh"

if [ -f "$BENTO_PIDS" ]; then
    while read -r pid name; do
        [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || continue
        tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | grep -qE "$BENTO_AGENT_RE|$BENTO_REST_RE" || { echo "skip $name ($pid): not a bento process"; continue; }
        echo "kill $name ($pid)"; run kill "$pid"
    done <"$BENTO_PIDS"
    run rm -f "$BENTO_PIDS"
fi
# fallback: anything started outside the pid file
run pkill -f "$BENTO_AGENT_RE" || true
run pkill -f "$BENTO_REST_RE" || true
echo "agents + rest_api stopped"

if [ "${KEEP_INFRA:-1}" != 0 ]; then echo "docker infra left running (KEEP_INFRA=0 to tear down taskdb/minio)"; exit 0; fi
zkq_confirm_mainnet "docker compose down: drops the taskdb + minio state of every in-flight job"
if [ -n "$(bento_pg_container)" ] || [ "$DRY_RUN" = 1 ]; then
    run docker compose -f "$BENTO_COMPOSE" down
fi
