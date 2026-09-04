# Source me (after scripts/lib/config.sh). Shared bento helpers; DRY_RUN=1 prints instead.
#   run CMD...            run or print
#   start_bg NAME CMD...  background + log + pid (or print)
#   bento_export_env      DATABASE_URL/REDIS_URL/S3_* from config
BENTO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BENTO_COMPOSE="$BENTO_DIR/infra-compose.yml"
BENTO_LOG_DIR=${BENTO_LOG_DIR:-/tmp/bento}
BENTO_PIDS="$BENTO_LOG_DIR/pids"
DRY_RUN=${DRY_RUN:-0}
export BENTO_PG_USER=${BENTO_PG_USER:-worker} BENTO_PG_PASSWORD=${BENTO_PG_PASSWORD:-password}
export BENTO_PG_DB=${BENTO_PG_DB:-taskdb}
export BENTO_MINIO_USER=${BENTO_MINIO_USER:-admin} BENTO_MINIO_PASSWORD=${BENTO_MINIO_PASSWORD:-password}

run() {
    if [ "$DRY_RUN" = 1 ]; then echo "+ $*"; else "$@"; fi
}

start_bg() {
    local name=$1; shift
    if [ "$DRY_RUN" = 1 ]; then echo "+ $* > $BENTO_LOG_DIR/$name.log &"; return; fi
    nohup "$@" >"$BENTO_LOG_DIR/$name.log" 2>&1 &
    echo "$! $name" >>"$BENTO_PIDS"
    echo "$name (pid $!)"
}

# infra host = where infra-compose runs; agents connect to it
bento_export_env() {
    local host=${1:-$BENTO_INFRA_HOST}
    export DATABASE_URL="postgresql://$BENTO_PG_USER:$BENTO_PG_PASSWORD@$host:5432/$BENTO_PG_DB"
    export REDIS_URL="redis://$host:6379"
    export S3_URL="http://$host:9000"
    export S3_BUCKET=workflow
    export S3_ACCESS_KEY=$BENTO_MINIO_USER
    export S3_SECRET_KEY=$BENTO_MINIO_PASSWORD
    export RUST_LOG=${RUST_LOG:-info}
}

# nvidia-smi GPU indices, empty if no nvidia-smi
bento_gpus() {
    command -v nvidia-smi >/dev/null 2>&1 || return 0
    nvidia-smi --query-gpu=index --format=csv,noheader,nounits 2>/dev/null | tr '\n' ' '
}

# match by basename: live agents may run via a non-normalized path
_re_escape() { printf '%s' "$1" | sed 's/[][\.*^$+?(){}|]/\\&/g'; }
BENTO_AGENT_RE="(^|/)$(_re_escape "$(basename "$BENTO_AGENT")") -t (prove|exec|join|snark|aux)( |$)"
BENTO_REST_RE="(^|/)$(_re_escape "$(basename "$BENTO_REST_API")") --bind-addr"

# running agent pids (any type)
bento_agent_pids() { pgrep -f "$BENTO_AGENT_RE" || true; }

# postgres container id when infra runs here (this compose, else any postgres:16.3)
bento_pg_container() {
    command -v docker >/dev/null 2>&1 || return 0
    local id
    id=$(docker compose -f "$BENTO_COMPOSE" ps -q postgres 2>/dev/null || true)
    [ -n "$id" ] || id=$(docker ps -q --filter ancestor=postgres:16.3-bullseye | head -1)
    echo "$id"
}
