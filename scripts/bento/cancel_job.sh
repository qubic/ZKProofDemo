#!/usr/bin/env bash
# Cancel a bento job in taskdb (run on infra host): cancel_job.sh <job_id> | all-stale
# all-stale = running jobs with no task progress in STALE_MIN (default 60) minutes. Running tasks are left alone.
# Dead clients keep jobs running server-side; this fails pending/ready tasks + the job.
set -euo pipefail
. "$(dirname "$0")/../lib/config.sh"
. "$(dirname "$0")/common.sh"

[ $# -eq 1 ] || { echo "usage: $0 <job_id|all-stale>"; exit 1; }
STALE_MIN=${STALE_MIN:-60}
[[ "$STALE_MIN" =~ ^[0-9]+$ ]] || { echo "STALE_MIN must be numeric"; exit 1; }
pg=$(bento_pg_container)
[ -n "$pg" ] || [ "$DRY_RUN" = 1 ] || { echo "no postgres container here: run on $BENTO_INFRA_HOST"; exit 1; }
sql() { run docker exec "${pg:-<postgres>}" psql -U "$BENTO_PG_USER" -d "$BENTO_PG_DB" -c "$1"; }

if [ "$1" = all-stale ]; then
    cond="job_id in (select id from jobs j where j.state='running' and (select max(coalesce(updated_at, started_at, created_at)) from tasks t where t.job_id=j.id) < now() - interval '$STALE_MIN minutes')"
else
    [[ "$1" =~ ^[0-9a-f-]{36}$ ]] || { echo "bad job id: $1"; exit 1; }
    cond="job_id='$1'"
fi
zkq_confirm_mainnet "cancel bento job(s): $1"
sql "update tasks set state='failed', error='cancelled', updated_at=now() where $cond and state in ('pending','ready');"
sql "update jobs set state='failed', error='cancelled' where id in (select distinct job_id from tasks where $cond) and state='running';"
echo "cancelled: $1"
