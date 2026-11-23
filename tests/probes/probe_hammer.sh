#!/usr/bin/env bash
# SHAKAAL — can ANY reconcile path flip a genuinely healthy scan?
#
# A real sweep runs while six concurrent writers hammer every reconcile entry
# point: the CLI reap, the scheduler's pass, and the two API routes that
# reconcile on every request. The window Wasooli flagged is the microseconds
# between the fresh /proc read and the UPDATE, so this races it repeatedly.
set -u
DB=/usr/local/serverscrub/database/serverscrub.db
SS=/usr/local/serverscrub
sqlite3 "$DB" "DELETE FROM threats; DELETE FROM scan_jobs;"
sqlite3 "$DB" "INSERT OR REPLACE INTO settings (key,value) VALUES ('scan_paused_for_backup','0');"

php "$SS/backend/cli/serverscrub.php" scan /home --full >/tmp/scan.log 2>&1 &
sleep 2
JOB=$(sqlite3 "$DB" "SELECT id FROM scan_jobs ORDER BY id DESC LIMIT 1;")
PID=$(sqlite3 "$DB" "SELECT worker_pid FROM scan_jobs WHERE id=$JOB;")
echo "job $JOB, worker $PID — hammering every reconcile path for ~40s"

END=$((SECONDS+40)); FLIP=""; N=0
while [ $SECONDS -lt $END ]; do
  php "$SS/backend/cli/serverscrub.php" scan-reap >/dev/null 2>&1 &
  php "$SS/backend/cli/serverscrub.php" scan-reap >/dev/null 2>&1 &
  php "$SS/backend/cron/scheduler.php"            >/dev/null 2>&1 &
  curl -s "http://localhost:8777/api.cgi?r=scanner%2Factive" >/dev/null 2>&1 &
  curl -s "http://localhost:8777/api.cgi?r=scanner%2Frunning" >/dev/null 2>&1 &
  curl -s "http://localhost:8777/api.cgi?r=scanner%2Fjobs"   >/dev/null 2>&1 &
  wait
  N=$((N+1))
  ST=$(sqlite3 "$DB" "SELECT status FROM scan_jobs WHERE id=$JOB;" 2>/dev/null)
  RE=$(sqlite3 "$DB" "SELECT stop_reason FROM scan_jobs WHERE id=$JOB;" 2>/dev/null)
  case "$ST" in
    running|pending) ;;
    done) echo "  round $N: scan finished normally (status=done) — stopping"; break ;;
    *) FLIP="round $N: status=$ST reason=$RE"; break ;;
  esac
done

echo "rounds of 6 concurrent reconcilers: $N"
if [ -n "$FLIP" ]; then
  echo "  *** A HEALTHY SCAN WAS FLIPPED: $FLIP"
else
  echo "  the healthy scan was never flipped"
fi
echo "final row : $(sqlite3 "$DB" "SELECT id||' '||status||' files='||files_scanned||' reason=['||stop_reason||']' FROM scan_jobs WHERE id=$JOB;")"
echo "any row marked interrupted during the run: $(sqlite3 "$DB" "SELECT COUNT(*) FROM scan_jobs WHERE status='interrupted';")"
echo "SQLITE_BUSY/locked in scan log: $(grep -ciE 'SQLITE_BUSY|database is locked' /tmp/scan.log)"
pkill -f 'serverscrub/backend/cron/scan.php' 2>/dev/null
echo "integrity : $(sqlite3 "$DB" 'PRAGMA integrity_check;')"
