#!/usr/bin/env bash
# SHAKAAL PROBE — reach the stale-snapshot reap through the REAL scheduler.
#
# One tick: reconcile pass (snapshot) -> 'scan' task starts a real scan ->
# 'resumescan' task calls liveScans() again inside the 5s cache window.
set -u
DB=/usr/local/serverscrub/database/serverscrub.db
SS=/usr/local/serverscrub

echo "--- clearing in-progress rows and arming the tick ---"
sqlite3 "$DB" "DELETE FROM scan_jobs;"
sqlite3 "$DB" "INSERT OR REPLACE INTO settings (key,value) VALUES ('scan_schedule','daily');"
sqlite3 "$DB" "INSERT OR REPLACE INTO settings (key,value) VALUES ('scan_paths','/home');"
sqlite3 "$DB" "INSERT OR REPLACE INTO settings (key,value) VALUES ('last_run_scan','0');"
sqlite3 "$DB" "DELETE FROM settings WHERE key LIKE 'last_run_%';"
pkill -f 'cron/scan.php' 2>/dev/null; sleep 1

# The marker install.sh leaves behind after an update, which is what makes the
# 'resumescan' task do its liveScans() call.
cat > "$SS/logs/.resume-scans.json" <<JSON
[{"path":"/home/alpha","type":"full","by":"@update"}]
JSON

echo "--- one scheduler tick ---"
php "$SS/backend/cron/scheduler.php" 2>&1 | sed 's/^/  /'

echo
echo "--- scan_jobs after the tick ---"
sqlite3 -header -column "$DB" \
  "SELECT id,status,scan_path,worker_pid,stop_reason FROM scan_jobs ORDER BY id;"

echo
echo "--- which of those workers are actually alive right now ---"
for p in $(sqlite3 "$DB" "SELECT worker_pid FROM scan_jobs WHERE worker_pid>1;"); do
  if [ -d "/proc/$p" ]; then
    echo "  pid $p ALIVE : $(tr '\0' ' ' < /proc/$p/cmdline)"
  else
    echo "  pid $p gone"
  fi
done
echo
echo "--- clamscan processes running concurrently ---"
pgrep -a clamscan | sed 's/^/  /' || echo "  none"
