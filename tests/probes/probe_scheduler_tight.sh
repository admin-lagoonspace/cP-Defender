#!/usr/bin/env bash
# SHAKAAL PROBE — the realistic production tick.
#
# At 02:00 the daily/hourly tasks have already run, so the only tasks between
# 'scan' and 'resumescan' are the fast 'every' ones. That is the tick where
# the 5-second procSnapshot() cache is still warm when resumescan asks again.
set -u
DB=/usr/local/serverscrub/database/serverscrub.db
SS=/usr/local/serverscrub

pkill -f 'cron/scan.php' 2>/dev/null; sleep 1
sqlite3 "$DB" "DELETE FROM scan_jobs;"
sqlite3 "$DB" "INSERT OR REPLACE INTO settings (key,value) VALUES ('scan_schedule','daily');"
sqlite3 "$DB" "INSERT OR REPLACE INTO settings (key,value) VALUES ('scan_paths','/home');"

echo "--- tick 1: let every daily/hourly task mark itself run (as at 01:45) ---"
php "$SS/backend/cron/scheduler.php" >/dev/null 2>&1
pkill -f 'cron/scan.php' 2>/dev/null; sleep 1
sqlite3 "$DB" "DELETE FROM scan_jobs;"

# The daily scan becomes due; the marker install.sh left behind is still there.
sqlite3 "$DB" "UPDATE settings SET value = (strftime('%s','now') - 1200) WHERE key LIKE 'last_run_%';"
sqlite3 "$DB" "INSERT OR REPLACE INTO settings (key,value) VALUES ('last_run_scan','0');"
cat > "$SS/logs/.resume-scans.json" <<JSON
[{"path":"/home/acct2","type":"full","by":"@update"}]
JSON

echo "--- tick 2: the 02:00 tick ---"
php "$SS/backend/cron/scheduler.php" 2>&1 \
  | grep -E "running:|started|resumed|reconcile|interrupted|Already" | sed 's/^/  /'

echo
echo "--- scan_jobs ---"
sqlite3 -header -column "$DB" \
  "SELECT id,status,scan_path,worker_pid,stop_reason FROM scan_jobs ORDER BY id;"
echo
echo "--- are those workers alive? ---"
for p in $(sqlite3 "$DB" "SELECT worker_pid FROM scan_jobs WHERE worker_pid>1;" 2>/dev/null); do
  [ -d "/proc/$p" ] && echo "  pid $p ALIVE : $(tr '\0' ' ' < /proc/$p/cmdline)" \
                    || echo "  pid $p gone"
done
echo
echo "--- scan workers actually running right now ---"
pgrep -af 'cron/scan.php' | sed 's/^/  /' || echo "  none"
pkill -f 'cron/scan.php' 2>/dev/null
