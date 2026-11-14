#!/usr/bin/env bash
# Shakaal — bounds, concurrency and permissions, inside the container.
set -uo pipefail
D=/usr/local/serverscrub; DB=$D/database/serverscrub.db
CLI="php $D/backend/cli/serverscrub.php"
hr() { echo; echo "──────── $* ────────"; }

hr "install permissions"
stat -c '%a %U:%G  %n' "$D/database" "$DB" "$D" 2>&1
echo "quarantine dir: $(stat -c '%a %U:%G' /home/.serverscrub/quarantine 2>&1)"

hr "virtfs shape present?"
ls /home/virtfs 2>/dev/null | head -3
echo "virtfs entries: $(ls /home/virtfs 2>/dev/null | wc -l)"
echo "files under /home/virtfs: $(find /home/virtfs -type f 2>/dev/null | wc -l)"
echo "files under /home (total): $(find /home -type f 2>/dev/null | wc -l)"

hr "quick scan path construction (does it look outside public_html?)"
grep -n "public_html" "$D/backend/lib/Scanner.php" | grep -iE "quick|scanPath|buildPath" | head -10

hr "timed full sweep"
START=$(date +%s)
timeout 900 $CLI scan --type=full --wait 2>&1 | tail -25
echo "elapsed: $(( $(date +%s) - START ))s (timeout 900)"

hr "did it walk virtfs?"
sqlite3 "$DB" "SELECT COUNT(*) FROM threats WHERE file_path LIKE '/home/virtfs/%';"
sqlite3 -header -column "$DB" "SELECT id,scan_type,status,files_scanned,threats_found FROM scan_jobs ORDER BY id DESC LIMIT 5;"

hr "concurrency: scan + scheduler + CLI together"
( $CLI scan --type=quick >/tmp/c1.log 2>&1 ) &
( php $D/backend/cron/scheduler.php >/tmp/c2.log 2>&1 ) &
( for i in $(seq 1 25); do $CLI status >/dev/null 2>>/tmp/c3.log; done ) &
wait
echo "SQLITE_BUSY / locked mentions:"
grep -ciE "busy|locked|database is locked" /tmp/c1.log /tmp/c2.log /tmp/c3.log 2>/dev/null
echo "WAL size: $(stat -c %s "$DB-wal" 2>/dev/null || echo 'no wal')"

hr "integrity + db-check"
sqlite3 "$DB" 'PRAGMA integrity_check;'
$CLI db-check 2>&1 | tail -15
