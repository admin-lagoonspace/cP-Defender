#!/usr/bin/env bash
set -uo pipefail
D=/usr/local/serverscrub; DB=$D/database/serverscrub.db
CLI="php $D/backend/cli/serverscrub.php"
hr() { echo; echo "──────── $* ────────"; }

hr "the docroot that is not public_html"
echo "deepnest userdata: $(grep -h documentroot /var/cpanel/userdata/deepnest/* 2>/dev/null | head -2)"
echo "/home/deepnest/public_html exists? $([ -d /home/deepnest/public_html ] && echo yes || echo NO)"
echo "real docroot files: $(find /home/deepnest/sites -type f 2>/dev/null | wc -l)"

hr "what accountsForScan() hands the quick scan"
php -r '
define("SG_ROOT","'$D'"); define("SG_API",true);
require "'$D'/backend/config/config.php";
require "'$D'/backend/lib/Database.php"; require "'$D'/backend/lib/Scanner.php";
$m = new ReflectionMethod("Scanner","accountsForScan"); $m->setAccessible(true);
foreach ($m->invoke(null) as $r) {
  printf("  %-12s home=%-28s docroot=%s\n", $r["user"], $r["home"], $r["docroot"] ?? "(NONE)");
}' 2>&1 | head -20

hr "artefact locations OUTSIDE public_html (the 30 Apr shape)"
for u in deepnest acct3; do
  mkdir -p /home/$u/.cache /home/$u/tmp/webalizer /home/$u/.cpanel/caches/config
  printf 'qTox ID 5F2A8C...\n' > /home/$u/README.md
  printf 'qTox ID 5F2A8C...\n' > /home/$u/.cache/README.md
  printf 'qTox ID 5F2A8C...\n' > /home/$u/tmp/webalizer/README.md
done
echo "planted 6 notes in \$HOME, .cache/ and tmp/webalizer/"

hr "TIMED quick scan of /home"
S=$(date +%s); JOB=$($CLI scan --quick /home | grep job_id | awk '{print $2}')
for i in $(seq 1 180); do
  st=$(sqlite3 "$DB" "SELECT status FROM scan_jobs WHERE id=$JOB;")
  [ "$st" = "completed" ] || [ "$st" = "failed" ] && break
  sleep 2
done
echo "quick job $JOB status=$st elapsed=$(( $(date +%s) - S ))s"
sqlite3 -header -column "$DB" "SELECT files_scanned,threats_found,scan_path FROM scan_jobs WHERE id=$JOB;"

hr "TIMED full scan of /home (virtfs present)"
S=$(date +%s); JOB2=$($CLI scan --full /home | grep job_id | awk '{print $2}')
for i in $(seq 1 300); do
  st2=$(sqlite3 "$DB" "SELECT status FROM scan_jobs WHERE id=$JOB2;")
  [ "$st2" = "completed" ] || [ "$st2" = "failed" ] && break
  sleep 2
done
echo "full job $JOB2 status=$st2 elapsed=$(( $(date +%s) - S ))s"
sqlite3 -header -column "$DB" "SELECT files_scanned,threats_found FROM scan_jobs WHERE id=$JOB2;"
echo "findings under /home/virtfs: $(sqlite3 "$DB" "SELECT COUNT(*) FROM threats WHERE file_path LIKE '/home/virtfs/%';")"
echo "findings outside public_html: $(sqlite3 "$DB" "SELECT COUNT(*) FROM threats WHERE file_path NOT LIKE '%/public_html/%';")"

hr "load + db"
cat /proc/loadavg
sqlite3 "$DB" 'PRAGMA integrity_check; PRAGMA journal_mode;'
