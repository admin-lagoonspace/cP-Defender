#!/usr/bin/env bash
# Shakaal — is .cache invisible to a FULL scan? EICAR is the only thing the
# stubbed ClamAV flags, so it is the only honest probe for "was this read".
set -uo pipefail
D=/usr/local/serverscrub; DB=$D/database/serverscrub.db
E='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
U=acct1; H=/home/$U
mkdir -p "$H/public_html" "$H/.cache" "$H/cache" "$H/.cpanel/caches/config" "$H/tmp/webalizer" "$H/.cphorde" "$H/ssl"
printf '%s' "$E" > "$H/public_html/probe_docroot.php"          # control: must be found
printf '%s' "$E" > "$H/probe_home.php"                          # $HOME
printf '%s' "$E" > "$H/.cache/probe_dotcache.php"               # .cache
printf '%s' "$E" > "$H/cache/probe_cache.php"                   # cache
printf '%s' "$E" > "$H/.cpanel/caches/config/probe_cpcache.php" # .cpanel/caches
printf '%s' "$E" > "$H/tmp/webalizer/probe_webalizer.php"       # tmp/webalizer
printf '%s' "$E" > "$H/.cphorde/probe_cphorde.php"              # .cphorde
printf '%s' "$E" > "$H/ssl/probe_ssl.php"                       # ssl
echo "planted 8 EICAR probes under $H"

sqlite3 "$DB" "DELETE FROM threats;" 2>/dev/null
J=$(php $D/backend/cli/serverscrub.php scan --full /home | grep job_id | awk '{print $2}')
for i in $(seq 1 150); do s=$(sqlite3 "$DB" "SELECT status FROM scan_jobs WHERE id=$J;"); case "$s" in done|completed|failed|error) break;; esac; sleep 2; done
echo "full scan job $J status=$s files_scanned=$(sqlite3 "$DB" "SELECT files_scanned FROM scan_jobs WHERE id=$J;")"
echo
echo "PROBE                 FOUND BY FULL SCAN?"
for p in probe_docroot probe_home probe_dotcache probe_cache probe_cpcache probe_webalizer probe_cphorde probe_ssl; do
  n=$(sqlite3 "$DB" "SELECT COUNT(*) FROM threats WHERE file_path LIKE '%${p}.php';")
  printf "  %-20s %s\n" "$p" "$([ "$n" -gt 0 ] && echo FOUND || echo '*** NOT SEEN ***')"
done
