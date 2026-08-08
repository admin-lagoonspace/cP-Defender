#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Sentinel Gate — trigger watcher
#
# Runs every minute. Costs one `test -f` when there is nothing to do, so it is
# effectively free to schedule tightly.
#
# webhook.php always writes a trigger file. Where PHP's exec() is available the
# sync is already running by the time this fires and the lock in cdn-sync.sh
# makes the second attempt a no-op. Where exec() is disabled — common on shared
# cPanel hosting — this is what actually starts the sync, which is why the
# webhook does not depend on exec() being enabled.
#
#   * * * * * /home/lwss1/bin/cdn-trigger-watch.sh >> /home/lwss1/logs/cdn-sync.log 2>&1
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

TRIGGER="${SG_TRIGGER_FILE:-/home/lwss1/.sg-sync-trigger}"
SYNC="${SG_SYNC_SCRIPT:-/home/lwss1/bin/cdn-sync.sh}"

[ -f "$TRIGGER" ] || exit 0

REASON="$(head -1 "$TRIGGER" 2>/dev/null)"

# Consume the trigger BEFORE syncing. If a new release lands mid-sync, GitHub
# rewrites the trigger and the next minute picks it up — removing it afterwards
# would discard that signal and leave the CDN a release behind.
rm -f "$TRIGGER"

echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] webhook trigger: ${REASON:-unknown}"
exec "$SYNC"
