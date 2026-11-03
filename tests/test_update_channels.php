<?php
/**
 * A channel that answers with stale data must not pin the server to it.
 *
 * The updater walked its channel list and stopped at the first one that
 * replied. That was right while a broken channel 404d -- it fell through to
 * the next. It is wrong when a channel replies with OLD data: the updater
 * believes it, prints "Already up to date", and every server stays on an old
 * version with nothing anywhere to say why.
 *
 * Which is what happened. The CDN's sync died before writing its manifest, so
 * serverscrub.com served v4.28.9 while GitHub had v4.28.10, and the updater
 * never asked GitHub because the CDN had already answered. Ironically the
 * CDN being BROKEN (404) worked better than the CDN being WRONG.
 *
 * A channel that fails loudly is safe. A channel that is confidently wrong is
 * not, so correctness cannot rest on which one replies first.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$upd = t_shell($repo . '/update.sh');

// ── Every channel is asked, and the newest wins ────────────────────────────
t_ok(strpos($upd, 'ok "Channel reachable: ${BASE}"
            break') === false,
     'THE FIRST-ANSWER RULE: the loop no longer stops at the first channel '
   . 'that replies');
t_contains($upd, 'if [[ -z "$MANIFEST_JSON" ]] || { [[ -n "$THIS_VER" ]] && _ver_gt "$THIS_VER" "$BEST_VER"; }; then',
     'a channel is adopted only when it offers a NEWER version than the best '
   . 'so far');
t_contains($upd, 'DIST_BASE="${BASE}/dist"',
     'and the download base follows the channel that won, not the one that '
   . 'happened to be first — downloading 4.28.10 from a mirror still serving '
   . '4.28.9 would 404');

// The comparison has to exist before the loop. _is_newer is defined much
// further down, after the manifest has been parsed, and cannot be used here.
t_contains($upd, '    _ver_gt() {',
     'with a version comparison available at that point in the script');
t_contains($upd, '[[ "$(printf \'%s\n%s\n\' "$b" "$a" | sort -V | tail -1)" == "$a" ]]',
     'done with sort -V, which handles 4.28.9 vs 4.28.10 — a string compare '
   . 'puts 4.28.9 last and would have kept exactly the stale version this is '
   . 'about');

// ── Disagreement is reported, not silently resolved ────────────────────────
//
// Taking the newest fixes the update. It does not fix the mirror, and nothing
// else on the server would ever mention that one is stuck.
t_contains($upd, 'warn "Channels disagree about the latest version:"',
     'THE SILENT MIRROR: when channels disagree the updater says so, rather '
   . 'than quietly papering over a sync that has stopped');
t_contains($upd, 'A channel behind the others has a stalled sync.',
     'and names what that means');
t_contains($upd, 'if [[ "$_distinct" -gt 1 ]]; then',
     'only when they actually differ — a warning on every run is a warning '
   . 'nobody reads');

// ── The cost of asking everyone ────────────────────────────────────────────
//
// Probing every channel with the full retry budget would add ~8s per dead
// channel to every single update.
t_contains($upd, '        if [[ -n "$MANIFEST_JSON" ]]; then
            API_RETRIES=1
        fi',
     'once one channel has answered the rest get a single attempt, so the '
   . 'common path does not pay for the rare one');

// ── The old fallback must still work ───────────────────────────────────────
t_contains($upd, 'warn "Channel unreachable, trying next…"
            continue',
     'an unreachable channel is skipped and the walk continues — the '
   . 'behaviour that carried every update while the CDN was 404ing');

// ── The override still bypasses all of it ──────────────────────────────────
t_contains($upd, '[[ -n "${SG_MANIFEST_URL:-}" ]] && CHANNELS=("${SG_MANIFEST_URL%/latest.json}")',
     'SG_MANIFEST_URL still pins a single channel, which is what unblocks a '
   . 'server while a mirror is being repaired');
