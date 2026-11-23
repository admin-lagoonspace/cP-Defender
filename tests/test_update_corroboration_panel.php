<?php
/**
 * The panel must distinguish "no newer version" from "could not find out".
 *
 * Reported symptom (2026-11-23): the updater printed "Already up to date —
 * v4.37.7" minutes after v4.37.8 was published. The panel reads the same
 * channels through this class and would have agreed, because both mitigations
 * that were supposed to prevent it fail on the GitHub channel, as measured
 * that day:
 *
 *   - ?cb= is not part of raw.githubusercontent.com's cache key. Same object,
 *     two consecutive requests: plain -> X-Cache: MISS, ?cb=... -> X-Cache:
 *     HIT, identical ETag "f7a7cab...". The branch path carries max-age=300.
 *   - .../main/latest/VERSION is a 404, so channelManifest()'s cross-check --
 *     written specifically to catch a cached manifest -- has never been able
 *     to fire on the channel that is now the only working one.
 *
 * So the class could only ever read sources that might be five minutes old,
 * and it recorded the result as fact. Three states are now recorded: a newer
 * version is available, the install is CONFIRMED current, and the check could
 * not be corroborated. The third one is the one that was being rounded down.
 *
 * The fetcher seam feeds the real fetchManifest()/channelManifest(); these are
 * not text assertions about the class, except where the defect was structural.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$CDN = 'https://cdn.example/releases';
$GH  = 'https://raw.githubusercontent.com/example/repo/main';
// The TAG path. Not $GH . '/v<ver>/...': on raw the version is a git ref and
// replaces the branch component, so appending it to .../repo/main/ is a 404 --
// which is what the shipped per-version fetch asked for on this channel.
$TAG = 'https://raw.githubusercontent.com/example/repo/v';
$API = 'https://api.github.com/repos/example/repo/tags';

putenv('SG_CDN_BASE=' . $CDN);
putenv('SG_RELEASES_REPO=example/repo');

$seen = [];

$manifest = function (string $ver, string $sha, string $base): string {
    return json_encode([
        'version' => $ver,
        'url'     => $base . '/dist/serverscrub-' . $ver . '.zip',
        'sha256'  => $sha,
        'notes'   => 'https://notes/' . $ver,
    ]);
};

$tags = function (array $vers): string {
    return json_encode(array_map(function ($v) {
        return ['name' => 'v' . $v, 'commit' => ['sha' => str_repeat('f', 40)]];
    }, $vers));
};

$resolve = function (array $fixtures) use (&$seen): ?array {
    $seen = [];
    UpdateChecker::setFetcherForTests(
        function (string $url, array $headers) use ($fixtures, &$seen): ?string {
            $seen[] = $url;
            $bare = explode('?', $url)[0];
            // The tags url carries a real query string of its own, so it is
            // keyed on the path and matched before the query is stripped.
            foreach ($fixtures as $k => $v) {
                if ($k === $bare || strpos($url, $k) === 0) { return $v; }
            }
            return null;
        }
    );
    $m = (function () {
        $r = new ReflectionMethod('UpdateChecker', 'fetchManifest');
        if (PHP_VERSION_ID < 80100) { $r->setAccessible(true); }
        return $r->invoke(null);
    })();
    UpdateChecker::setFetcherForTests(null);
    return $m;
};

$bare = function () use (&$seen): array {
    return array_map(function ($u) { return explode('?', $u)[0]; }, $seen);
};

// ── THE REPORTED INCIDENT ───────────────────────────────────────────────────
//
// The branch manifest is a cached 4.37.7 while the newest tag is v4.37.8.
$m = $resolve([
    $GH . '/latest.json' => $manifest('4.37.7', str_repeat('a', 64), $GH),
    $API                 => $tags(['4.37.8', '4.37.7']),
    $TAG . '4.37.8/latest.json' => $manifest('4.37.8', str_repeat('d', 64), $GH),
]);

t_eq('4.37.8', $m['version'] ?? null,
     'THE REPORTED INCIDENT: a branch manifest cached at 4.37.7 beside a '
   . 'v4.37.8 tag resolves to 4.37.8, so the panel raises the notification '
   . 'instead of showing a clean dot');
t_eq(str_repeat('d', 64), $m['sha256'] ?? null,
     'and carries the checksum from the manifest committed under that tag — '
   . 'the cached manifest describes the 4.37.7 zip');
t_eq(true, !empty($m['_corroborated']),
     'and the answer is marked corroborated, which is what permits the panel '
   . 'to state a patch level as fact');
t_eq($TAG . '4.37.8/latest.json', (string)($m['_source'] ?? ''),
     'naming the url that confirmed it, so an operator can recheck by hand');
t_ok(in_array($TAG . '4.37.8/latest.json', $bare(), true),
     'THE TAG PATH, NOT THE BRANCH PATH: .../repo/v4.37.8/latest.json is '
   . 'fetched. The shipped code appended v<ver> to the branch base, giving '
   . '.../repo/main/v4.37.8/latest.json, which 404s on this channel');
t_ok(!in_array($GH . '/v4.37.8/latest.json', $bare(), true),
     'and nothing asks for v<ver> underneath main/, which cannot exist');
t_eq(1, count(array_filter($bare(), function ($u) use ($API) {
         return strpos($u, 'api.github.com') !== false;
     })),
     'the tags api is asked exactly ONCE per check: unauthenticated the limit '
   . 'is 60 requests an hour per IP, and scheduled checks run once a day');

// ── NO IMMUTABLE SOURCE: labelled, not asserted ─────────────────────────────
$m = $resolve([
    $GH . '/latest.json' => $manifest('4.37.7', str_repeat('a', 64), $GH),
]);
t_eq('4.37.7', $m['version'] ?? null,
     'NO IMMUTABLE SOURCE: the branch answer still stands — a rate-limited or '
   . 'firewalled server must still get an answer');
t_eq(false, !empty($m['_corroborated']),
     'but it is NOT corroborated, so nothing may present it as a confirmed '
   . 'patch level');

// ── latest/VERSION 404 IS NOT A PASSED CROSS-CHECK ──────────────────────────
$m = $resolve([
    $GH . '/latest.json' => $manifest('4.37.7', str_repeat('a', 64), $GH),
]);
t_ok(in_array($GH . '/latest/VERSION', $bare(), true),
     'the cross-check is still attempted where it used to exist');
t_ok(in_array($GH . '/VERSION', $bare(), true),
     'AND, when it 404s, the alternative that DOES exist on a git-shaped '
   . 'channel is tried: VERSION at the repo root. A 404 was being treated as '
   . '"nothing to disagree with", which reads downstream as a cross-check '
   . 'that passed — that is how the one safety net for a cached manifest '
   . 'became a no-op on the only working channel');
t_eq(false, !empty($m['_corroborated']),
     'and the repo-root VERSION does not make the answer confirmed: it sits '
   . 'behind the same edge cache, with the same five-minute window, so it is '
   . 'a second opinion rather than an independent one');

// A repo-root VERSION AHEAD of the manifest is the cached-manifest case, and
// it must move the answer forward.
$m = $resolve([
    $GH . '/latest.json'        => $manifest('4.37.7', str_repeat('a', 64), $GH),
    $GH . '/VERSION'            => "4.37.8\n",
    $TAG . '4.37.8/latest.json' => $manifest('4.37.8', str_repeat('d', 64), $GH),
]);
t_eq('4.37.8', $m['version'] ?? null,
     'A SEPARATELY-KEYED OBJECT AHEAD OF THE MANIFEST: when the repo-root '
   . 'VERSION reads 4.37.8 beside a manifest reading 4.37.7, the newer one '
   . 'wins — one of the two is a cached copy and only one of them can be');

// ── CONFIRMED CURRENT ───────────────────────────────────────────────────────
$m = $resolve([
    $GH . '/latest.json'        => $manifest('4.37.9', str_repeat('e', 64), $GH),
    $API                        => $tags(['4.37.9', '4.37.8']),
    $TAG . '4.37.9/latest.json' => $manifest('4.37.9', str_repeat('e', 64), $GH),
]);
t_eq('4.37.9', $m['version'] ?? null, 'CONFIRMED CURRENT: the version does not move');
t_eq(true, !empty($m['_corroborated']), 'and it is confirmed against the tag');

// ── A LAGGING MIRROR IS REPORTED ────────────────────────────────────────────
$m = $resolve([
    $CDN . '/latest.json'       => $manifest('4.37.0', str_repeat('b', 64), $CDN),
    $CDN . '/latest/VERSION'    => "4.37.0\n",
    $GH  . '/latest.json'       => $manifest('4.37.9', str_repeat('e', 64), $GH),
    $API                        => $tags(['4.37.9']),
    $TAG . '4.37.9/latest.json' => $manifest('4.37.9', str_repeat('e', 64), $GH),
]);
t_eq('4.37.9', $m['version'] ?? null,
     'A FROZEN MIRROR CANNOT PULL THE ANSWER BACK DOWN');
t_ok(strpos((string)($m['_lag'] ?? ''), $CDN) !== false,
     'and it is REPORTED as a mirror problem, naming the channel: nine '
   . 'releases (4.37.1 … 4.37.9) went unmirrored for a month with no '
   . 'indication anywhere a human looks');
t_ok(strpos((string)($m['_lag'] ?? ''), '4.37.0') !== false,
     'with the version that mirror is stuck on');

// Tag order is not a documented guarantee, and v4.9.0 sorts above v4.36.0 one
// character at a time -- the bug that made 38 releases verify the wrong tag.
$m = $resolve([
    $GH . '/latest.json'        => $manifest('4.9.0', str_repeat('a', 64), $GH),
    $API                        => $tags(['4.9.0', '4.36.0', '4.10.0']),
    $TAG . '4.36.0/latest.json' => $manifest('4.36.0', str_repeat('c', 64), $GH),
]);
t_eq('4.36.0', $m['version'] ?? null,
     'TAG ORDER IS NOT TRUSTED: the highest tag BY VERSION wins, whatever the '
   . 'api listed first');

// ── Nothing reachable is still null, not a fabricated version ───────────────
t_eq(null, $resolve([]),
     'NO CHANNEL REACHABLE: null, so checkForUpdates keeps its cached state '
   . 'instead of inventing one');

// ── THE THREE STATES, as the panel receives them ────────────────────────────
$check = function (array $fixtures) use (&$seen) {
    UpdateChecker::setFetcherForTests(
        function (string $url, array $headers) use ($fixtures, &$seen): ?string {
            $seen[] = $url;
            $b = explode('?', $url)[0];
            foreach ($fixtures as $k => $v) {
                if ($k === $b || strpos($url, $k) === 0) { return $v; }
            }
            return null;
        }
    );
    $r = UpdateChecker::checkForUpdates();
    UpdateChecker::setFetcherForTests(null);
    return $r;
};

$cur = defined('SG_VERSION') ? SG_VERSION : '0.0.0';

// 1. A newer version is available.
$s = $check([
    $GH . '/latest.json'      => $manifest('99.0.0', str_repeat('a', 64), $GH),
    $API                      => $tags(['99.0.0']),
    $TAG . '99.0.0/latest.json' => $manifest('99.0.0', str_repeat('d', 64), $GH),
]);
t_eq(true, (bool)$s['update_available'], 'STATE 1: a newer version is available');
t_eq(true, (bool)$s['corroborated'], 'confirmed against the tag');
t_eq('', (string)$s['uncorroborated_note'], 'so there is nothing to hedge');

// 2. Confirmed current.
$s = $check([
    $GH . '/latest.json'       => $manifest($cur, str_repeat('a', 64), $GH),
    $API                       => $tags([$cur]),
    $TAG . $cur . '/latest.json' => $manifest($cur, str_repeat('a', 64), $GH),
]);
t_eq(false, (bool)$s['update_available'], 'STATE 2: no newer version');
t_eq(true, (bool)$s['corroborated'],
     'and it is CONFIRMED, against a url that names the version');
t_eq('', (string)$s['uncorroborated_note'], 'so the panel shows no notice');
t_eq('', (string)$s['check_error'], 'and no error');

// 3. Could not be corroborated.
$s = $check([
    $GH . '/latest.json' => $manifest($cur, str_repeat('a', 64), $GH),
]);
t_eq(false, (bool)$s['update_available'], 'STATE 3: no newer version seen');
t_eq(false, (bool)$s['corroborated'],
     'but the reading is not confirmed — this is the state that was being '
   . 'rendered identically to state 2, which is how a server a version behind '
   . 'showed a clean dot');
t_ok(strpos($s['uncorroborated_note'], '5 minutes') !== false,
     'and the note says how stale the evidence can be, in minutes');
t_ok(strpos($s['uncorroborated_note'], 'raw.githubusercontent.com') !== false,
     'naming the channel the answer came from');
t_eq('', (string)$s['check_error'],
     'check_error stays empty: the scheduler SKIPS the automatic update when '
   . 'that setting is non-empty (scheduler.php:394), and an uncorroborated '
   . 'check is not a reason to stop applying an update that was found');

// 4. A lagging mirror reaches the panel.
$s = $check([
    $CDN . '/latest.json'       => $manifest('1.0.0', str_repeat('b', 64), $CDN),
    $CDN . '/latest/VERSION'    => "1.0.0\n",
    $GH  . '/latest.json'       => $manifest('99.0.0', str_repeat('e', 64), $GH),
    $API                        => $tags(['99.0.0']),
    $TAG . '99.0.0/latest.json' => $manifest('99.0.0', str_repeat('e', 64), $GH),
]);
t_ok(strpos($s['mirror_lag'], $CDN) !== false,
     'STATE 4: a channel behind the newest version seen reaches the panel as '
   . 'a release-mirror problem, named');

// ── The dashboard actually renders all of it ────────────────────────────────
//
// STRUCTURAL ON PURPOSE. app.js has set #dash-update-error since the
// unreachable-channel fix and NO ELEMENT WITH THAT ID EXISTED in index.html,
// so getElementById returned null, the branch did nothing, and a server that
// had not reached a release channel for weeks looked exactly like a patched
// one. A behavioural assertion cannot see that; the element either is in the
// markup or it is not.
$html = file_get_contents($repo . '/frontend/index.html');
t_contains($html, 'id="dash-update-error"',
     'THE MISSING ELEMENT: #dash-update-error exists in the dashboard markup. '
   . 'app.js has written to it for releases and it was never there');
t_contains($html, 'id="dash-mirror-lag"',
     'and #dash-mirror-lag exists for the release-mirror warning');

$js = t_js($repo . '/frontend/js/app.js');
$fn = t_fn_body($js, 'checkForUpdates');
t_contains($fn, 'uncorroborated_note',
     'the dashboard shows the uncorroborated note, so state 3 is visible');
t_contains($fn, 'mirror_lag',
     'and the mirror-lag warning, so a release that was never mirrored is '
   . 'visible to a human');
t_contains($fn, "d.corroborated === false",
     'and it tests corroborated explicitly against false rather than for '
   . 'truthiness, so an older backend that sends neither key cannot be read '
   . 'as "uncorroborated" and start hedging every check');
