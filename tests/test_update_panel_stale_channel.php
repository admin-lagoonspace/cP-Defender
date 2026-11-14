<?php
/**
 * The in-panel update notification must not be silenced by a cache.
 *
 * Reported symptom (2026-11-13, v4.36.0 release): after the release was
 * published and the CDN sync ran, serverscrub.com/releases/latest.json served
 * 4.35.1 out of cPanel's nginx reverse-proxy cache, with a Last-Modified six
 * days old. Reproduced with THIS CLASS'S exact request headers -- User-Agent
 * and Accept, no revalidation -- so the panel would never have raised the
 * notification for any operator. A cache-busted url returned 4.36.0 from the
 * same host in the same second, and latest/VERSION read 4.36.0 all along.
 *
 * Two defects, both exercised here against the real selection code:
 *
 *   1. fetchManifest() returned the FIRST channel that answered. A channel
 *      that 404s is safe, because the loop moves on; a channel that is
 *      confidently wrong is not. Same defect update.sh had at v4.28.9.
 *   2. Nothing it sent could miss that cache. Only a url the proxy has never
 *      seen does, which means a query parameter, not a header.
 *
 * These are not text assertions. The fetcher seam feeds the real
 * fetchManifest()/channelManifest() fixtures and records every url and header
 * they ask for.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$CDN = 'https://cdn.example/releases';
// channels() builds this from SG_RELEASES_REPO; the host is fixed in code.
$GH  = 'https://raw.githubusercontent.com/example/repo/main';

putenv('SG_CDN_BASE=' . $CDN);
putenv('SG_RELEASES_REPO=example/repo');

/** The urls and headers the class asked for during the last resolve(). */
$seen = [];

$manifest = function (string $ver, string $sha, string $base): string {
    return json_encode([
        'version' => $ver,
        'url'     => $base . '/dist/serverscrub-' . $ver . '.zip',
        'sha256'  => $sha,
        'notes'   => 'https://notes/' . $ver,
    ]);
};

/**
 * Run the REAL fetchManifest() against a url => body fixture map.
 * A url absent from the map is a 404, which is what a channel serving only
 * dist/ does for latest/VERSION.
 */
$resolve = function (array $fixtures) use (&$seen): ?array {
    $seen = [];
    UpdateChecker::setFetcherForTests(
        function (string $url, array $headers) use ($fixtures, &$seen): ?string {
            $seen[] = ['url' => $url, 'headers' => $headers];
            $bare = explode('?', $url)[0];
            return $fixtures[$bare] ?? null;
        }
    );
    $m = (function () {
        $r = new ReflectionMethod('UpdateChecker', 'fetchManifest');
        // Required below 8.1, a no-op and deprecated at and above it.
        if (PHP_VERSION_ID < 80100) { $r->setAccessible(true); }
        return $r->invoke(null);
    })();
    UpdateChecker::setFetcherForTests(null);
    return $m;
};

$urls = function () use (&$seen): array {
    return array_map(function ($s) { return $s['url']; }, $seen);
};

// ── THE 4.36.0 FAILURE ──────────────────────────────────────────────────────
//
// The CDN answers with a cached 4.35.1 manifest while its own extracted tree
// reads 4.36.0, and the GitHub raw mirror is behind its own cache serving
// 4.35.1 too. Before the fix this returned 4.35.1 and the panel stayed quiet.
$m = $resolve([
    $CDN . '/latest.json'         => $manifest('4.35.1', str_repeat('a', 64), $CDN),
    $CDN . '/latest/VERSION'      => "4.36.0\n",
    $CDN . '/v4.36.0/latest.json' => $manifest('4.36.0', str_repeat('b', 64), $CDN),
    $GH  . '/latest.json'         => $manifest('4.35.1', str_repeat('a', 64), $GH),
]);

t_eq('4.36.0', $m['version'] ?? null,
     'THE 4.36.0 FAILURE: a cached 4.35.1 manifest sitting beside a 4.36.0 '
   . 'tree resolves to 4.36.0, so the panel raises the notification');
t_eq(str_repeat('b', 64), $m['sha256'] ?? null,
     'and carries the checksum for THAT build — the stale manifest\'s hash '
   . 'describes the 4.35.1 zip and would fail verification');
t_eq($CDN . '/dist/serverscrub-4.36.0.zip', $m['url'] ?? null,
     'and the download url points at the build that exists');
t_ok(in_array($CDN . '/latest/VERSION', array_map(function ($u) {
         return explode('?', $u)[0];
     }, $urls()), true),
     'THE CROSS-CHECK IS MADE AT ALL: the panel reads latest/VERSION, which '
   . 'it never did before — it only ever asked for the manifest');

// ── Every fetch has to be able to miss the cache ─────────────────────────────
//
// Measured on the live host: no-cache and Pragma made no difference; a ?cb=
// the proxy had not seen returned the new version immediately.
$all = $urls();
t_ok(count($all) > 0, 'the resolver fetches something');
$unbusted = array_values(array_filter($all, function ($u) {
    return strpos($u, 'cb=') === false;
}));
t_eq([], $unbusted,
     'CACHE KEY: every url carries a single-use cache-buster (' . count($all)
   . ' fetched). Client revalidation headers were measured NOT to miss '
   . 'cPanel\'s nginx cache; only a new cache key did');

$hdrs = $seen[0]['headers'] ?? [];
t_ok(in_array('Cache-Control: no-cache, no-store, max-age=0', $hdrs, true),
     'the revalidation headers are sent as well — free, and they do work on '
   . 'the caches between a customer\'s server and us that honour them');
t_ok(in_array('Pragma: no-cache', $hdrs, true), 'including Pragma for HTTP/1.0 proxies');

// Two different resolves must not share a cache key, or the second one is
// answerable from whatever the first one warmed.
$first = $urls();
$resolve([$CDN . '/latest.json' => $manifest('4.36.0', str_repeat('a', 64), $CDN)]);
t_ok($first[0] !== $urls()[0],
     'and the buster differs between runs, so a check does not poison the next');

// ── First-answer rule ───────────────────────────────────────────────────────
//
// The v4.28.9 incident, on the panel side. The CDN answered with a valid
// older manifest and the loop stopped there.
$m = $resolve([
    $CDN . '/latest.json' => $manifest('4.28.9',  str_repeat('a', 64), $CDN),
    $GH  . '/latest.json' => $manifest('4.28.10', str_repeat('c', 64), $GH),
]);
t_eq('4.28.10', $m['version'] ?? null,
     'FIRST-ANSWER RULE: the newest manifest across channels wins, not the '
   . 'first channel that replied — and 4.28.10 over 4.28.9 needs a version '
   . 'compare, not a string compare');
t_eq($GH . '/dist/serverscrub-4.28.10.zip', $m['url'] ?? null,
     'and the url comes from the channel that actually has it');

// A dead channel still falls through — the one thing the old rule got right.
$m = $resolve([$GH . '/latest.json' => $manifest('4.36.0', str_repeat('c', 64), $GH)]);
t_eq('4.36.0', $m['version'] ?? null,
     'an unreachable first channel is skipped and a later one answers');

// Nothing reachable at all is null, not a fabricated version. The caller
// keeps its cached state and records the error rather than claiming a check.
t_eq(null, $resolve([]),
     'NO CHANNEL REACHABLE: null, so checkForUpdates keeps the cached state '
   . 'instead of inventing one');

// A manifest that is not a manifest is not a version.
t_eq(null, $resolve([$CDN . '/latest.json' => '<html>maintenance</html>']),
     'a captive-portal or error page is not accepted as a manifest');
t_eq(null, $resolve([$CDN . '/latest.json' => '{"version":"not-a-version"}']),
     'nor is a manifest whose version is not a version');

// ── The override is one-directional ─────────────────────────────────────────
//
// A tree BEHIND the manifest is a sync still extracting. There is nothing to
// take there, and rolling back to it would be a downgrade.
$m = $resolve([
    $CDN . '/latest.json'    => $manifest('4.36.0', str_repeat('b', 64), $CDN),
    $CDN . '/latest/VERSION' => "4.35.1\n",
]);
t_eq('4.36.0', $m['version'] ?? null,
     'MID-SYNC: a manifest AHEAD of latest/ stands — the cross-check only '
   . 'ever moves the answer forward');
t_eq(str_repeat('b', 64), $m['sha256'] ?? null, 'with its own checksum intact');

// A losing channel still reports its tree. Easy half of the fix to miss: the
// CDN manifest can lose the comparison while the CDN tree holds the answer.
$m = $resolve([
    $CDN . '/latest.json'         => $manifest('4.30.0', str_repeat('a', 64), $CDN),
    $CDN . '/latest/VERSION'      => "4.36.0\n",
    $CDN . '/v4.36.0/latest.json' => $manifest('4.36.0', str_repeat('b', 64), $CDN),
    $GH  . '/latest.json'         => $manifest('4.35.1', str_repeat('c', 64), $GH),
]);
t_eq('4.36.0', $m['version'] ?? null,
     'A LOSING CHANNEL STILL REPORTS ITS TREE: the CDN manifest (4.30.0) is '
   . 'older than GitHub\'s (4.35.1), and the CDN tree (4.36.0) still decides');

// No per-version manifest: report the version, carry no checksum. Presenting
// the stale manifest's hash as verification of a different build would be
// worse than having none.
$m = $resolve([
    $CDN . '/latest.json'    => $manifest('4.35.1', str_repeat('a', 64), $CDN),
    $CDN . '/latest/VERSION' => "4.36.0\n",
]);
t_eq('4.36.0', $m['version'] ?? null,
     'NO PINNED MANIFEST: the version from the tree is still reported — an '
   . 'operator told they are up to date when they are not is the worse of '
   . 'the two failures');
t_eq('', (string)($m['sha256'] ?? ''),
     'and NO checksum, so the 4.35.1 hash cannot be shown as verification of '
   . 'a 4.36.0 download');
t_eq('', (string)($m['url'] ?? ''),
     'and no download url, so nothing downstream can fetch an unverified zip '
   . 'as though it were verified');

// A channel with no latest/ tree (dist/ only) is normal, not an error.
$m = $resolve([$CDN . '/latest.json' => $manifest('4.36.0', str_repeat('b', 64), $CDN)]);
t_eq('4.36.0', $m['version'] ?? null,
     'NO latest/ TREE: a channel serving only dist/ is normal and its '
   . 'manifest stands');

// ── The seam is not a production code path ──────────────────────────────────
$code = t_code($repo . '/backend/lib/UpdateChecker.php');
t_contains($code, "if (!defined('SG_TEST'))",
     'THE SEAM IS FENCED: the test fetcher cannot be installed outside tests/');
t_contains($code, 'private static $fetcher = null;',
     'and it is null in production, so a shipped install always does real HTTP');

// ── An explicit SG_MANIFEST_URL still disables rotation ─────────────────────
putenv('SG_MANIFEST_URL=' . $CDN . '/latest.json');
$m = $resolve([
    $CDN . '/latest.json' => $manifest('4.30.0', str_repeat('a', 64), $CDN),
    $GH  . '/latest.json' => $manifest('4.36.0', str_repeat('c', 64), $GH),
]);
t_eq('4.30.0', $m['version'] ?? null,
     'AN OPERATOR OVERRIDE IS STILL AN OVERRIDE: SG_MANIFEST_URL pins the '
   . 'channel, and asking everyone must not quietly re-enable rotation');
putenv('SG_MANIFEST_URL');

