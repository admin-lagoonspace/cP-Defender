<?php
/**
 * Quick scan covers each account's whole home directory, bounded per account,
 * and a bounded account is reported incomplete -- never clean.
 *
 * In April 2026 a root-level qTox run left a dropper at
 * /home/officialwebspace/.cache/.<41 hex>. No scan this product could run
 * would ever have opened that directory:
 *
 *   - quick walked each account's public_html and nothing else;
 *   - SCAN_SKIP_DIRS pruned 'cache' and '.cache' by name at every depth, for
 *     BOTH walks and EVERY scan type -- so even the full scan, which took
 *     57h41m, walked straight past it. Along with node_modules, .git and
 *     .svn: directories whose names the attacker chooses.
 *
 * The user's definition since 4.37.11: quick scans "everything, inside user
 * directory, that means mail too". What keeps it quicker than full is a
 * per-account bound (1,000,000 files, depth 25, 60 min) and a 20 h bound on
 * the run. A bound that fires means the account was NOT fully looked at, so
 * the job is 'incomplete' -- 'done' is what both the WHM dashboard and the
 * customer's page render as "Clean".
 *
 * Fixtures are inert (t_inert_payload); what is asserted is what each walk
 * reaches, because a file a walk never yields can never be detected by any
 * engine.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// ── The tree ────────────────────────────────────────────────────────────────
$R = $ctx['sandbox'] . '/qhome';
$hex41 = str_repeat('a3', 20) . 'f';
$alice = [
    // The April 2026 shape: no extension, in ~/.cache.
    '.cache/.' . $hex41,
    '.cache/drop.php',
    'drop.php',                         // directly in $HOME
    'tmp/t.php',
    '.cphorde/c.php',
    'public_html/index.php',
    'public_html/vendor/v.php',
    'public_html/node_modules/pkg/n.php',
    'mail/example.com/alice/cur/m.php', // mail is in scope now
    'backup-x/b.php',
    '.git/hooks/g.php',
    '.svn/s.php',
];
foreach ($alice as $rel) {
    @mkdir(dirname($R . '/alice/' . $rel), 0777, true);
    file_put_contents($R . '/alice/' . $rel, t_inert_payload('a dropper at ~/' . $rel));
}
// carol has no public_html at all.
@mkdir($R . '/carol/.cache', 0777, true);
file_put_contents($R . '/carol/.cache/x.php', t_inert_payload('a dropper in an account with no web root'));
// The bind-mounted copy: not customer content, never reported.
@mkdir($R . '/virtfs/alice/home/alice/.cache', 0777, true);
file_put_contents($R . '/virtfs/alice/home/alice/.cache/drop.php', t_inert_payload('a virtfs copy'));

$cp = $ctx['sandbox'] . '/qcpanel/users';
@mkdir($cp, 0777, true);
foreach (['alice', 'carol'] as $u) { file_put_contents($cp . '/' . $u, "USER=$u\n"); }
Scanner::setCpanelUsersDir($cp);
Database::setSetting('scan_paths', $R);

// ── 1. Quick resolves to whole homes ────────────────────────────────────────
$q = Scanner::resolveScanPaths('quick', $R);
sort($q['paths']);
t_eq([$R . '/alice', $R . '/carol'], $q['paths'],
    'quick walks each account\'s WHOLE home, carol (no public_html) included: '
  . 'a web-root scan never reaches ~/.cache, where the April 2026 dropper was');
t_contains($q['note'], '2 home dir(s)', 'and the note says how many');

// ── 2. Both walks, both scope shapes, reach everything ──────────────────────
$sc  = new Scanner();
$ref = new ReflectionClass(Scanner::class);
$walk = static function (string $fn, string $root) use ($sc, $ref): array {
    $m = $ref->getMethod($fn);
    $m->setAccessible(true);
    $seen = [];
    foreach ($m->invoke($sc, $root) as $f) { $seen[] = str_replace('\\', '/', $f); }
    return $seen;
};
$has = static function (array $seen, string $suffix): bool {
    foreach ($seen as $p) {
        if (substr($p, -strlen($suffix)) === $suffix) { return true; }
    }
    return false;
};

foreach (['quick' => $R . '/alice', 'full' => $R] as $type => $root) {
    $seenW = $walk('walkFiles', $root);
    $seenP = $walk('getPhpFiles', $root);
    foreach ($alice as $rel) {
        t_ok($has($seenW, '/alice/' . $rel),
            "$type: the ClamAV walk reaches ~/$rel -- if it is not walked it "
          . 'cannot be detected, whatever the signatures say');
        if (substr($rel, -4) === '.php') {
            t_ok($has($seenP, '/alice/' . $rel),
                "$type: the pattern-engine walk reaches ~/$rel too");
        }
    }
    foreach ([$seenW, $seenP] as $seen) {
        t_eq(0, count(array_filter($seen, static function ($p) {
            return strpos($p, '/virtfs/') !== false;
        })), "$type: nothing under virtfs -- one bind mount per account makes the walk multiplicative");
    }
}

// ── 3. A real quick run over both accounts is complete ──────────────────────
$newJob = static function (string $type, string $path): int {
    return (int) Database::insert('scan_jobs', [
        'scan_type' => $type, 'status' => 'running',
        'started_at' => time(), 'scan_path' => $path,
    ]);
};
$paths = [$R . '/alice', $R . '/carol'];
$j   = $newJob('quick', implode(',', $paths));
$run = $sc->runPaths($paths, $j, 'quick');
t_eq([], $run['incomplete'], 'under the default bounds the fixture accounts are scanned whole');
t_ok((int) Database::fetchOne('SELECT files_scanned FROM scan_jobs WHERE id=?', [$j])['files_scanned'] >= 12,
    'and every inspectable file across both homes was examined');
t_eq(['done', ''], Scanner::finalStatus('running', $run['incomplete'], 2),
    'a complete run ends done');

// ── 4. Each bound fires, and fires as INCOMPLETE ────────────────────────────
$cases = [
    'file limit 3 reached'   => ['files' => 3],
    'depth limit 2 reached'  => ['depth' => 2],          // mail/example.com/alice/cur is depth 4
    'time limit 0s reached'  => ['account_seconds' => 0],
];
foreach ($cases as $expect => $bound) {
    Scanner::setQuickBounds($bound);
    $j   = $newJob('quick', $R . '/alice');
    $run = $sc->runPaths([$R . '/alice'], $j, 'quick');
    t_eq(['alice: ' . $expect], $run['incomplete'],
        "the bound fires on a real walk and names the account and the bound ($expect)");
    [$st, $why] = Scanner::finalStatus('running', $run['incomplete'], 1);
    t_eq('incomplete', $st,
        "($expect) an account that hit a bound is INCOMPLETE -- 'done' renders as Clean on the "
      . 'dashboard and the customer page, and this account was not fully looked at');
    t_contains($why, '1 of 1 home dir(s) incomplete: alice: ' . $expect,
        'and the job\'s reason says which account and which bound');
}

// The walks themselves honour the bound, not only the ClamAV path.
foreach (['walkFiles', 'getPhpFiles'] as $fn) {
    $p = $ref->getProperty('walkBound');
    $p->setAccessible(true);
    $p->setValue($sc, ['root' => $R . '/alice', 'files' => 3, 'depth' => 25,
        'account_seconds' => 3600, 'sweep_seconds' => 72000,
        'sweep_end' => microtime(true) + 60, 'deadline' => microtime(true) + 60]);
    // getPhpFiles() counts files WALKED (the walk is the cost) and yields only
    // the inspectable ones, so it may yield fewer than the bound.
    $n = count($walk($fn, $R . "/alice"));
    t_ok($fn === "walkFiles" ? $n === 3 : $n <= 3, "$fn() stops at the file bound (yielded $n)");
    $h = $ref->getProperty('boundHit');
    $h->setAccessible(true);
    t_eq('file limit 3 reached', $h->getValue($sc), "$fn() records that it stopped");
    $h->setValue($sc, '');
    $p->setValue($sc, null);
}

// The whole-run bound: accounts not reached are each listed.
Scanner::setQuickBounds(['sweep_seconds' => 0]);
$j   = $newJob('quick', implode(',', $paths));
$run = $sc->runPaths($paths, $j, 'quick');
t_eq(2, count($run['incomplete']),
    'with the whole-run bound spent, every account not reached is listed, one line each');
t_contains(implode("\n", $run['incomplete']), 'carol: not reached, whole-run time limit 0s',
    'naming the account and the bound');

// ── 5. A missing home is counted, not silently skipped ─────────────────────
Scanner::setQuickBounds(null);
$j   = $newJob('quick', $R . '/ghost');
$run = $sc->runPaths([$R . '/alice', $R . '/ghost'], $j, 'quick');
t_eq(['ghost: home directory missing or unreadable'], $run['incomplete'],
    'an account whose home cannot be opened makes the quick run incomplete');
t_eq('incomplete', Scanner::finalStatus('running', $run['incomplete'], 2)[0],
    '"N accounts not scanned" is never reported as clean');

// ── 6. Full is not bounded ──────────────────────────────────────────────────
Scanner::setQuickBounds(['files' => 3, 'depth' => 1, 'account_seconds' => 0, 'sweep_seconds' => 0]);
$j   = $newJob('full', $R);
$run = $sc->runPaths([$R], $j, 'full');
t_eq([], $run['incomplete'], 'the quick bounds never apply to a full scan');
Scanner::setQuickBounds(null);

// A cancelled scan stays cancelled; it is not relabelled.
t_eq('cancelled', Scanner::finalStatus('cancelling', ['alice: file limit 3 reached'], 1)[0],
    'a stopped scan is reported as stopped');

// ── 7. The defaults are what the spec states ────────────────────────────────
t_eq(['files' => 1000000, 'depth' => 25, 'account_seconds' => 3600, 'sweep_seconds' => 72000],
    Scanner::quickBounds(),
    'bounds: 1,000,000 files, depth 25, 60 min per account, 20 h per run');

// ── 8. No operator-facing text still calls quick "web roots" ────────────────
foreach (['frontend/js/app.js', 'frontend/index.html', 'backend/cli/serverscrub.php'] as $f) {
    t_ok(stripos(file_get_contents($repo . '/' . $f), 'web roots') === false,
        "$f no longer describes quick as web roots");
}
t_contains(file_get_contents($repo . '/frontend/index.html'),
    'all account home directories, including mail',
    'the Settings page says what quick now scans');
t_contains(t_js($repo . '/frontend/js/app.js'), "incomplete: 'var(--amber)'",
    'an incomplete scan is amber in the scan log, not green');
