<?php
/**
 * The resource limits must be settable from the page they govern, and the
 * numbers shown there must be the ones actually enforced.
 *
 * Reported: "real-time monitor is consuming more resources than needed; I want
 * a setting for how many resources to pull from the server."
 *
 * The limits were already settable -- in Settings, several screens from the
 * monitor page an operator is looking at when they form that opinion. So this
 * adds the controls to the monitor page itself.
 *
 * What makes that risky is not the markup, it is the three places the same
 * numbers now live: the HTML presets, MON_RES_PRESETS in app.js, and PROFILES
 * in monitor.py. Only the last one is enforced. A card that offers "Light --
 * 5 files/sec" while the daemon runs something else is worse than no card,
 * because it is a specific promise about server load. These tests pin the
 * three together, and pin the setting KEYS to the ones load_profile() reads:
 * a mistyped key saves successfully, changes nothing, and looks like the
 * limits do not work.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$html = file_get_contents($repo . '/frontend/index.html');
$js   = t_js($repo . '/frontend/js/app.js');
$py   = file_get_contents($repo . '/backend/daemon/monitor.py');
$rtm  = t_code($repo . '/backend/lib/RealTimeMonitor.php');

// ── The card is on the monitor page, not in Settings ────────────────────────
//
// Position is the entire point of the change. A card with these ids that
// landed in the Settings screen would pass every other assertion here and
// would not be the thing that was asked for.
$pageTitle = strpos($html, 'Real-Time File Monitor');
$card      = strpos($html, 'id="mon-res-card"');
$watchCard = strpos($html, 'id="mon-paths-list"');
t_ok($pageTitle !== false && $card !== false && $watchCard !== false,
     'the monitor page, the resource card and the watch-paths card all exist');
t_ok($card > $pageTitle && $card < $watchCard,
     'ON THE PAGE IT GOVERNS: the resource card sits inside the Real-Time '
   . 'Monitor page, between its header and the watch-paths card — being in '
   . 'Settings is the complaint, not the fix');

// It must not collide with the existing Settings card, which keeps its own ids
// and its own save button.
t_ok(strpos($html, 'id="set-rt-profile"') !== false,
     'the Settings card is left in place, so no existing workflow breaks');
foreach (['mon-res-profile', 'mon-res-fps', 'mon-res-maxmb', 'mon-res-nice',
          'mon-res-watches', 'mon-res-poll', 'mon-res-debounce',
          'mon-res-excludes', 'mon-res-cpu'] as $id) {
    t_eq(1, substr_count($html, 'id="' . $id . '"'),
         "id $id is declared exactly once — a duplicate id makes "
       . 'getElementById return whichever came first, which is how a control '
       . 'silently stops being the one you are editing');
}

// ── The preset numbers match the daemon's PROFILES ──────────────────────────
//
// PROFILES is the only one of the three copies that is enforced.
preg_match('/^PROFILES = \{(.*?)^\}/ms', $py, $mm);
t_ok(!empty($mm[1]), 'PROFILES is still a dict literal in monitor.py');

$daemon = [];
if (preg_match_all('/^\s*\'(\w+)\':\s*\(\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)\s*\)/m',
                   $mm[1] ?? '', $rows, PREG_SET_ORDER)) {
    foreach ($rows as $r) {
        $daemon[$r[1]] = ['nice' => (int)$r[2], 'fps' => (int)$r[3], 'mb' => (int)$r[4],
                          'poll' => (int)$r[5], 'watches' => (int)$r[6], 'debounce' => (int)$r[7]];
    }
}
t_eq(['light', 'balanced', 'thorough'], array_keys($daemon),
     'the daemon still defines exactly these three presets');

// MON_RES_PRESETS in app.js, parsed the same way.
preg_match('/const MON_RES_PRESETS = \{(.*?)^\};/ms', $js, $jm);
t_ok(!empty($jm[1]), 'MON_RES_PRESETS is declared in app.js');

$ui = [];
if (preg_match_all('/(\w+):\s*\{([^}]*)\}/', $jm[1] ?? '', $rows, PREG_SET_ORDER)) {
    foreach ($rows as $r) {
        $vals = [];
        preg_match_all('/(\w+):\s*(\d+)/', $r[2], $kv, PREG_SET_ORDER);
        foreach ($kv as $p) { $vals[$p[1]] = (int)$p[2]; }
        $ui[$r[1]] = $vals;
    }
}

foreach ($daemon as $name => $want) {
    t_ok(isset($ui[$name]), "app.js knows the '$name' profile");
    if (!isset($ui[$name])) continue;
    foreach ($want as $k => $v) {
        t_eq($v, $ui[$name][$k] ?? null,
             "NO DRIFT: $name.$k is $v in both monitor.py and app.js — the "
           . 'card makes a specific promise about server load, and only the '
           . 'daemon copy is enforced');
    }
}

// The HTML tiles quote the same numbers to the operator.
//
// Scoped to the new card: the Settings card has tiles with the same
// data-profile values and fewer numbers on them, and an unscoped search finds
// those first -- passing or failing for the wrong markup either way.
$cardHtml = '';
if (preg_match('/id="mon-res-card".*?id="mon-res-save-status"/s', $html, $cm)) {
    $cardHtml = $cm[0];
}
t_ok($cardHtml !== '', 'the resource card markup can be isolated for scoping');

foreach ($daemon as $name => $want) {
    $tile = '';
    if (preg_match('/data-profile="' . $name . '".*?<\/label>/s', $cardHtml, $tm)) {
        $tile = $tm[0];
    }
    t_ok($tile !== '', "the '$name' tile exists in the resource card");
    if ($tile === '') continue;
    t_contains($tile, $want['fps'] . ' files/sec',
         "and quotes the daemon's own rate for $name, not a rounder number");
    t_contains($tile, 'nice ' . $want['nice'],
         "and its real nice value");
}

// ── The keys it saves are the keys the daemon reads ─────────────────────────
//
// A mistyped key saves with success:true, changes nothing, and presents as
// "the limits do not work".
preg_match('/async function saveMonitorResources\(\).*?^}/ms', $js, $sm);
$saver = $sm[0] ?? '';
t_ok($saver !== '', 'saveMonitorResources() exists');

$readByDaemon = [
    'rt_profile'           => "db_get(conn, 'rt_profile'",
    'rt_nice'              => "num('rt_nice'",
    'rt_max_files_per_sec' => "num('rt_max_files_per_sec'",
    'rt_max_file_size_mb'  => "num('rt_max_file_size_mb'",
    'rt_poll_interval'     => "num('rt_poll_interval'",
    'rt_max_watches'       => "num('rt_max_watches'",
    'rt_debounce_seconds'  => "num('rt_debounce_seconds'",
    'rt_exclude_dirs'      => "db_get(conn, 'rt_exclude_dirs'",
];
foreach ($readByDaemon as $key => $proof) {
    t_contains($py, $proof,
         "load_profile() reads $key");
    t_contains($saver, $key . ':',
         "THE KEY THE DAEMON READS IS THE KEY THE CARD WRITES: $key — a "
       . 'mistyped setting name saves successfully and does nothing');
}
t_contains($saver, 'cpu_limit_percent:',
     'and the CPU ceiling, which governs the scanner as well as the monitor '
   . '— the single biggest lever over what this product costs the server');
t_contains($py, "db_get(conn, 'cpu_limit_percent'",
     'and that key is the one get_cpu_limit() reads');

// ── Clamps: the inputs may not offer what the daemon will refuse ────────────
//
// An input that accepts 5000 files/sec while load_profile() clamps to 1000
// invites a value that is silently rejected, which is indistinguishable from
// the setting not working.
$clamps = [
    'mon-res-fps'      => ['num(\'rt_max_files_per_sec\', 25,  1, 1000)', 1, 1000],
    'mon-res-maxmb'    => ['num(\'rt_max_file_size_mb\',  16,  1, 512)',  1, 512],
    'mon-res-nice'     => ['num(\'rt_nice\',              10,  0, 19)',   0, 19],
    'mon-res-watches'  => ['num(\'rt_max_watches\',    20000, 100, 500000)', 100, 500000],
    'mon-res-poll'     => ['num(\'rt_poll_interval\',    300, 10, 86400)', 10, 86400],
    'mon-res-debounce' => ['num(\'rt_debounce_seconds\',   5,  0, 3600)',  0, 3600],
];
foreach ($clamps as $id => [$_proof, $lo, $hi]) {
    $input = '';
    if (preg_match('/<input[^>]*id="' . $id . '"[^>]*>/', $html, $im)) { $input = $im[0]; }
    t_ok($input !== '', "the $id input exists");
    if ($input === '') continue;
    t_contains($input, 'min="' . $lo . '"',
         "SAME FLOOR AS THE DAEMON: $id offers no less than $lo");
    t_contains($input, 'max="' . $hi . '"',
         "SAME CEILING AS THE DAEMON: $id offers no more than $hi, so the "
       . 'operator cannot type a number that is silently clamped away');
}

// ── What is shown as "in effect" comes from the daemon ──────────────────────
//
// The whole value of the top row is that it reports enforcement, not
// intention. Every key it reads has to be one the daemon actually writes.
$published = ['rt_effective_profile', 'rt_effective_files_per_sec',
              'rt_effective_poll_interval', 'rt_effective_nice',
              'rt_effective_max_watches', 'rt_watch_count', 'rt_watch_capped'];
foreach ($published as $key) {
    t_contains($py, "'" . $key . "'",
         "THE DAEMON ACTUALLY PUBLISHES $key — a panel reading a key nothing "
       . 'writes renders a confident blank');
    t_contains($rtm, "'" . $key . "'",
         "and RealTimeMonitor exposes it");
}

preg_match('/function renderMonResources\(d\).*?^}/ms', $js, $rm);
$render = $rm[0] ?? '';
t_ok($render !== '', 'renderMonResources() exists');
t_contains($render, 'd.effective_profile',
     'ENFORCED, NOT STORED: the row renders the profile the DAEMON reports, '
   . 'so a value that was clamped or not yet picked up cannot read as applied');
t_contains($render, 'd.effective_nice',
     'and its real nice value, which "custom" could never be inferred from');
t_contains($render, 'd.watch_capped',
     'and it reads the capped flag');
t_contains($render, 'coverage is partial until one of those changes',
     'A CAPPED WATCH COUNT IS PARTIAL COVERAGE: the card says so plainly '
   . 'rather than reporting itself healthy, which is how the silent inotify '
   . 'ceiling went unnoticed in the first place');
t_contains($render, 'polling',
     'and it names polling mode, where the interval is the setting that '
   . 'actually decides the load');

// A save must not be reported as applied on a failed request.
t_contains($saver, "if (!res?.success)",
     'a failed save is reported as not applied, rather than leaving the '
   . 'operator believing a limit is in force');
t_contains($saver, 'loadMonResourceValues()',
     'and the values are read BACK after saving, so a clamped number is '
   . 'shown as what it became');
t_contains($saver, 'loadMonitor()',
     'and the in-effect row is refreshed, so it cannot keep showing the '
   . 'previous profile as though nothing happened');

// Editing a limit under a preset must not silently discard it.
preg_match('/function monResEdited\(\).*?^}/ms', $js, $em);
t_contains($em[0] ?? '', "selectMonResProfile('custom'",
     'editing an individual limit switches to Custom, so a typed value is '
   . 'never dropped because the profile was left on a preset');

// The loader is wired in, or the card renders "Loading…" for ever.
t_contains($js, 'renderMonResources(d);',
     'THE CARD IS REACHED: loadMonitor() calls the renderer — an unwired '
   . 'panel and a failing API look identical, both just sit on the '
   . 'placeholder the markup ships with');
