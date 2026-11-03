<?php
/**
 * Every lib must load on its own.
 *
 * backend/lib classes required nothing and relied on each caller having
 * loaded their dependencies first. scheduler.php and user-scans.php loaded
 * UserScanRequest; the CLI did not. So `serverscrub user-reports` hit
 *
 *     Error: Class "UserScanRequest" not found
 *
 * inside UserReport::build(), on all 132 accounts -- and writeAll() catches
 * Throwable per account, so it surfaced as "no usable home directory" and
 * every customer's report.json stayed frozen for three releases while the
 * page kept rendering it.
 *
 * A class whose correctness depends on the caller's include list breaks the
 * moment a new caller appears, and breaks SILENTLY wherever that caller
 * catches Throwable. check-cron-requires.php enforces this for cron scripts;
 * nothing enforced it for the libs themselves.
 *
 * Each file is loaded in a FRESH process. Loading them all in one would hide
 * exactly what this looks for: an earlier file declaring the class that a
 * later one forgot to require.
 */

// Forward slashes throughout. These paths are embedded in a generated PHP
// double-quoted string, and on Windows a backslash run becomes an escape.
$slash = static function (string $p): string { return str_replace('\\', '/', $p); };

$ROOT = $slash(dirname(__DIR__));
$TMP  = $slash(sys_get_temp_dir()) . '/sg-libload';
@mkdir($TMP, 0777, true);

$header = '<?php
define("SG_ROOT","' . $ROOT . '");
define("SG_DB",SG_ROOT."/database/check-libload.db");
define("SG_LOGS",SG_ROOT."/logs"); define("SG_TMP",sys_get_temp_dir());
define("CPANEL_BASE","/usr/local/cpanel"); define("CPANEL_USER","root");
define("SCAN_MAX_SIZE",52428800); define("SIG_DIR",SG_ROOT."/backend/signatures");
define("QUARANTINE_DIR",SG_ROOT."/quarantine"); define("RBL_FEEDS",serialize([]));
define("JWT_SECRET","x"); define("JWT_EXPIRY",28800);
define("INSTALL_MODE","cpanel"); define("SG_PORT",31150); define("SG_VERSION","t");
';

$fail  = 0;
$n     = 0;
$probe = $TMP . '/probe.php';

// Which sibling classes exist, so references to them can be told apart from
// references to PHP's own classes.
$siblings = [];
foreach (glob($ROOT . '/backend/lib/*.php') ?: [] as $f) {
    $siblings[basename($f, '.php')] = true;
}

foreach (glob($ROOT . '/backend/lib/*.php') ?: [] as $f) {
    $cls = basename($f, '.php');
    $n++;

    // Declaring its own class is NOT the test.
    //
    // The first version of this check did only that, and it passed happily
    // with the UserScanRequest require removed again -- because UserReport
    // still declares UserReport perfectly well. The class that goes missing
    // is one the file CALLS, and that call only runs in production. So every
    // sibling class this file references has to be loadable too.
    $src  = (string) file_get_contents($f);
    $code = (string) preg_replace('#/\*.*?\*/#s', '', $src);
    $code = (string) preg_replace('#//[^\n]*#', '', $code);
    preg_match_all('/\b([A-Z][A-Za-z0-9_]+)::/', $code, $m);

    $needs = [];
    foreach (array_unique($m[1]) as $ref) {
        if ($ref !== $cls && isset($siblings[$ref])) { $needs[] = $ref; }
    }

    $checks = 'exit(class_exists("' . $cls . '") || interface_exists("' . $cls . '") ? 0 : 3);';
    if ($needs) {
        $list = '"' . implode('","', $needs) . '"';
        $checks = 'foreach ([' . $list . '] as $need) {' . "\n"
                . '  if (!class_exists($need) && !interface_exists($need)) {' . "\n"
                . '    fwrite(STDERR, "calls " . $need . ":: but never requires it"); exit(4);' . "\n"
                . '  }' . "\n"
                . '}' . "\n" . $checks;
    }

    $body = $header
          . 'require "' . $slash($f) . '";' . "\n"
          . $checks;
    file_put_contents($probe, $body);

    $out  = [];
    $code = 0;
    exec('"' . PHP_BINARY . '" "' . $probe . '" 2>&1', $out, $code);

    if ($code === 0) {
        continue;
    }
    $fail++;
    // Exit 3 means the file loaded but did not declare the class it is
    // named for; anything else means it could not be loaded at all.
    if ($code === 3)     { $why = 'loaded but did not declare ' . $cls; }
    elseif ($code === 4) { $why = 'uses a sibling class it does not require'; }
    else                 { $why = 'failed to load (exit ' . $code . ')'; }
    echo '  [x] ' . $cls . ': ' . $why . "\n";
    foreach (array_slice($out, 0, 2) as $l) {
        if (trim($l) !== '') { echo '        ' . trim($l) . "\n"; }
    }
}

@unlink($probe);

if ($fail > 0) {
    echo "\n  " . $fail . ' of ' . $n . " libs cannot load without help from the caller.\n";
    echo "  Add the missing require_once to the lib itself -- placed AFTER any\n";
    echo "  declare(strict_types=1), which must remain the first statement.\n";
    exit(1);
}

echo 'all ' . $n . " libs load standalone and declare their class\n";
exit(0);
