<?php
/**
 * Sentinel Gate — test runner.
 *
 * DEVELOPMENT ONLY. Never packaged. No external dependencies: adding a
 * dependency manager to run a few dozen assertions is not worth the weight, and
 * the checks that matter here are about the product's own wiring.
 *
 * Every test file is a regression test for a fault that actually reached a
 * production server. If a test looks obvious, it is because the bug it guards
 * against was obvious in hindsight and still shipped.
 *
 *   php tests/run.php            run everything
 *   php tests/run.php auth       run files matching "auth"
 */

$repo = dirname(__DIR__);
$filter = $argv[1] ?? '';

$files = array_merge(
    glob($repo . '/tests/test_*.php'),
    // The real-time monitor is Python. Its resource limits are the part most
    // likely to be got wrong quietly, so they are tested in the same run rather
    // than in a separate suite nobody remembers to invoke.
    glob($repo . '/tests/test_*.py')
);
sort($files);
if ($filter !== '') {
    $files = array_values(array_filter($files, fn($f) => stripos(basename($f), $filter) !== false));
}

$GREEN = "\033[0;32m"; $RED = "\033[0;31m"; $DIM = "\033[2m"; $NC = "\033[0m";

$total = 0; $failed = 0; $failures = [];

foreach ($files as $file) {
    $name = basename($file, '.php');
    echo "\n" . substr($name, 5) . "\n";

    // Each file runs in its own process: the product is built on constants and
    // static state, so one test file must not be able to poison the next.
    // exec(), not shell_exec(): the exit code matters. A test file that dies
    // with a fatal emits no FAIL lines, and an earlier version of this runner
    // reported "71 assertions passed" while two files had crashed outright.
    // A harness that cannot fail is not a harness.
    if (substr($file, -3) === '.py') {
        $python = null;
        foreach ([$repo . '/python/python.exe', $repo . '/python/python',
                  'python3', 'python'] as $cand) {
            if (strpos($cand, '/') !== false || strpos($cand, DIRECTORY_SEPARATOR) !== false) {
                if (is_file($cand)) { $python = $cand; break; }
            } else {
                $probe = [];
                $rc = 0;
                @exec(escapeshellarg($cand) . ' --version 2>&1', $probe, $rc);
                if ($rc === 0) { $python = $cand; break; }
            }
        }
        if ($python === null) {
            // Silently skipping would report a green run for tests that never
            // executed, which is the failure mode this project keeps hitting.
            $total++; $failed++;
            $failures[] = substr($name, 5) . ': no Python interpreter to run it';
            echo "  {$RED}SKIP{$NC} no Python interpreter available
";
            continue;
        }
        $cmd = escapeshellarg($python) . ' ' . escapeshellarg($file) . ' 2>&1';
    } else {
        $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($file) . ' 2>&1';
    }
    $lines = [];
    $exit = 0;
    exec($cmd, $lines, $exit);
    $out = implode("
", $lines);

    if ($exit !== 0 || stripos($out, 'Fatal error') !== false
                    || stripos($out, 'Parse error') !== false) {
        $total++; $failed++;
        $first = '';
        foreach ($lines as $l) {
            if (stripos($l, 'error') !== false) { $first = trim($l); break; }
        }
        $failures[] = substr($name, 5) . ': CRASHED — ' . ($first ?: "exit {$exit}");
        echo "  {$RED}CRASH{$NC} " . ($first ?: "exit {$exit}") . "
";
        continue;
    }

    foreach (explode("\n", trim($out)) as $line) {
        if ($line === '') { continue; }
        if (strpos($line, 'PASS ') === 0) {
            $total++;
            echo "  {$GREEN}ok{$NC}   " . substr($line, 5) . "\n";
        } elseif (strpos($line, 'FAIL ') === 0) {
            $total++; $failed++;
            $failures[] = substr($name, 5) . ': ' . substr($line, 5);
            echo "  {$RED}FAIL{$NC} " . substr($line, 5) . "\n";
        } else {
            echo "  {$DIM}{$line}{$NC}\n";
        }
    }
}

echo "\n";
if ($failed) {
    echo "{$RED}{$failed} of {$total} assertions failed{$NC}\n";
    foreach ($failures as $f) { echo "  - {$f}\n"; }
    exit(1);
}
echo "{$GREEN}{$total} assertions passed{$NC}\n";
exit(0);
