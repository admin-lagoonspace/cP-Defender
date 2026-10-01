<?php
/**
 * Every class a cron script names must be required by it.
 *
 * A scheduled task that references a class the script never loaded fatals the
 * moment it becomes due -- and cron output goes to a log nobody reads, so the
 * symptom is a feature that silently never runs. This has now happened three
 * times: UserReport, RealTimeMonitor and WAF.
 */
$repo = dirname(__DIR__);
$bad  = 0;
$checked = 0;

foreach (glob($repo . '/backend/cron/*.php') as $file) {
    $src = file_get_contents($file);

    // Classes this script requires, plus ones PHP always has.
    preg_match_all("#require_once[^;]*?/lib/([A-Za-z]+)\.php#", $src, $req);
    $have = array_flip($req[1]);
    $have['Database'] = $have['Logger'] = true;

    // Static calls and `new X` on our own classes.
    preg_match_all('/\b([A-Z][A-Za-z0-9]{2,})::/', $src, $m1);
    preg_match_all('/\bnew\s+([A-Z][A-Za-z0-9]{2,})\s*\(/', $src, $m2);

    $ignore = ['PDO','DateTime','Throwable','Exception','RuntimeException','PHP_EOL',
               'RecursiveIteratorIterator','RecursiveDirectoryIterator','SplFileInfo',
               'ZipArchive','ReflectionMethod','ArrayObject','Closure','Generator'];

    foreach (array_unique(array_merge($m1[1], $m2[1])) as $cls) {
        if (in_array($cls, $ignore, true)) { continue; }
        if (!is_file($repo . '/backend/lib/' . $cls . '.php')) { continue; }
        $checked++;
        if (!isset($have[$cls])) {
            echo "  [x] " . basename($file) . " uses {$cls} but never requires lib/{$cls}.php\n";
            $bad++;
        }
    }
}

if ($bad) {
    echo "\n{$bad} missing require(s) in cron scripts.\n";
    exit(1);
}
echo "Checked {$checked} class use(s) across cron scripts.\n";
echo "Every class used by a cron script is required by it.\n";
