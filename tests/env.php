<?php
/**
 * What environment does this test actually need?
 *
 * DEVELOPMENT ONLY. Not packaged. Not globbed by tests/run.php (no test_ prefix).
 *
 * ── WHY THIS EXISTS ──────────────────────────────────────────────────────────
 *
 * Three times now a test has been written on a bare developer machine, passed
 * there, and failed in the container that is deliberately shaped like a cPanel
 * server:
 *
 *   test_scan_types.php           assumed /var/cpanel/users was empty
 *   test_waf_categories_real.php  assumed no system CRS existed
 *   test_waf_crs_tree.php         assumes no foreign ModSecurity ruleset exists
 *
 * Every one of them was a TEST defect and in every one the product was right.
 * But the suite reported failures on the only machine that resembles a
 * customer's server, which is the machine whose result matters, and the person
 * reading the output had no way to tell "the product is broken" from "this
 * test wanted a different machine".
 *
 * Three is a pattern, so it gets a mechanism rather than a third one-off.
 *
 * ── THE DURABLE FIX IS NOT HERE ──────────────────────────────────────────────
 *
 * The root cause is product code that reads HARDCODED ABSOLUTE PATHS with no
 * injection point, which leaves a test no way to describe the world it wants.
 * Where the product offers an override the problem disappears:
 * WAFInstaller::setConfDir(), setIncludeDir() and now setCrsPath() are exactly
 * that, and the tests that use them do not need anything in this file.
 *
 * WAFInstaller::FOREIGN_RULE_GLOBS is a const with no override, so for now a
 * test that needs those locations empty has to empty them. That is what this
 * does, and it is a workaround: the better fix is an override on the product
 * side, and it is recorded as a finding rather than hidden by this helper.
 *
 * ── WHAT IT DOES ─────────────────────────────────────────────────────────────
 *
 * Moves the matching files aside for the duration of ONE test process and puts
 * them back on shutdown — including after a fatal, which is when it matters.
 * The suite already runs each test file in its own process, so the blast
 * radius is one file.
 *
 * It also PRINTS what it moved. A test that quietly rearranges the machine and
 * then passes is worse than one that fails honestly: the next reader has to be
 * able to see that the pass was conditional, and on what.
 */

if (!function_exists('t_env_isolate')) {

/**
 * Empty a set of glob locations for the rest of this process.
 *
 * @param string[] $globs Absolute glob patterns.
 * @param string   $why   Said out loud, so a conditional pass reads as one.
 * @return int            How many files were moved aside.
 */
function t_env_isolate(array $globs, string $why): int
{
    static $stash = null;

    if ($stash === null) {
        $stash = sys_get_temp_dir() . '/sg-env-' . getmypid() . '-' . mt_rand(1000, 9999);
        @mkdir($stash, 0700, true);
    }

    $moved = [];
    foreach ($globs as $glob) {
        foreach (glob($glob) ?: [] as $path) {
            if (!is_file($path)) { continue; }
            $to = $stash . '/' . count($moved) . '-' . basename($path);
            // rename() across filesystems can fail; copy+unlink is the fallback
            // so a half-isolated environment is never left behind.
            if (@rename($path, $to) || (@copy($path, $to) && @unlink($path))) {
                $moved[] = ['from' => $path, 'to' => $to];
            }
        }
    }

    if ($moved) {
        echo 'NOTE  isolated ' . count($moved) . ' file(s) for this test: ' . $why . "\n";
        foreach ($moved as $m) { echo 'NOTE    moved aside: ' . $m['from'] . "\n"; }
    }

    /* Restore on shutdown, fatal included. Registered per call; each closure
     * owns only the files it moved, so two calls cannot undo each other. */
    register_shutdown_function(static function () use ($moved) {
        foreach ($moved as $m) {
            if (!is_file($m['to'])) { continue; }
            @mkdir(dirname($m['from']), 0755, true);
            if (!@rename($m['to'], $m['from'])) {
                @copy($m['to'], $m['from']);
                @unlink($m['to']);
            }
        }
    });

    return count($moved);
}

/**
 * The same thing, said as a precondition: this test needs no OTHER ModSecurity
 * ruleset installed on the host.
 */
function t_env_without_foreign_rulesets(): int
{
    if (!class_exists('WAFInstaller')) { return 0; }
    return t_env_isolate(
        WAFInstaller::FOREIGN_RULE_GLOBS,
        'it asserts what happens when NO other ModSecurity ruleset is present, '
      . 'and the test container seeds one at the cPanel vendor path'
    );
}

}
