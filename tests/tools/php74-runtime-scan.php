<?php
/**
 * The fourth category: code that PARSES on the floor and FATALS when it runs.
 *
 * DEVELOPMENT ONLY. Not packaged, not globbed by tests/run.php.
 *
 * ── WHY THIS EXISTS ──────────────────────────────────────────────────────────
 *
 * We believed PHP 7.4 was broken in three files. It was thirty `match()`
 * expressions and forty-eight `str_contains`/`str_starts_with`/
 * `str_ends_with` calls, because `php -l` STOPS AT THE FIRST ERROR in a file
 * and reports nothing about the rest — and reports nothing at all about a call
 * to a function that will not exist until PHP 8.
 *
 * A parse gate cannot see this class of fault. `str_contains($h, $n)` is
 * perfectly valid 7.4 syntax; it is a fatal `Call to undefined function` the
 * moment that line executes, which on a customer's server is the first request
 * that reaches it.
 *
 * So this resolves every function call, class reference, constant and
 * interface in the tree against the interpreter it is RUN BY. Run it with the
 * oldest supported PHP and anything it reports is a runtime fatal waiting for
 * the right code path.
 *
 *   php tests/tools/php74-runtime-scan.php [path ...]
 *
 * Exit 1 if anything is unresolved.
 *
 * ── WHAT IT CANNOT SEE ───────────────────────────────────────────────────────
 *
 * Dynamic calls — $fn(), call_user_func('str_contains', ...), new $cls — are
 * invisible to a token scan, and so are methods on objects, whose class is not
 * known statically. This narrows the gap; it does not close it. The only thing
 * that closes it is executing the code on the floor version.
 */

error_reporting(E_ALL);

$roots = array_slice($argv, 1);
if (!$roots) {
    $repo  = dirname(dirname(__DIR__));
    $roots = [$repo . '/backend', $repo . '/cpanel', $repo . '/whm'];
}

/* Collect everything the project defines itself, so its own helpers are not
 * reported as missing. Done across the WHOLE tree first, because a function
 * defined in one file is called from another. */
$ownFunctions = [];
$ownClasses   = [];
$ownConstants = [];
$files        = [];

foreach ($roots as $root) {
    if (is_file($root)) { $files[] = $root; continue; }
    if (!is_dir($root)) { continue; }
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $f) {
        if ($f->isFile() && strtolower($f->getExtension()) === 'php') { $files[] = $f->getPathname(); }
    }
}
sort($files);

foreach ($files as $file) {
    $toks = @token_get_all((string) file_get_contents($file));
    if (!$toks) { continue; }
    for ($i = 0, $n = count($toks); $i < $n; $i++) {
        $t = $toks[$i];
        if (!is_array($t)) { continue; }
        if ($t[0] === T_FUNCTION) {
            $j = $i + 1;
            while ($j < $n && is_array($toks[$j]) && in_array($toks[$j][0], [T_WHITESPACE], true)) { $j++; }
            if ($j < $n && is_array($toks[$j]) && $toks[$j][0] === T_STRING) {
                $ownFunctions[strtolower($toks[$j][1])] = true;
            }
        }
        if (in_array($t[0], [T_CLASS, T_INTERFACE, T_TRAIT], true)) {
            $j = $i + 1;
            while ($j < $n && is_array($toks[$j]) && $toks[$j][0] === T_WHITESPACE) { $j++; }
            if ($j < $n && is_array($toks[$j]) && $toks[$j][0] === T_STRING) {
                $ownClasses[strtolower($toks[$j][1])] = true;
            }
        }
    }
    if (preg_match_all('/\bdefine\s*\(\s*[\'"]([A-Za-z_][A-Za-z0-9_]*)[\'"]/', (string) file_get_contents($file), $m)) {
        foreach ($m[1] as $c) { $ownConstants[$c] = true; }
    }
    if (preg_match_all('/\bconst\s+([A-Za-z_][A-Za-z0-9_]*)/', (string) file_get_contents($file), $m)) {
        foreach ($m[1] as $c) { $ownConstants[$c] = true; }
    }
}

/* Language constructs that look like calls but are not functions. */
$constructs = array_flip([
    'echo','print','isset','unset','empty','list','array','exit','die','include',
    'include_once','require','require_once','eval','new','clone','return','if',
    'elseif','while','for','foreach','switch','match','catch','function','fn',
    'use','and','or','xor','static','parent','self','class','int','float',
    'string','bool','void','callable','iterable','object','mixed','null','true',
    'false','default','case','yield','throw','global','declare','printf_',
]);

$missingFns    = [];
$missingCls    = [];
$missingConsts = [];

foreach ($files as $file) {
    $src  = (string) file_get_contents($file);
    $toks = @token_get_all($src);
    if (!$toks) { continue; }
    $n = count($toks);

    for ($i = 0; $i < $n; $i++) {
        $t = $toks[$i];
        if (!is_array($t) || $t[0] !== T_STRING) { continue; }
        $name  = $t[1];
        $lower = strtolower($name);
        $line  = $t[2];

        // What precedes it decides what it is.
        $p = $i - 1;
        while ($p >= 0 && is_array($toks[$p]) && $toks[$p][0] === T_WHITESPACE) { $p--; }
        $prev = $p >= 0 ? $toks[$p] : null;
        $prevIs = static function ($tok, $type) {
            return is_array($tok) && $tok[0] === $type;
        };
        // Skip property/method access and class-constant access: the receiver's
        // type is not known statically, so these cannot be resolved here.
        if ($prev !== null && (
                $prevIs($prev, T_OBJECT_OPERATOR)
             || $prevIs($prev, T_DOUBLE_COLON)
             || $prevIs($prev, T_FUNCTION)
             || $prevIs($prev, T_CONST)
             || $prevIs($prev, T_NEW)        // handled separately below
             || $prevIs($prev, T_CLASS)
             || $prevIs($prev, T_INTERFACE)
             || $prevIs($prev, T_TRAIT)
             || $prevIs($prev, T_NS_SEPARATOR)
        )) {
            if ($prevIs($prev, T_NEW)) {
                if (!isset($ownClasses[$lower]) && !class_exists($name) && !interface_exists($name)) {
                    $missingCls[$name][] = basename($file) . ':' . $line;
                }
            }
            continue;
        }

        // What follows decides call vs constant.
        $q = $i + 1;
        while ($q < $n && is_array($toks[$q]) && $toks[$q][0] === T_WHITESPACE) { $q++; }
        $next = $q < $n ? $toks[$q] : null;

        if ($next === '(') {
            if (isset($constructs[$lower]) || isset($ownFunctions[$lower])) { continue; }
            if (function_exists($name)) { continue; }
            /* A call the file itself guards is not a fatal waiting to happen.
             * Auth.php does exactly this for getallheaders(), absent under the
             * CGI SAPI cpsrvd uses, and falls back to $_SERVER. Reporting that
             * as a defect trains the reader to ignore this tool, which is the
             * one thing it cannot afford. */
            if (strpos($src, "function_exists('" . $name . "')") !== false
             || strpos($src, 'function_exists("' . $name . '")') !== false) { continue; }
            // A class being instantiated via `new` is handled above; a bare
            // Name( here is a function call.
            $missingFns[$lower][] = basename($file) . ':' . $line;
            continue;
        }

        if (is_array($next) && $next[0] === T_DOUBLE_COLON) {
            if (isset($ownClasses[$lower]) || in_array($lower, ['self','static','parent'], true)) { continue; }
            if (class_exists($name) || interface_exists($name)) { continue; }
            $missingCls[$name][] = basename($file) . ':' . $line;
            continue;
        }

        // A bare ALL-CAPS identifier is almost always a constant.
        if (preg_match('/^[A-Z][A-Z0-9_]*$/', $name)) {
            if (isset($ownConstants[$name]) || defined($name)) { continue; }
            if (isset($constructs[$lower])) { continue; }
            $missingConsts[$name][] = basename($file) . ':' . $line;
        }
    }
}

/* `instanceof X` and `catch (X ...)` */
foreach ($files as $file) {
    $src = (string) file_get_contents($file);
    if (preg_match_all('/\b(?:instanceof|catch\s*\(\s*)\\\\?([A-Z][A-Za-z0-9_]*)/', $src, $m, PREG_OFFSET_CAPTURE)) {
        foreach ($m[1] as $hit) {
            $name = $hit[0];
            // self/static/parent are keywords here, not class names.
            if (in_array(strtolower($name), ['self', 'static', 'parent'], true)) { continue; }
            if (isset($ownClasses[strtolower($name)])) { continue; }
            if (class_exists($name) || interface_exists($name)) { continue; }
            $line = substr_count(substr($src, 0, $hit[1]), "\n") + 1;
            $missingCls[$name][] = basename($file) . ':' . $line;
        }
    }
}

echo "PHP " . PHP_VERSION . " — runtime resolution scan\n";
echo str_repeat('-', 70) . "\n";
echo count($files) . " file(s) scanned\n\n";

$bad = 0;

$report = static function (string $title, array $items) use (&$bad) {
    if (!$items) { return; }
    ksort($items);
    echo $title . "\n";
    foreach ($items as $name => $where) {
        $where = array_values(array_unique($where));
        $shown = array_slice($where, 0, 6);
        echo sprintf("  %-28s %d call site(s): %s%s\n",
            $name, count($where), implode(', ', $shown),
            count($where) > 6 ? ', …' : '');
        $bad += count($where);
    }
    echo "\n";
};

$report('UNDEFINED FUNCTIONS — fatal the moment the line executes:', $missingFns);
$report('UNDEFINED CLASSES / INTERFACES:', $missingCls);

/* Constants are reported SEPARATELY and do not set the exit status. Most of
 * this product's constants come from whatever bootstraps it -- config.php, the
 * installer, tests/bootstrap.php -- none of which are in the scanned path, so
 * an unresolved constant here usually means "defined somewhere this scan
 * cannot see" rather than "fatal". Listed for a human to glance at, not as a
 * verdict. */
if ($missingConsts) {
    ksort($missingConsts);
    echo "Unresolved constants — FOR INFORMATION, not counted as failures:
";
    echo "  (normally defined by config.php or the bootstrap, which this scan
";
    echo "   does not load. Check any name you do not recognise.)
";
    foreach ($missingConsts as $name => $where) {
        $where = array_values(array_unique($where));
        echo sprintf("  %-28s %d site(s): %s
", $name, count($where),
                     implode(', ', array_slice($where, 0, 4)));
    }
    echo "
";
}

if ($bad === 0) {
    echo "Nothing unresolved. No fourth category found by this scan.\n";
    echo "(Dynamic calls and method calls are invisible here — see the header.)\n";
    exit(0);
}

echo str_repeat('-', 70) . "\n";
echo "{$bad} unresolved reference(s) on PHP " . PHP_VERSION . ".\n";
exit(1);
