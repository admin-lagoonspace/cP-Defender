<?php
/**
 * Minimal assertions. DEVELOPMENT ONLY — never packaged.
 *
 * Output is line-oriented ("PASS x" / "FAIL x") so tests/run.php can run each
 * file in its own process and still report per-assertion results.
 */

function t_ok(bool $cond, string $what): void
{
    echo ($cond ? 'PASS ' : 'FAIL ') . $what . "\n";
}

function t_eq($expected, $actual, string $what): void
{
    $pass = $expected === $actual;
    if ($pass) {
        echo "PASS {$what}\n";
        return;
    }
    echo "FAIL {$what} — expected " . t_show($expected) . ", got " . t_show($actual) . "\n";
}

function t_contains(string $haystack, string $needle, string $what): void
{
    $pass = strpos($haystack, $needle) !== false;
    echo ($pass ? 'PASS ' : 'FAIL ') . $what
        . ($pass ? '' : " — " . t_show($needle) . " not found in " . t_show(substr($haystack, 0, 120)))
        . "\n";
}

/** Assert that running $fn does not raise a PHP Error/Exception. */
function t_no_throw(callable $fn, string $what): void
{
    try {
        $fn();
        echo "PASS {$what}\n";
    } catch (Throwable $e) {
        echo "FAIL {$what} — " . get_class($e) . ': ' . $e->getMessage()
            . ' in ' . basename($e->getFile()) . ':' . $e->getLine() . "\n";
    }
}

function t_show($v): string
{
    if (is_bool($v))  { return $v ? 'true' : 'false'; }
    if (is_null($v))  { return 'null'; }
    if (is_array($v)) { return 'array(' . count($v) . ')'; }
    if (is_string($v)) { return "'" . $v . "'"; }
    return (string)$v;
}

/**
 * A PHP file's CODE, with comments and docblocks removed.
 *
 * Grepping raw source for "Logger::write(" matched the comment explaining why
 * that call was removed, so three tests failed against correct code. Assertions
 * about what the code does must not read prose about what it used to do.
 */
function t_code(string $path): string
{
    $out = '';
    foreach (token_get_all(file_get_contents($path)) as $tok) {
        if (is_array($tok) && in_array($tok[0], [T_COMMENT, T_DOC_COMMENT], true)) {
            continue;
        }
        $out .= is_array($tok) ? $tok[1] : $tok;
    }
    return $out;
}
