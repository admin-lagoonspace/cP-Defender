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
/**
 * A PHP file's code with its comments removed, so an assertion cannot be
 * satisfied by a mention in a comment.
 *
 * PHP ONLY. It is built on token_get_all(), and handing it a shell script does
 * something quietly wrong rather than failing: install.sh writes PHP heredocs,
 * so the tokeniser enters PHP mode at the first `<?php` and from there strips
 * every `#` shell comment and anything else that looks like PHP syntax. Four
 * tests were asserting on shell scripts through this function, and the
 * assertions were being evaluated against mangled text.
 *
 * Use t_shell() for .sh files.
 */
function t_code(string $path): string
{
    if (!preg_match('/\.(?:php|phtml|inc)$/i', $path)) {
        throw new InvalidArgumentException(
            't_code() is for PHP files; ' . basename($path)
            . ' is not one. Use t_shell() for shell scripts.');
    }
    $out = '';
    foreach (token_get_all(file_get_contents($path)) as $tok) {
        if (is_array($tok) && in_array($tok[0], [T_COMMENT, T_DOC_COMMENT], true)) {
            continue;
        }
        $out .= is_array($tok) ? $tok[1] : $tok;
    }
    return $out;
}

/**
 * A shell script's code with its comments removed.
 *
 * Line comments only, and a `#` inside a quoted string is left alone — a
 * naive strip would delete half of `grep -oP '^\s*AUTO_UPDATES...'`. Good
 * enough to stop an assertion passing on a commented-out line, which is all
 * this is for. Shebangs are kept.
 */
function t_shell(string $path): string
{
    $out = [];
    foreach (explode("\n", (string)file_get_contents($path)) as $i => $line) {
        if ($i === 0 && str_starts_with($line, '#!')) { $out[] = $line; continue; }

        $sq = false; $dq = false; $cut = null;
        $len = strlen($line);
        for ($j = 0; $j < $len; $j++) {
            $c = $line[$j];
            if ($c === '\\' && $dq) { $j++; continue; }
            if ($c === "'" && !$dq)   { $sq = !$sq; continue; }
            if ($c === '"' && !$sq)   { $dq = !$dq; continue; }
            if ($c === '#' && !$sq && !$dq) {
                // A comment only at the start of a word, so `${x#y}` and
                // `file#1` survive.
                if ($j === 0 || $line[$j - 1] === ' ' || $line[$j - 1] === "\t") {
                    $cut = $j; break;
                }
            }
        }
        $out[] = $cut === null ? $line : rtrim(substr($line, 0, $cut));
    }
    return implode("\n", $out);
}
