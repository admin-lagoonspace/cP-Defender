<?php
/**
 * Shell scripts must never hand PHP a multi-line `-r` argument.
 *
 * Reported: a routine update printed
 *
 *   Unsuccessful stat on filename containing newline at
 *   /var/cpanel/ea4/ea_php_cli.pm line 87
 *
 * and then rolled the whole thing back.
 *
 * On cPanel, `php` on PATH is not PHP. It is a Perl wrapper that picks an
 * EasyApache interpreter, and when its argument contains a newline it tries to
 * stat that argument as a filename and dies -- before any PHP runs at all. The
 * exit status is non-zero, `set -euo pipefail` turns that into an abort, and
 * the ERR trap restores the previous version. A perfectly good update was
 * discarded over a formatting choice in the script that performed it.
 *
 * The wrapper is perfectly happy with a long single-line `-r`, so the fix is to
 * keep each payload on one line rather than to restructure ten call sites.
 *
 * This test exists because the shipped scripts are the one part of the product
 * that nothing else exercises: they run on the customer's server, as root, and
 * a mistake in them is discovered by the customer.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$scripts = ['install.sh', 'test.sh', 'uninstall.sh', 'update.sh'];

// The interpreter is spelled several ways -- `php`, `/usr/bin/php`, `"$SG_PHP"`,
// `${SG_PHP}` -- so matching on the word "php" alone stopped seeing payloads the
// moment install.sh moved to a resolved binary, and the test reported a clean
// bill of health for code it could not see. Matching on `-r` alone is worse: it
// picks up `cp -r` and `grep -r`. The interpreter token is therefore required.
$PHP_R = '/(?:php[\w.-]*|\$\{?SG_PHP\}?)"?\s+-r\s+/';

foreach ($scripts as $script) {
    $path = $repo . '/' . $script;
    t_ok(is_file($path), $script . ' exists');
    $src = file_get_contents($path);

    // An opening quote with nothing after it starts a multi-line payload.
    $open = preg_match_all(rtrim($PHP_R, '/') . '"[ \t]*\r?\n/', $src);
    t_eq(0, $open, $script . ' has no multi-line -r payload');

    // The same applies to the other way of spelling it.
    t_eq(0, preg_match_all(rtrim($PHP_R, '/') . "'[ \t]*\r?\n/", $src),
        $script . ' has none in single quotes either');
}

// ── Every payload must still be valid PHP ────────────────────────────────────
// Collapsing lines is only safe if nothing was mangled on the way -- in
// particular a `//` comment, which on a single line would swallow everything
// after it. Those were rewritten as /* ... */; this proves none was missed.
$checked = 0;
foreach ($scripts as $script) {
    foreach (file($repo . '/' . $script) as $lineNo => $line) {
        if (!preg_match(rtrim($PHP_R, '/') . '"/', $line, $m, PREG_OFFSET_CAPTURE)) {
            continue;
        }
        $start = $m[0][1] + strlen($m[0][0]);

        // Find the quote that closes the shell string, honouring backslash
        // escapes exactly as the shell does.
        $end = -1;
        for ($i = $start; $i < strlen($line); $i++) {
            if ($line[$i] === '\\') {
                $i++;
                continue;
            }
            if ($line[$i] === '"') {
                $end = $i;
                break;
            }
        }
        t_ok($end > 0, $script . ':' . ($lineNo + 1) . ' -r string is closed');
        if ($end < 0) {
            continue;
        }

        $code = substr($line, $start, $end - $start);
        // Undo the shell's escaping, then neutralise its expansions so the
        // payload can be parsed on its own.
        $code = str_replace(['\\"', '\\$'], ['"', '$'], $code);
        $code = preg_replace('/\$\{\w+\}/', 'SGVAR', $code);

        // A `//` is only safe here inside a string literal or a block comment
        // (php://input occurs in both) -- never introducing a line comment,
        // which on a collapsed payload would swallow everything after it.
        $stripped = preg_replace('#/\*.*?\*/#', '', $code);
        $stripped = preg_replace('/\'[^\']*\'|"[^"]*"/', "''", $stripped);
        t_ok(strpos($stripped, '//') === false,
            $script . ':' . ($lineNo + 1) . ' has no line comment in a one-line payload');

        $tmp = sys_get_temp_dir() . '/sg_shell_php_' . getmypid() . '.php';
        file_put_contents($tmp, '<?php ' . $code . "\n");
        exec(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($tmp) . ' 2>&1', $out, $rc);
        @unlink($tmp);
        t_eq(0, $rc, $script . ':' . ($lineNo + 1) . ' -r payload parses');
        $checked++;
    }
}

t_ok($checked >= 10, 'every -r payload was parsed (' . $checked . ')');
