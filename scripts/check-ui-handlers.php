<?php
/**
 * Every onclick/onchange in the UI must resolve to a function that exists.
 *
 * A button wired to a function that was renamed or never written does nothing at
 * all when clicked: no error the user can see, no network request, nothing. The
 * page looks finished and is not, which is exactly how "the refresh button does
 * not work for any of these modules" happens.
 *
 * php -l cannot see it, the API smoke test cannot see it, and neither can any
 * test that does not open a browser. A name check can.
 *
 * Usage:  php scripts/check-ui-handlers.php
 * Exit 0 = every handler resolves.
 */

$repo = dirname(__DIR__);
$html = (string) file_get_contents($repo . '/frontend/index.html');

$js = '';
foreach (glob($repo . '/frontend/js/*.js') as $f) {
    $js .= "\n" . file_get_contents($f);
}
// Handlers may also be defined in the inline bootstrap block.
$js .= "\n" . $html;

/** Names defined anywhere as a callable. */
$defined = [];
foreach ([
    '/\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/',            // function foo()
    '/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(/',  // const foo = (
    '/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function/',
    '/\b([A-Za-z_$][\w$]*)\s*:\s*(?:async\s*)?\(/',      // object literal methods
    '/\b([A-Za-z_$][\w$]*)\s*:\s*(?:async\s*)?function/',
] as $re) {
    if (preg_match_all($re, $js, $m)) {
        foreach ($m[1] as $name) { $defined[$name] = true; }
    }
}

// Browser and library globals a handler may legitimately call.
$builtins = array_flip([
    'alert', 'confirm', 'console', 'window', 'document', 'location', 'history',
    'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval', 'fetch',
    'JSON', 'Object', 'Array', 'String', 'Number', 'Boolean', 'Math', 'Date',
    'parseInt', 'parseFloat', 'encodeURIComponent', 'decodeURIComponent',
    'event', 'this', 'return', 'if', 'else', 'true', 'false', 'null', 'void',
    'API', 'Auth', 'Demo', 'State',
]);

$problems = [];
$checked  = 0;

// on*="name(...)" — take the first call in each handler.
if (preg_match_all('/\bon(?:click|change|input|submit|keyup|keydown)\s*=\s*"([^"]*)"/i',
                   $html, $m, PREG_OFFSET_CAPTURE)) {
    foreach ($m[1] as $idx => $hit) {
        $body = $hit[0];
        $line = substr_count(substr($html, 0, $m[0][$idx][1]), "\n") + 1;

        // (?<![\w.$]) so document.getElementById() is not read as a call to a
        // bare getElementById -- a method on an object is not a global handler.
        if (preg_match_all('/(?<![\w.$])([A-Za-z_$][\w$]*)\s*\(/', $body, $calls)) {
            foreach ($calls[1] as $fn) {
                if (isset($builtins[$fn])) { continue; }
                $checked++;
                if (!isset($defined[$fn])) {
                    $problems[] = sprintf('index.html:%d  %s() is not defined anywhere', $line, $fn);
                }
            }
        }
    }
}

$problems = array_values(array_unique($problems));
sort($problems);

echo "Checked {$checked} handler call(s).\n";
if ($problems) {
    echo implode("\n", $problems), "\n\n";
    echo count($problems), " handler(s) point at nothing.\n";
    exit(1);
}
echo "Every UI handler resolves to a defined function.\n";
exit(0);
