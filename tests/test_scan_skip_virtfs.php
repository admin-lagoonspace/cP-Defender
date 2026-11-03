<?php
/**
 * A /home scan must not walk the bind-mounted copies.
 *
 * cPanel jailshell bind-mounts a copy of the filesystem under /home/virtfs
 * for EVERY account. Walking /home therefore scans every customer's files
 * once per account -- on the server this was found on, 118 times over.
 *
 * Scanner had two walks and two different ideas of what to skip.
 * getPhpFiles() pruned virtfs; walkFiles() did not, and walkFiles() is the
 * one that feeds ClamAV. The result, straight out of the live database:
 *
 *     account  job    status   n
 *     virtfs   12439  deleted  1
 *
 * The one finding on that server had the path /home/virtfs/..., so it was
 * attributed to an "account" called virtfs, which does not exist. It showed
 * on no customer's page, and no customer could act on it. The same scans
 * reported 104-121 threats and ran for nine to seventeen hours.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// ── A real tree, walked by the real methods ────────────────────────────────
$root = sys_get_temp_dir() . '/sg-skip-' . getmypid();
foreach ([
    $root . '/alice/public_html',
    $root . '/virtfs/alice/home/alice/public_html',   // the bind-mounted copy
    $root . '/bob/public_html/node_modules/pkg',
    $root . '/carol/.cagefs/tmp',
] as $d) { @mkdir($d, 0777, true); }

file_put_contents($root . '/alice/public_html/real.php', '<?php echo 1;');
file_put_contents($root . '/virtfs/alice/home/alice/public_html/real.php', '<?php echo 1;');
file_put_contents($root . '/bob/public_html/node_modules/pkg/x.php', '<?php echo 2;');
file_put_contents($root . '/carol/.cagefs/tmp/y.php', '<?php echo 3;');

$sc  = new Scanner();
$ref = new ReflectionClass(Scanner::class);

// BOTH walks. Testing one proves nothing about the other, which is exactly
// how this survived: the pruned walk was the one nobody fed ClamAV from.
foreach (['walkFiles', 'getPhpFiles'] as $fn) {
    $m = $ref->getMethod($fn);
    $m->setAccessible(true);

    $seen = [];
    foreach ($m->invoke($sc, $root) as $f) {
        $seen[] = str_replace(DIRECTORY_SEPARATOR, chr(47), $f);
    }

    $under = static function (string $needle) use ($seen): int {
        return count(array_filter($seen, static function ($p) use ($needle) {
            return strpos($p, $needle) !== false;
        }));
    };

    t_eq(0, $under('/virtfs/'),
         'THE MULTIPLICATIVE WALK: ' . $fn . '() does not descend into '
       . 'virtfs. One bind mount per account turns a /home scan into 118 '
       . 'scans, and files a finding under an account that does not exist');
    t_eq(0, $under('/node_modules/'),
         $fn . '() still skips node_modules');
    t_eq(0, $under('/.cagefs/'),
         $fn . '() skips the CageFS tree for the same reason');

    // The point is to skip the COPY, not the file. A prune that also hid the
    // real thing would be a far worse bug than the one being fixed.
    t_eq(1, $under('/alice/public_html/real.php'),
         'and the real file is still scanned exactly once');
}

@array_map('unlink', (array) glob($root . '/*/*/*.php'));

// ── One list, so the two walks cannot drift again ──────────────────────────
$src = t_code($repo . '/backend/lib/Scanner.php');
t_contains($src, "'virtfs', '.snapshot', '.zfs', '.trash', '.cagefs',",
     'the names live in SCAN_SKIP_DIRS');
t_contains($src, 'implode(\'|\', array_map(',
     'THE TWO IDEAS: the regex walk builds its pattern FROM that list rather '
   . 'than keeping a second copy — the two disagreeing is the whole bug');
t_ok(!preg_match("#\\\$prune = '\#\(\?:\^\|/\)\(\?:virtfs#", $src),
     'and the hand-written duplicate of the list is gone');
