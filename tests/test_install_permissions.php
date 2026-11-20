<?php
/**
 * The permissions step must be BOUNDED and must SAY WHAT IT IS DOING.
 *
 * Reported: "installer stuck on fixing permissions".
 *
 * That section was four bare recursive calls, the last of them over a path
 * read out of the database, with nothing printed between the section header
 * "Fixing permissions" and "Permissions applied". Two separate defects, and
 * the report is the signature of both at once:
 *
 *   1. UNBOUNDED. `chmod -R` walks through mount points. quarantine_dir is
 *      routinely a mount to the big volume, and moveQuarantine() accepted
 *      ANY absolute writable path -- including /home, which passed every
 *      check it had. `chmod -R 700 /home` on a cPanel server walks
 *      /home/virtfs, which bind-mounts the whole filesystem once per
 *      account, so the walk is multiplied by the account count and re-enters
 *      /usr and /etc through the mounts. It does not finish, and what it
 *      completes on the way has set 700 on customer public_html directories.
 *      Scanner, Heuristics, the path walker and the CDN setup all prune
 *      virtfs for exactly this reason. The installer did not.
 *
 *   2. SILENT. A stalled installer printed no path, so the one fact needed
 *      to diagnose it was the one fact not on the screen.
 *
 * The fix is `find -xdev` (cannot cross a filesystem boundary), a timeout
 * (a wedged filesystem fails the step, not the update), a line per path, and
 * a refusal to walk a path that is not a quarantine directory at all.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$up  = file_get_contents($repo . '/update.sh');
$ins = file_get_contents($repo . '/install.sh');
$sc  = t_code($repo . '/backend/lib/Scanner.php');

// ── No unbounded recursive chmod survives in either script ────────────────
//
// The whole defect in one grep. -R is what crosses the mount.
//
// Checked against the CODE, not the file: both scripts now carry comments
// explaining what `chmod -R` did here and why it is gone, and a test that
// cannot tell a comment from a command would force those comments to be
// deleted to stay green. The explanation is the most valuable part.
$code = function (string $src): string {
    $out = [];
    foreach (explode("\n", $src) as $line) {
        if (preg_match('/^\s*#/', $line)) { continue; }
        $out[] = $line;
    }
    return implode("\n", $out);
};
foreach ([['update.sh', $up], ['install.sh', $ins]] as [$name, $src]) {
    t_ok(strpos($code($src), 'chmod -R') === false,
         "NO RECURSIVE CHMOD LEFT IN {$name}: `chmod -R` follows a bind mount "
       . 'into another volume, which is how a hardening step became an '
       . 'unbounded walk of every account on the server');
}
// Guard the guard: the comments that explain the bug must still be there.
t_contains($up, '/home/virtfs holds a bind-mounted copy of the filesystem',
     'and the reason is recorded in update.sh, where the next person to touch '
   . 'this section will read it');

// ── Every walk stops at the filesystem boundary ───────────────────────────
foreach ([['update.sh', $up], ['install.sh', $ins]] as [$name, $src]) {
    preg_match('/_sg_chmod_tree\(\) \{.*?\n\}/s', $src, $m);
    $fn = $m[0] ?? '';
    t_ok($fn !== '', "{$name} defines _sg_chmod_tree()");
    t_contains($fn, 'find "$dir" -xdev -exec chmod "$mode" {} +',
         "-XDEV IN {$name}: the walk cannot leave the filesystem it started "
       . 'on, so a quarantine mount point is tightened without reaching '
       . 'through to whatever is mounted there');
    t_contains($fn, 'timeout 300',
         "{$name} bounds the walk in time, so a slow or wedged filesystem "
       . 'fails this one hardening step instead of hanging the update');
    t_contains($fn, 'command -v timeout >/dev/null 2>&1',
         'and still works where timeout is absent, rather than skipping the '
       . 'chmod entirely');
}

// The timeout must be reported, not swallowed: a silently-skipped hardening
// step is how you end up with world-readable quarantine and no record of it.
preg_match('/_sg_chmod_tree\(\) \{.*?\n\}/s', $up, $m);
$upFn = $m[0] ?? '';
t_contains($upFn, 'rc -eq 124',
     'the timeout exit code is detected specifically');
t_contains($upFn, 'Timed out after 300s tightening ${dir}',
     'A TIMEOUT IS REPORTED, NOT SWALLOWED: it names the path and tells the '
   . 'operator the update itself is fine, so a cut-short hardening step is '
   . 'not mistaken for a failed upgrade');
t_contains($upFn, 'find ${dir} -xdev -exec chmod ${mode} {} +',
     'and hands over the exact command to finish it by hand');

// ── Each path is named BEFORE it is walked ────────────────────────────────
//
// This is the entire difference between the bug report we got and a bug
// report we could have acted on.
t_contains($upFn, 'info "${label}: chmod ${mode} ${dir}"',
     'THE PATH IS PRINTED BEFORE THE WALK: "installer stuck on fixing '
   . 'permissions" was the whole report, because the section printed nothing '
   . 'between its header and its success line');
t_contains($up, 'info "Reading configured quarantine location"',
     'including the database read, which runs migrations on connect and so '
   . 'can itself be the slow step');

// ── The database read is bounded too ──────────────────────────────────────
t_contains($up, 'timeout 60 php -r "define(\'SG_API\', true);',
     'THE DB READ CANNOT HANG EITHER: Database::get() runs migrations on '
   . 'connect and six processes share that SQLite file, so a locked or '
   . 'mid-migration database used to stall here with nothing on screen');
// The payload stays written out at the call site rather than hidden in a
// variable: tests/test_shell_php.php extracts every `php -r "..."` in these
// scripts and runs php -l over it, and a variable is invisible to that check.
t_eq(2, substr_count($up, "echo Database::setting('quarantine_dir', '');"),
     'and it is INLINE in both the timeout and no-timeout branches, so '
   . 'test_shell_php.php can still parse-check the payload');

// ── update.sh refuses to walk a path that is not a quarantine directory ───
preg_match('/_sg_quarantine_path_ok\(\) \{.*?\n\}/s', $up, $m2);
$guard = $m2[0] ?? '';
t_ok($guard !== '', 'update.sh defines _sg_quarantine_path_ok()');
t_contains($guard, '[[ "$d" == */*/* ]] || return 1',
     'DEPTH 1 IS REFUSED: /home, /usr and /var are volumes, not quarantine '
   . 'directories — and /home is the value that caused this');
t_contains($guard, '/home/virtfs|/home/virtfs/*) return 1',
     'and the per-account bind-mount tree is refused by name');
t_contains($guard, '/proc/*|/sys/*|/dev/*)',
     'as is anything that is not real storage');

t_contains($up, 'warn "REFUSING to tighten permissions on quarantine_dir=',
     'A REFUSAL IS LOUD: the operator is told the value is wrong and that '
   . 'nothing was changed, rather than the step quietly doing nothing');
t_contains($up, 'serverscrub move-quarantine /var/serverscrub/quarantine',
     'and told how to fix it');

// An unsafe value and a non-existent one are different problems with
// different fixes, so they are not collapsed into one message.
t_contains($up, 'is configured but does not exist — skipping',
     'a configured-but-missing quarantine is reported as its own case');

// ── The setting cannot hold a volume in the first place ───────────────────
//
// update.sh refusing is defence in depth; a server that already holds a bad
// value got it from the version before this one. The real fix is at the only
// place that writes the setting.
preg_match('/public static function moveQuarantine.*?\n    \}/s', $sc, $m3);
$mq = $m3[0] ?? '';
t_ok($mq !== '', 'moveQuarantine() is still there');
t_contains($mq, '$depth = count(array_filter(explode(\'/\', str_replace(\'\\\\\', \'/\', $dest)), \'strlen\'));',
     'moveQuarantine measures the path depth');
t_contains($mq, 'if ($depth < 2) {',
     'AND REFUSES A WHOLE VOLUME: /home was absolute, existing and writable, '
   . 'so it passed every check this function had — and quarantine_dir=/home '
   . 'is what turned the hardening step into a walk of the entire server');
t_contains($mq, 'is a whole volume, not a quarantine ',
     'with an error that says what is wrong');
t_contains($mq, "rtrim(\$dest, '/') . '/.serverscrub/quarantine'",
     'and suggests a usable path built from what was typed, rather than '
   . 'rejecting it and leaving the admin to guess');
t_contains($mq, "preg_match('#^/home/virtfs(/|\$)#', \$dest)",
     'and /home/virtfs is refused by name — it is bind mounts, not storage');

// The guard has to run BEFORE anything is created or moved, or refusing is
// academic: mkdir would already have happened.
$posDepth = strpos($mq, '$depth < 2');
$posMkdir = strpos($mq, '@mkdir($dest, 0700, true)');
t_ok($posDepth !== false && $posMkdir !== false && $posDepth < $posMkdir,
     'THE CHECK RUNS BEFORE THE MKDIR: validating after creating the target '
   . 'would leave a directory behind on every rejected path');
