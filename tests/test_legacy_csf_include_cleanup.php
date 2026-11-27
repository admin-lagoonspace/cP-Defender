<?php
/**
 * Every CSF reload on a migrated server printed an error for a file that
 * ServerScrub itself had deleted.
 *
 * Before the rename, Sentinel Gate added two lines to CSF's config:
 *
 *     /etc/csf/csf.allow   Include /etc/sentinel-gate/csf_allow.txt
 *     /etc/csf/csf.ignore  Include /etc/sentinel-gate/csf_ignore.txt
 *
 * install.sh's legacy WAF cleanup removes /etc/sentinel-gate, and it never
 * looked in /etc/csf. So from then on every `csf -r` and `csf -ra` said
 *
 *     *Error* File does not exist: [/etc/sentinel-gate/csf_allow.txt]
 *     at /usr/sbin/csf line 2448.
 *
 * On prod (2026-11-23) the lines sat at csf.allow:72 and csf.ignore:30 with
 * the directory long gone. The firewall still loaded, so the cost was not an
 * outage. It was an operator trained to scroll past a CSF *Error*, which is
 * how a real one gets missed.
 *
 * What this test pins, in order of how easy it is to get wrong:
 *
 *  1. WHERE the cleanup runs. Inside `if [[ -d /etc/sentinel-gate ]]` it never
 *     runs again on any server that has the fault, because that block is what
 *     deleted the directory. Inside a `! $REGISTER_ONLY` block it never runs on
 *     an upgrade, because update.sh reaches install.sh only through
 *     --register-only. Either placement passes a fresh-install test and fixes
 *     nothing on prod.
 *
 *  2. WHAT it removes. csf.allow is the operator's file. Only a real `Include`
 *     of a path under /etc/sentinel-gate/ goes. A comment, a commented-out
 *     include, our own /etc/serverscrub include and every IP entry stay
 *     byte-for-byte, in order. A file with nothing to remove is not rewritten.
 *
 *  3. That it is actually run here, not just grepped for. The function is
 *     lifted out of install.sh and executed by bash against fixtures, under
 *     `set -euo pipefail`, which install.sh does not use but a careless edit
 *     could make it need.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

const FN_NAME = '_ss_strip_legacy_csf_includes';

$sh    = t_shell($repo . '/install.sh');
$unsh  = t_shell($repo . '/uninstall.sh');

/** The function's source, from its definition to the closing brace. */
function t_sh_fn(string $src, string $name): string
{
    $start = strpos($src, $name . '() {');
    if ($start === false) { return ''; }
    $end = strpos($src, "\n}\n", $start);
    return $end === false ? '' : substr($src, $start, $end + 3 - $start);
}

// ── A1: install.sh has it, and it runs on the path prod takes ──────────────

$fnInstall = t_sh_fn($sh, FN_NAME);
t_ok($fnInstall !== '', 'install.sh defines the legacy CSF include cleanup');

$callAllow  = strpos($sh, FN_NAME . ' /etc/csf/csf.allow');
$callIgnore = strpos($sh, FN_NAME . ' /etc/csf/csf.ignore');
t_ok($callAllow !== false && $callIgnore !== false,
     'and calls it on both csf.allow and csf.ignore, the two files prod had '
   . 'the stale lines in');

$legacyIf = strpos($sh, 'if [[ -d "${LEGACY_WAF_DIR}" ]]; then');
$prefl    = strpos($sh, 'section "Pre-flight checks"');
$migEnd   = strpos($sh, 'ok "  Migration complete — continuing as ServerScrub"');
t_ok($legacyIf !== false && $prefl !== false && $migEnd !== false,
     'the legacy-dir block, the migration block and pre-flight are all findable');
t_ok($callAllow > $prefl && $callAllow > $legacyIf && $callAllow > $migEnd,
     'the cleanup sits after BOTH legacy blocks have closed. Inside the '
   . '/etc/sentinel-gate block it would never run again on a migrated server, '
   . 'because that block is what deleted the directory -- so it would fix '
   . 'nothing on any server that has the fault');

$raw = (string)file_get_contents($repo . '/install.sh');
$rawCall = strpos($raw, FN_NAME . ' /etc/csf/csf.allow');
$installOnlyEnd = strpos($raw, 'fi  # ═══ end INSTALL-ONLY SECTIONS');
t_ok($installOnlyEnd !== false && $rawCall > $installOnlyEnd,
     'and after the INSTALL-ONLY span closes, so --register-only reaches it. '
   . 'update.sh runs install.sh only with --register-only, so anywhere else '
   . 'this never reaches an upgraded server');

// Every top-level `if ... REGISTER_ONLY ...` block, walked to its matching
// top-level `fi`. A call inside any of them is skipped on one install path.
$lines   = explode("\n", $sh);
$callLn  = substr_count(substr($sh, 0, (int)$callAllow), "\n");
$inside  = [];
foreach ($lines as $i => $l) {
    if (!preg_match('/^if .*REGISTER_ONLY/', $l)) { continue; }
    $depth = 0;
    for ($j = $i; $j < count($lines); $j++) {
        $lj = $lines[$j];
        // `if (` at column 0 is PHP inside a heredoc, not shell.
        if (preg_match('/^if (?!\()/', $lj) &&!preg_match('/;\s*fi\b/', $lj)) { $depth++; }
        if (preg_match('/^fi\b/', $lj)) { $depth--; }
        if ($depth === 0) { break; }
    }
    if ($callLn > $i && $callLn < $j) { $inside[] = ($i + 1) . '-' . ($j + 1); }
}
t_eq([], $inside,
     'the call is inside no REGISTER_ONLY-gated block at all. A block listed here '
   . 'means fresh installs or upgrades skip the cleanup');

$csfSection = strpos($sh, 'section "CSF / LFD firewall integration"');
$csfGate    = strpos($sh, 'if [[ -f /usr/sbin/csf ]]; then', (int)$csfSection);
$csfReload  = strpos($sh, 'if csf -r >/dev/null 2>&1; then', (int)$csfSection);
t_ok($csfSection !== false && $callAllow > $csfSection && $callIgnore < $csfGate,
     'it runs BEFORE the /usr/sbin/csf check, not inside it: a server with CSF '
   . 'removed and /etc/csf left behind still gets clean files');
t_ok($csfReload !== false && $callIgnore < $csfReload,
     'and before the existing csf -r, so that one reload applies the change on '
   . 'a server that has CSF');
t_ok(!preg_match('/\bcsf\s+-/', $fnInstall),
     'the cleanup itself runs no csf command -- no reload, no -a/-d/-x. The '
   . 'existing reload is the only one, so a run never reloads CSF twice');
t_ok(strpos($sh, 'SKIP_CSF') === false
     || strpos(substr($sh, (int)$csfSection, (int)$callIgnore - (int)$csfSection), 'SKIP_CSF') === false,
     'and it is not gated on --no-csf, which governs installing CSF, not '
   . 'cleaning up after ourselves');

$noWalk = !preg_match('/\b(find|ls)\b|\*/', preg_replace("/'[^']*'/", '', $fnInstall));
t_ok($noWalk,
     'it reads exactly the file it is given: no find, no glob, no directory '
   . 'walk under /etc/csf');

// ── A2: uninstall.sh does the same, before its reload ──────────────────────

$fnUninstall = t_sh_fn($unsh, FN_NAME);
t_ok($fnUninstall !== '', 'uninstall.sh also removes the legacy includes');
t_eq($fnInstall, $fnUninstall,
     'with the SAME function, byte for byte. A looser copy in uninstall.sh '
   . '(a substring delete, like its existing serverscrub sed) would take an '
   . 'operator comment that mentions sentinel-gate with it');
t_eq(t_sh_fn((string)file_get_contents($repo . '/install.sh'), FN_NAME),
     t_sh_fn((string)file_get_contents($repo . '/uninstall.sh'), FN_NAME),
     'comments included, so the explanation cannot drift from the code in one copy');

$uCallA  = strpos($unsh, FN_NAME . ' /etc/csf/csf.allow');
$uCallI  = strpos($unsh, FN_NAME . ' /etc/csf/csf.ignore');
$uReload = strpos($unsh, 'csf -r >/dev/null 2>&1 || systemctl restart lfd');
t_ok($uCallA !== false && $uCallI !== false && $uReload !== false,
     'uninstall.sh calls it on both files and still has its reload');
t_ok($uCallA < $uReload && $uCallI < $uReload,
     'and calls it before that reload, so CSF is left clean on its way out '
   . 'rather than at the next reload somebody else triggers');

// ── A3: run the real function against fixtures ─────────────────────────────

function t_find_bash(): string
{
    $cands = ['/bin/bash', '/usr/bin/bash',
              'C:/Program Files/Git/bin/bash.exe',
              'C:/Program Files (x86)/Git/bin/bash.exe'];
    foreach ($cands as $c) {
        if (!is_file($c)) { continue; }
        // Runs, not merely exists -- see docker/compose.yml on python.exe.
        $out = []; $rc = 1;
        @exec(escapeshellarg($c) . ' -c "echo ok" 2>&1', $out, $rc);
        if ($rc === 0 && trim(implode('', $out)) === 'ok') { return $c; }
    }
    return '';
}

$bash = t_find_bash();
t_ok($bash !== '',
     'a bash that runs was found. Without one the behavioural half of this test '
   . 'did not run, and that is a failure, not a pass');

if ($bash !== '') {
    $dir = sys_get_temp_dir() . '/sg-csfinc-' . getmypid() . '-' . mt_rand(1000, 9999);
    @mkdir($dir, 0700, true);
    $bdir = str_replace('\\', '/', $dir);

    // csf.allow: LF, no final newline, the stale include mid-file.
    $allowKeep = [
        "# Allowed IPs -- one per line, or an advanced rule\n",
        "192.0.2.10 # office\n",
        "\n",
        "# migrated from sentinel-gate\n",
        "tcp|in|d=22|s=198.51.100.7\n",
        "# Include /etc/sentinel-gate/csf_allow.txt\n",
        "Includes /etc/sentinel-gate/not-a-directive.txt\n",
        "Include /etc/serverscrub/csf_allow.txt\n",
        "203.0.113.0/24",
    ];
    $allowStale = "Include /etc/sentinel-gate/csf_allow.txt\n";
    $allowIn  = implode('', array_slice($allowKeep, 0, 4)) . $allowStale
              . implode('', array_slice($allowKeep, 4));
    $allowOut = implode('', $allowKeep);

    // csf.ignore: CRLF throughout, leading whitespace, trailing whitespace,
    // a lowercase `include` (left alone -- AQ1), and a different file under
    // the old directory (removed -- AQ3).
    $ignoreIn = "# IPs lfd will ignore\r\n"
              . " \tInclude /etc/sentinel-gate/csf_ignore.txt\r\n"
              . "192.0.2.20\r\n"
              . "include /etc/sentinel-gate/lowercase.txt\r\n"
              . "\r\n"
              . "Include\t /etc/sentinel-gate/other.txt   \r\n"
              . "Include /etc/serverscrub/csf_ignore.txt\r\n";
    $ignoreOut = "# IPs lfd will ignore\r\n"
               . "192.0.2.20\r\n"
               . "include /etc/sentinel-gate/lowercase.txt\r\n"
               . "\r\n"
               . "Include /etc/serverscrub/csf_ignore.txt\r\n";

    $clean = "# nothing of ours here\n192.0.2.30\n# migrated from sentinel-gate\n";

    file_put_contents("$dir/csf.allow", $allowIn);
    file_put_contents("$dir/csf.ignore", $ignoreIn);
    file_put_contents("$dir/clean.allow", $clean);
    @chmod("$dir/csf.allow", 0640);
    $old = time() - 86400;
    foreach (['csf.allow', 'csf.ignore', 'clean.allow'] as $f) { touch("$dir/$f", $old); }

    $script = "set -euo pipefail\n"
            . "ok()   { echo \"OK: \$*\"; }\n"
            . "info() { echo \"INFO: \$*\"; }\n"
            . "warn() { echo \"WARN: \$*\"; }\n"
            . $fnInstall
            . FN_NAME . " '$bdir/csf.allow'\n"
            . FN_NAME . " '$bdir/csf.ignore'\n"
            . FN_NAME . " '$bdir/clean.allow'\n"
            . FN_NAME . " '$bdir/absent.allow'\n"
            . "echo DONE\n";
    file_put_contents("$dir/run.sh", $script);

    $run = function () use ($bash, $bdir): array {
        $out = []; $rc = 1;
        exec(escapeshellarg($bash) . ' ' . escapeshellarg("$bdir/run.sh") . ' 2>&1', $out, $rc);
        return [$rc, $out];
    };

    [$rc, $out] = $run();
    clearstatcache();
    $text = implode("\n", $out);

    t_eq(0, $rc, 'the cleanup runs to completion under set -euo pipefail'
               . ($rc === 0 ? '' : ' (output: ' . str_replace("\n", ' | ', substr($text, 0, 300)) . ')'));
    t_contains($text, 'DONE', 'and returns to its caller on every file, including a missing one');

    t_eq($allowOut, (string)@file_get_contents("$dir/csf.allow"),
         'csf.allow loses exactly the stale include. The serverscrub include, '
       . 'the commented-out sentinel-gate include, the "migrated from '
       . 'sentinel-gate" comment, IPs, the blank line and the missing final '
       . 'newline are all byte-identical and in order');
    t_eq($ignoreOut, (string)@file_get_contents("$dir/csf.ignore"),
         'csf.ignore loses the indented CRLF include and the one with trailing '
       . 'whitespace; CRLF endings, the lowercase include and our own include '
       . 'are untouched');
    t_eq($clean, (string)@file_get_contents("$dir/clean.allow"),
         'a file with nothing to remove keeps its content');
    t_eq($old, filemtime("$dir/clean.allow"),
         'and is not rewritten at all: its mtime is unchanged');
    t_ok(!file_exists("$dir/absent.allow"),
         'a file that does not exist is skipped, not created');
    t_eq([], glob("$dir/*.ss-*") ?: [],
         'no temp file is left beside the originals');

    if (PHP_OS_FAMILY !== 'Windows') {
        t_eq('640', substr(sprintf('%o', fileperms("$dir/csf.allow")), -3),
             'the rewritten csf.allow keeps its mode');
    }

    $removed = array_values(array_filter($out, function ($l) {
        return strpos($l, 'OK:') === 0 && strpos($l, 'Removed stale Sentinel Gate include') !== false;
    }));
    t_eq(3, count($removed),
         'each removed line is reported once, and nothing else is reported as removed');
    t_contains($text, "from $bdir/csf.allow: Include /etc/sentinel-gate/csf_allow.txt",
               'the report names the file and the exact line taken out of it');
    t_ok(strpos($text, "\r") === false,
         'the CRLF line is reported without its carriage return');
    t_ok(strpos($text, 'WARN:') === false, 'and a writable file produces no warning');

    // ── R8: a second run is a no-op ─────────────────────────────────────────
    foreach (['csf.allow', 'csf.ignore'] as $f) { touch("$dir/$f", $old); }
    $before = [md5_file("$dir/csf.allow"), md5_file("$dir/csf.ignore")];
    [$rc2, $out2] = $run();
    clearstatcache();
    $text2 = implode("\n", $out2);
    t_eq(0, $rc2, 'the second run also completes');
    t_ok(strpos($text2, 'Removed') === false && strpos($text2, 'WARN:') === false,
         'a second run reports nothing: there is nothing left to remove');
    t_eq($before, [md5_file("$dir/csf.allow"), md5_file("$dir/csf.ignore")],
         'and changes no byte of either file');
    t_eq([$old, $old], [filemtime("$dir/csf.allow"), filemtime("$dir/csf.ignore")],
         'nor rewrites them: both mtimes are unchanged, so every upgrade after '
       . 'the first leaves CSF\'s files alone');

    // ── Links, and bytes grep calls binary (Shakaal, 2026-11-25) ────────────
    //
    // `mv tmp csf.allow` replaced a symlink with a plain copy and left the
    // stale line in the file it pointed to; with a hard link the other name
    // kept the stale line. Config-managed servers link these files. A first
    // fix wrote hard-linked files in place, which truncates before it writes:
    // a failed or killed write left csf.allow EMPTY (Shakaal R1). A
    // hard-linked file is now left alone and reported instead. And a NUL
    // byte made grep report "Binary file ... matches" as the removed line --
    // on the warn path, as the line the operator should delete by hand.
    $stale = "Include /etc/sentinel-gate/csf_allow.txt\n";
    file_put_contents("$dir/target.allow", "192.0.2.40\n" . $stale . "keep\n");
    $hIn = "192.0.2.41\n" . $stale . "keep\n";
    file_put_contents("$dir/h1.allow", $hIn);
    touch("$dir/h1.allow", $old);
    file_put_contents("$dir/nul.allow", "a\0b\nInclude /etc/sentinel-gate/a\nkeep\n");

    $links = "set -euo pipefail\n"
           . "ok()   { echo \"OK: \$*\"; }\n"
           . "info() { echo \"INFO: \$*\"; }\n"
           . "warn() { echo \"WARN: \$*\"; }\n"
           . $fnInstall
           . "cd '$bdir'\n"
           . "ln -s target.allow link.allow 2>/dev/null || true\n"
           . "if [[ -L link.allow ]]; then echo SYMLINK=yes; " . FN_NAME . " '$bdir/link.allow'; "
           .   "[[ -L link.allow ]] && echo LINK_AFTER=symlink || echo LINK_AFTER=plain; "
           . "else echo SYMLINK=no; rm -f link.allow; fi\n"
           . "ln h1.allow h2.allow\n"
           . FN_NAME . " '$bdir/h1.allow'\n"
           . "echo HLINKS=\$(stat -c %h h1.allow)\n"
           . FN_NAME . " '$bdir/nul.allow'\n"
           . "echo DONE\n";
    file_put_contents("$dir/links.sh", $links);
    $lo = []; $lrc = 1;
    exec(escapeshellarg($bash) . ' ' . escapeshellarg("$bdir/links.sh") . ' 2>&1', $lo, $lrc);
    clearstatcache();
    $lt = implode("\n", $lo);
    t_eq(0, $lrc, 'the link and binary-byte cases run to completion'
                . ($lrc === 0 ? '' : ' (output: ' . str_replace("\n", ' | ', substr($lt, 0, 300)) . ')'));

    if (strpos($lt, 'SYMLINK=yes') !== false) {
        t_contains($lt, 'LINK_AFTER=symlink',
                   'a symlinked csf.allow is still a symlink afterwards, not a '
                 . 'plain copy that the config manager will fight');
        t_eq("192.0.2.40\nkeep\n", (string)@file_get_contents("$dir/target.allow"),
             'and the file it points at is the one cleaned: before the fix the '
           . 'stale line survived there and CSF kept printing the error');
    } else {
        // Windows without developer mode cannot make a symlink. The docker run
        // of this suite (Linux) is where this half executes.
        echo "SKIP symlink case: this bash cannot create symlinks here\n";
    }

    t_eq($hIn, (string)@file_get_contents("$dir/h1.allow"),
         'a hard-linked csf.allow is NOT rewritten: byte-identical. Every '
       . 'rewrite either splits the link or truncates first, and a truncate that '
       . 'fails or is interrupted leaves the firewall allow list empty');
    t_eq($hIn, (string)@file_get_contents("$dir/h2.allow"), 'and neither is its other name');
    t_eq($old, filemtime("$dir/h1.allow"), 'not even touched: its mtime is unchanged');
    t_contains($lt, 'HLINKS=2', 'the two names are still one file');
    t_contains($lt, "WARN:   $bdir/h1.allow is hard-linked, so it was not rewritten",
               'the operator is told, with the file named');
    t_contains($lt, 'WARN:     Include /etc/sentinel-gate/csf_allow.txt',
               'and the exact line to remove by hand');
    t_ok(strpos($lt, "Removed stale Sentinel Gate include from $bdir/h1.allow") === false,
         'and is never told it was removed');

    t_eq("a\0b\nkeep\n", (string)@file_get_contents("$dir/nul.allow"),
         'a file with a NUL byte loses only the stale line');
    t_contains($lt, "from $bdir/nul.allow: Include /etc/sentinel-gate/a",
               'and the report names the actual line, not grep\'s "Binary file '
             . '... matches", which on the warn path would be the "line" the '
             . 'operator is told to delete');
    t_ok(strpos($lt, 'Binary file') === false, 'grep\'s binary summary never reaches the output');
    t_eq([], glob("$dir/*.ss-*") ?: [], 'no temp or backup file is left by the link cases');

    foreach (glob("$dir/*") ?: [] as $f) { @unlink($f); }
    @rmdir($dir);
}
