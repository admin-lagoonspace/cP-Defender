#!/usr/bin/env php
<?php
/**
 * ServerScrub — Command-line interface
 * ──────────────────────────────────────
 * Installed as /usr/bin/serverscrub (thin wrapper execs this file).
 * Reuses the exact same config bootstrap and library classes as the web app,
 * so CLI and dashboard always agree on state.
 *
 * Usage:
 *   serverscrub version
 *   serverscrub status
 *   serverscrub scan [path] [--full|--quick]
 *   serverscrub firewall list
 *   serverscrub firewall block   <ip> [reason]
 *   serverscrub firewall unblock <ip>
 *   serverscrub firewall allow   <ip> [comment]
   serverscrub waf mode                 (show the rule engine mode)
   serverscrub waf mode <on|detectiononly|off>
   serverscrub waf triage [days]        (what arming the engine would do)
   serverscrub db-check                 (SQLite integrity check)
 *   serverscrub reputation <ip>
 *   serverscrub update-sigs
 * Global flag: --json  (machine-readable output for any command)
 */

if (PHP_SAPI !== 'cli') { fwrite(STDERR, "serverscrub: CLI only\n"); exit(2); }

// ── Bootstrap: identical to the web app ───────────────────────────────────────
$BASE = dirname(__DIR__);                       // .../backend
require_once $BASE . '/config/config.php';
require_once $BASE . '/lib/Database.php';
require_once $BASE . '/lib/Logger.php';
require_once $BASE . '/lib/Heuristics.php';
require_once $BASE . '/lib/Scanner.php';
require_once $BASE . '/lib/Firewall.php';
require_once $BASE . '/lib/IPReputation.php';
require_once $BASE . '/lib/License.php';
require_once $BASE . '/lib/UserReport.php';
require_once $BASE . '/lib/Signatures.php';
// Loaded at the top rather than inside the command: a require_once buried in
// a switch arm is how a CLI path dies with 'Class not found' the first time
// somebody uses it, which for a recovery tool is the worst possible moment.
require_once $BASE . '/lib/QuarantineRestore.php';
require_once $BASE . '/lib/SignatureSuppressions.php';
require_once $BASE . '/lib/MassDetection.php';

// ── Arg parsing ───────────────────────────────────────────────────────────────
$argv0 = 'serverscrub';
$args  = array_slice($argv, 1);
$JSON  = false;
$args  = array_values(array_filter($args, function ($a) use (&$JSON) {
    if ($a === '--json') { $JSON = true; return false; }
    return true;
}));
$cmd = $args[0] ?? 'help';
$rest = array_slice($args, 1);

// ── Output helpers ────────────────────────────────────────────────────────────
function out($data): void {
    global $JSON;
    if ($JSON) { echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n"; return; }
    if (is_scalar($data) || $data === null) { echo $data . "\n"; return; }
    render($data, 0);
}
function render($data, int $indent): void {
    $pad = str_repeat('  ', $indent);
    foreach ((array)$data as $k => $v) {
        if (is_array($v)) {
            echo $pad . (is_int($k) ? "-" : "$k:") . "\n";
            render($v, $indent + 1);
        } else {
            $v = is_bool($v) ? ($v ? 'yes' : 'no') : $v;
            echo $pad . (is_int($k) ? "  $v" : sprintf("%-22s %s", "$k:", $v)) . "\n";
        }
    }
}
/**
 * What to do about a tripped bound, per verdict.
 *
 * The suppression command is COMPOSED ONLY for 'varied-content'. For the
 * identical and undetermined cases it is named in prose and not typed out: a
 * ready-to-paste `signatures suppress add` for a signature the product has
 * just said it cannot judge is one keystroke from switching off detection of a
 * live ransomware run, which is what 2e160dc's message did.
 */
function self_mass_next(string $verdict, string $signature, int $job): string
{
    if ($verdict === MassDetection::V_IDENTICAL) {
        return 'the matched files are the same few files repeated, which is what '
             . 'ransomware and mass defacement look like. Read one of the '
             . 'flagged files. If it is malware, decide the scope of the '
             . 'clean-up and raise the bound deliberately with `serverscrub scan '
             . 'mass-bound <N>`; do NOT suppress the signature.';
    }
    if ($verdict === MassDetection::V_VARIED) {
        return 'the matched files all differ, which is what a noisy signature '
             . 'looks like. Read one of the flagged files; if the signature is '
             . 'wrong: serverscrub signatures suppress add ' . $signature
             . ' -- and put back what it already took: serverscrub quarantine '
             . 'restore --job=' . $job . ' --signature=' . $signature;
    }
    return 'the product could not tell whether these are one file repeated or '
         . 'many different files, and has not guessed. Read one of the flagged '
         . 'files before anything else. If it is malware, decide the scope of '
         . 'the clean-up; if it is not, suppressing the signature is the lever '
         . '(see `serverscrub signatures suppress add --help`) and the already '
         . 'quarantined files come back with `serverscrub quarantine restore '
         . '--job=' . $job . '`.';
}

function fail(string $msg, int $code = 1): void { fwrite(STDERR, "serverscrub: $msg\n"); exit($code); }
function need_root(): void {
    if (function_exists('posix_geteuid') ? posix_geteuid() !== 0 : trim(shell_exec('id -u')) !== '0') {
        fail('this command needs root', 3);
    }
}
function valid_ip(string $ip): bool { return filter_var($ip, FILTER_VALIDATE_IP) !== false; }


// ── Commands ──────────────────────────────────────────────────────────────────
try {
    switch ($cmd) {

    case 'version':
        out(['name' => 'ServerScrub', 'version' => SG_VERSION, 'mode' => INSTALL_MODE]);
        break;

    case 'status': {
        $sc = new Scanner();
        $fw = new Firewall();
        $svc = function (string $s): string {
            $o = trim(shell_exec('systemctl is-active ' . escapeshellarg($s) . ' 2>/dev/null') ?? '');
            return $o !== '' ? $o : 'unknown';
        };
        out([
            'version'   => SG_VERSION,
            'mode'      => INSTALL_MODE,
            'scanner'   => $sc->getStats(),
            'firewall'  => $fw->getStats(),
            'csf'       => $fw->getCSFStatus(),
            'services'  => [
                'web'     => $svc('serverscrub-web'),
                'monitor' => $svc('serverscrub-monitor'),
            ],
        ]);
        break;
    }

    case 'scan': {
        /* THE BOUND ON DESTRUCTIVE ACTION AT SCALE, where an operator can
         * actually see it.
         *
         * scan_mass_signature_max existed only as a settings row: no command,
         * no field, no help text. Past the bound a real mass event leaves its
         * findings flagged and in place by design -- that is the right default
         * -- but the only ways on from there are suppressing the signature
         * (wrong: it hides a real infection), a per-file verdict on 153,800
         * files (not possible), or raising this. A conservative default with
         * no visible lever is a dead end during the incident it exists for. */
        if (($rest[0] ?? '') === 'mass-bound') {
            $arg = $rest[1] ?? '';

            if ($arg === '--clear-trip') {
                need_root();
                License::requireValid('Scan settings');
                MassDetection::clearLastTrip();
                out(['cleared' => true,
                     'note' => 'the recorded mass detection is cleared; the '
                             . 'findings themselves are untouched']);
                break;
            }

            if ($arg !== '') {
                need_root();
                License::requireValid('Scan settings');
                if (!preg_match('/^[0-9]+$/', $arg)) {
                    fail('usage: serverscrub scan mass-bound [N|--clear-trip]  '
                       . '(N files from one signature in one scan; 0 disables '
                       . 'the bound)');
                }
                $n = (int) $arg;
                if ($n > 10000000) {
                    fail('that is not a bound: ' . $n);
                }
                $was = MassDetection::limit();
                Database::setSetting(MassDetection::SETTING_MAX, (string) $n);
                /* Recorded, because raising this during an incident is a
                 * decision somebody should be able to find afterwards. */
                Logger::event('scan_mass_bound_changed', 'high', '',
                    MassDetection::SETTING_MAX,
                    'Mass-detection bound changed from ' . $was . ' to ' . $n
                    . ' by the CLI'
                    . ($n === 0 ? ' -- DISABLED: one signature may now quarantine '
                                . 'without limit, which is how 154,323 customer '
                                . 'files were taken on 10 Nov' : ''));
                out(['mass_signature_max' => $n, 'was' => $was,
                     'means' => $n === 0
                        ? 'DISABLED. One signature may quarantine without limit.'
                        : 'past ' . $n . ' files from one signature in one scan, '
                        . 'findings are flagged and left in place instead of '
                        . 'being quarantined. The scan still runs to the end '
                        . 'and still records everything it finds.']);
                break;
            }

            $limit = MassDetection::limit();
            $info  = [
                'mass_signature_max' => $limit,
                'default'            => MassDetection::DEFAULT_MAX,
                'means' => $limit === 0
                    ? 'DISABLED. One signature may quarantine without limit.'
                    : 'past ' . $limit . ' files from one signature in one '
                    . 'scan, findings are flagged and left in place instead of '
                    . 'being quarantined. The scan is NOT stopped.',
                'raise_it' => 'serverscrub scan mass-bound <N>   (0 disables)',
            ];
            $trip = MassDetection::lastTrip();
            if ($trip === null) {
                $info['last_trip'] = 'none recorded';
            } else {
                /* The evidence, not just the count. "154,323 matches, one
                 * distinct file" and "154,323 matches, 154,323 distinct files"
                 * are the ransomware case and the bad-signature case, and the
                 * operator's next step is opposite in each. */
                $info['last_trip'] = [
                    'at'        => date('Y-m-d H:i:s', (int) ($trip['at'] ?? 0)),
                    'job'       => (int) ($trip['job'] ?? 0),
                    'signature' => (string) ($trip['signature'] ?? ''),
                    'matched'   => (int) ($trip['count'] ?? 0),
                    'accounts'  => (int) ($trip['accounts'] ?? 0),
                    'extensions' => (string) ($trip['extensions'] ?? ''),
                    'verdict'   => (string) ($trip['verdict'] ?? ''),
                    'evidence'  => 'of ' . (int) ($trip['samples_conclusive'] ?? 0)
                                 . ' of ' . (int) ($trip['samples_taken'] ?? 0)
                                 . ' sampled matches with a content hash, '
                                 . (int) ($trip['distinct'] ?? 0)
                                 . ' distinct file(s), largest identical group '
                                 . (int) ($trip['identical_top'] ?? 0),
                    'next'      => self_mass_next((string) ($trip['verdict'] ?? ''),
                                                  (string) ($trip['signature'] ?? ''),
                                                  (int) ($trip['job'] ?? 0)),
                    'clear'     => 'serverscrub scan mass-bound --clear-trip',
                ];
            }
            out($info);
            break;
        }

        need_root();
        License::requireValid('Scanning');
        $path = '/home';
        $type = 'quick';
        foreach ($rest as $a) {
            if ($a === '--full')      $type = 'full';
            elseif ($a === '--quick') $type = 'quick';
            elseif ($a[0] !== '-')    $path = $a;
        }
        if (!file_exists($path)) fail("path not found: $path");
        $sc  = new Scanner();
        $job = $sc->startScan($path, $type, false, '@cli');
        out(['started' => true, 'job_id' => $job, 'path' => $path, 'type' => $type,
             'hint' => "check progress: serverscrub status --json"]);
        break;
    }

    case 'firewall': {
        $sub = $rest[0] ?? 'list';
        $fw  = new Firewall();
        // Reads are allowed so an operator can always inspect state;
        // anything that CHANGES protection requires a license.
        if ($sub !== 'list') License::requireValid('Firewall management');
        switch ($sub) {
        case 'list':
            out(['blocked' => $fw->getBlockedIPs(100, 0), 'rules' => $fw->getRules()]);
            break;
        case 'block': {
            need_root();
            $ip = $rest[1] ?? ''; if (!valid_ip($ip)) fail('usage: serverscrub firewall block <ip> [reason]');
            out($fw->blockIP($ip, $rest[2] ?? 'cli', true));
            break;
        }
        case 'unblock': {
            need_root();
            $ip = $rest[1] ?? ''; if (!valid_ip($ip)) fail('usage: serverscrub firewall unblock <ip>');
            out($fw->unblockIP($ip));
            break;
        }
        case 'allow': {
            need_root();
            $ip = $rest[1] ?? ''; if (!valid_ip($ip)) fail('usage: serverscrub firewall allow <ip> [comment]');
            out($fw->allowIP($ip, $rest[2] ?? 'cli'));
            break;
        }
        default:
            fail("unknown firewall subcommand: $sub");
        }
        break;
    }

    case 'reputation': {
        License::requireValid('IP reputation lookup');
        $ip = $rest[0] ?? ''; if (!valid_ip($ip)) fail('usage: serverscrub reputation <ip>');
        out((new IPReputation())->check($ip));
        break;
    }

    // Inspect and repair the pattern store.
    //
    //   signatures            counts, and where they came from
    //   signatures export     write the mirror file now
    //   signatures restore    rebuild the table from the mirror
    //   signatures disable X  switch one rule off after a false positive
    case 'signatures': {
        need_root();
        $sub = $args[1] ?? 'status';
        if ($sub === 'export') {
            $p = Signatures::export();
            echo $p ? "Mirrored to {$p}" . PHP_EOL : "Nothing to export" . PHP_EOL;
            break;
        }
        if ($sub === 'restore') {
            // Deliberately only seeds an EMPTY table. Restoring over a live
            // set would quietly undo every rule an operator had disabled.
            $n = Signatures::seedIfEmpty();
            echo $n > 0
                ? "Restored {$n} pattern(s)" . PHP_EOL
                : "The table already has patterns; nothing restored." . PHP_EOL;
            break;
        }
        if ($sub === 'disable') {
            $name = (string) ($args[2] ?? '');
            if ($name === '') { echo "Usage: signatures disable <name>" . PHP_EOL; break; }
            Signatures::disable($name);
            Signatures::export();
            echo "Disabled {$name}" . PHP_EOL;
            break;
        }
        $st = Signatures::stats();
        echo "Patterns: {$st['enabled']} enabled of {$st['total']}" . PHP_EOL;
        foreach ($st['by_source'] as $r) {
            echo "  {$r['source']}: {$r['c']}" . PHP_EOL;
        }
        echo "Built into the code: {$st['builtin']} (the floor if all else fails)" . PHP_EOL;
        echo "Mirror: " . ($st['mirror'] ?? '?')
           . (!empty($st['mirror_at']) ? ' (written ' . date('Y-m-d H:i', $st['mirror_at']) . ')'
                                       : ' (NOT WRITTEN YET)') . PHP_EOL;
        break;
    }

    case 'update-sigs':
        need_root();
        License::requireValid('Signature updates');
        out((new Scanner())->updateSignatures());
        break;

    // Regenerate the per-user reports the cPanel plugin reads. Useful right
    // after enabling the plugin, when waiting for the hourly task would mean
    // every customer sees "no report yet" in the meantime.
    case 'user-reports': {
        $r = UserReport::writeAll();
        echo "Per-user reports: {$r['written']} written, {$r['skipped']} skipped" . PHP_EOL;
        if ($r['skipped'] > 0) {
            // The actual reason, per account. Telling the operator to go and
            // read a log is a round trip, and the guess this used to print
            // sent three of them to the wrong place.
            echo PHP_EOL . "Why they were skipped:" . PHP_EOL;
            $seen = [];
            foreach (($r['reasons'] ?? []) as $line) {
                [$who, $why] = array_pad(explode(': ', $line, 2), 2, '');
                // One line per distinct cause: 132 copies of the same error
                // is not more informative than one, and buries anything else.
                if (isset($seen[$why])) { $seen[$why][] = $who; continue; }
                $seen[$why] = [$who];
            }
            foreach ($seen as $why => $who) {
                echo '  ' . count($who) . ' account(s): ' . $why . PHP_EOL;
                echo '    e.g. ' . implode(', ', array_slice($who, 0, 3)) . PHP_EOL;
            }
            if (!$seen) {
                echo '  (no reasons recorded - see the log)' . PHP_EOL;
            }
        }
        break;
    }

    // Clean up after workers that died: stale 'running' rows, and the
    // clamscan processes they left behind.
    // Stop everything that is scanning right now. This is the one to reach
    // for when scans have stacked up and the server is struggling.
    // Show what the parser makes of the real ModSecurity log on this server.
    // Install rkhunter and chkrootkit after the fact.
    //
    // The installer does this, so this is the retry path: a host with no
    // network at install time, or one where the operator declined with
    // --no-rootkit-tools and later changed their mind.
    // What third-party tools are present, where they came from, and what is
    // degraded without each one. Exists so the "complete package" claim is
    // auditable on a real server instead of taken on trust.
    case 'deps': {
        require_once $BASE . '/lib/Dependencies.php';
        $s = Dependencies::summary();

        echo 'Third-party security stack' . PHP_EOL . PHP_EOL;
        foreach ($s['detail'] as $d) {
            $mark = $d['installed'] ? '[ok]  ' : ($d['recommended'] ? '[MISS]' : '[--]  ');
            printf("%s %-14s %s%s", $mark, $d['name'],
                   $d['installed'] ? ($d['path'] ?: 'installed') : 'not installed',
                   PHP_EOL);
            if (!$d['installed']) {
                echo '         for:     ' . $d['what_for'] . PHP_EOL;
                echo '         without: ' . $d['without_it'] . PHP_EOL;
                if (empty($d['installable']) && isset($d['installable'])) {
                    echo '         note:    ' . $d['source'] . PHP_EOL;
                } else {
                    echo '         install: ' . $d['package'] . PHP_EOL;
                    echo '         from:    ' . $d['source'] . PHP_EOL;
                }
            }
        }

        if (!empty($s['csf_warning'])) {
            $w = $s['csf_warning'];
            echo PHP_EOL . 'WARNING (' . $w['severity'] . '): ' . $w['what'] . PHP_EOL;
            echo '  ' . $w['action'] . PHP_EOL;
        }

        echo PHP_EOL;
        if ($s['recommended_missing']) {
            echo 'Missing and recommended: '
               . implode(', ', $s['recommended_missing']) . PHP_EOL;
            echo 'Install them with:  bash ' . SG_ROOT . '/install.sh --register-only'
               . PHP_EOL;
            echo '  (or the package names above, through your package manager)'
               . PHP_EOL;
        } else {
            echo 'Nothing recommended is missing.' . PHP_EOL;
        }
        // Never downloaded, always packaged -- stated here because it is the
        // question everyone asks and the answer is load-bearing.
        echo PHP_EOL . 'All of these install from the OS package manager, never by '
           . 'download:' . PHP_EOL
           . '  a tarball fetched once is pinned forever and never patched again.'
           . PHP_EOL;
        break;
    }

    case 'install-rootkit-tools': {
        $have = static function (string $bin): bool {
            @exec('command -v ' . escapeshellarg($bin) . ' 2>/dev/null', $o, $rc);
            return $rc === 0;
        };

        if ($have('rkhunter') && $have('chkrootkit')) {
            echo 'Both tools are already installed.' . PHP_EOL;
            break;
        }

        $pm = '';
        foreach (['dnf', 'yum', 'apt-get'] as $cand) {
            @exec('command -v ' . $cand . ' 2>/dev/null', $o2, $rc2);
            if ($rc2 === 0) { $pm = $cand; break; }
        }
        if ($pm === '') {
            echo 'No supported package manager found (dnf/yum/apt-get).' . PHP_EOL;
            break;
        }

        echo "Installing rkhunter and chkrootkit with {$pm}…" . PHP_EOL;
        if ($pm === 'apt-get') {
            @exec('DEBIAN_FRONTEND=noninteractive apt-get install -y -q rkhunter chkrootkit 2>&1', $out);
        } else {
            @exec($pm . ' install -y -q rkhunter chkrootkit 2>&1', $out);
            if (!$have('rkhunter') || !$have('chkrootkit')) {
                // Same treatment as the installer: EPEL added with the repo
                // left disabled, and enabled for this transaction only, so it
                // cannot take part in anything cPanel does later.
                echo 'Not in the configured repositories; trying EPEL…' . PHP_EOL;
                if (!file_exists('/etc/yum.repos.d/epel.repo')) {
                    @exec($pm . ' install -y -q epel-release 2>&1');
                    @exec("sed -i 's/^enabled=1/enabled=0/' /etc/yum.repos.d/epel.repo 2>/dev/null");
                }
                @exec($pm . ' install -y -q --enablerepo=epel rkhunter chkrootkit 2>&1', $out2);
            }
        }

        $rk = $have('rkhunter'); $ck = $have('chkrootkit');
        echo '  rkhunter:   ' . ($rk ? 'installed' : 'NOT installed') . PHP_EOL;
        echo '  chkrootkit: ' . ($ck ? 'installed' : 'NOT installed') . PHP_EOL;
        if ($rk && !file_exists('/var/lib/rkhunter/db/rkhunter.dat')) {
            echo 'Building the rkhunter file property database (this takes a while)...' . PHP_EOL;
            @exec('rkhunter --propupd --nocolors 2>&1');
        }
        if (!$rk && !$ck) {
            echo 'Neither could be installed. The built-in engine needs neither'
               . ' and is used instead.' . PHP_EOL;
        }
        break;
    }

    // Read or set the rule engine mode, from the shell.
    //
    // Added because the panel's two mode controls disagreed and one of them
    // silently did nothing: pressing Apply Mode reported success while the
    // engine stayed in detection only. When a control cannot be trusted the
    // answer is a path that shows its working -- this one prints the mode it
    // reads back from the config Apache actually loads, so "did it take?" is
    // answerable without the UI.
    // SQLite's own integrity check.
    //
    // The first anyone knew of a corrupted database was every command
    // answering "database disk image is malformed". This is the one that
    // answers the question directly, and exits non-zero so it can be used
    // from a monitoring check.
    case 'db-check': {
        $r = Database::integrityCheck(50);
        out($r);
        if (empty($r['ok'])) {
            echo PHP_EOL . 'The database is damaged. Stop the writers, back it '
               . 'up, and rebuild:' . PHP_EOL;
            echo '  systemctl stop serverscrub-monitor' . PHP_EOL;
            echo '  mv /etc/cron.d/serverscrub /root/serverscrub.cron.held' . PHP_EOL;
            echo '  cp -a ' . SG_DB . ' /root/serverscrub.db.backup' . PHP_EOL;
            echo '  sqlite3 ' . SG_DB . " '.dump' > /root/sg-dump.sql" . PHP_EOL;
            echo '  sqlite3 /root/rebuilt.db < /root/sg-dump.sql' . PHP_EOL;
            echo "  sqlite3 /root/rebuilt.db 'PRAGMA integrity_check;'" . PHP_EOL;
            echo PHP_EOL . 'Check the row counts in the rebuilt file before '
               . 'putting it in place, and keep the original.' . PHP_EOL;
            exit(1);
        }
        break;
    }

    case 'waf': {
        require_once $BASE . '/lib/WAF.php';
        require_once $BASE . '/lib/WAFInstaller.php';
        $sub = $rest[0] ?? 'mode';

        // What would happen if the engine were armed, answered from the
        // events already recorded. Read-only: it changes nothing, so it is
        // safe to run on a production server mid-incident.
        if ($sub === 'triage') {
            require_once $BASE . '/lib/WAFTriage.php';
            $days = (int) ($rest[1] ?? 7);
            $rep  = WAFTriage::report($days, 40);
            if (in_array('--json', $args, true)) { out($rep); break; }
            echo WAFTriage::text($rep);
            break;
        }

        /* Rules the operator has switched off, and where.
         *
         * This is what makes arming the engine possible at all. Triage can
         * say rule 420047 fires on real POST /shop/checkout requests on one
         * site; without a way to exclude it, the only choices were to leave
         * the whole WAF in DetectionOnly or to break that shop. */
        if ($sub === 'exclude' || $sub === 'exclusions') {
            require_once $BASE . '/lib/WAFExclusions.php';
            $op = $rest[1] ?? 'list';

            if ($op === 'list') {
                $rows = WAFExclusions::all();
                if ($JSON) { out($rows); break; }
                if (!$rows) {
                    echo "No rule exclusions. Every CRS rule is active." . PHP_EOL;
                    break;
                }
                foreach ($rows as $r) {
                    printf("  %-4s %s" . PHP_EOL, '#' . $r['id'],
                           WAFExclusions::describe($r));
                }
                echo PHP_EOL . count($rows) . ' exclusion(s). Live in Apache as of the '
                   . 'last mode change or `waf exclude apply`.' . PHP_EOL;
                break;
            }

            if ($op === 'add') {
                need_root();
                License::requireValid('WAF management');
                $ruleId = (string) ($rest[2] ?? '');
                if ($ruleId === '' || $ruleId[0] === '-') {
                    fail('usage: serverscrub waf exclude add <ruleId> '
                       . '[--domain=example.com] [--uri=/path] [--reason="..."]');
                }
                $opt = function (string $name) use ($args): string {
                    foreach ($args as $a) {
                        if (strpos($a, '--' . $name . '=') === 0) {
                            return substr($a, strlen($name) + 3);
                        }
                    }
                    return '';
                };
                $r = WAFExclusions::add($ruleId, $opt('domain'), $opt('uri'), $opt('reason'));
                if (empty($r['success'])) { fail($r['error'] ?? 'could not add the exclusion'); }

                /* Writing the row changes nothing on its own: Apache is
                 * serving the config generated at the last mode change. */
                $applied = WAFInstaller::reapplyConfig();
                out(['id'      => $r['id'],
                     'scope'   => $r['scoped'] ? 'narrowed' : 'server-wide',
                     'applied' => $applied['applied'],
                     'mode'    => $applied['mode']]);
                if (!$applied['applied'] && $applied['configured']) {
                    echo 'WARNING: the exclusion is recorded but Apache was not '
                       . 'updated: ' . $applied['message'] . PHP_EOL
                       . 'Run `serverscrub waf exclude apply` once that is resolved.' . PHP_EOL;
                    exit(1);
                }
                if (!$applied['configured']) {
                    /* NOT an error, and NOT exit 1: the command did what was
                     * asked. There is simply no config to update yet. */
                    echo 'NOTE: ' . $applied['message'] . PHP_EOL;
                }
                if (!$r['scoped']) {
                    echo 'NOTE: this disables rule ' . $ruleId . ' for every site on the '
                       . 'server. Narrow it with --domain= if only one site needs it.' . PHP_EOL;
                }
                /* @streq is exact. A site served on both the apex and the
                 * www name is two hosts to ModSecurity, and excluding one
                 * leaves the other armed -- which looks like the exclusion
                 * not working at all. */
                $dom = $opt('domain');
                if ($dom !== '') {
                    $other = strpos($dom, 'www.') === 0
                        ? substr($dom, 4) : 'www.' . $dom;
                    echo 'NOTE: the host match is exact. If that site is also served as '
                       . $other . ', add a second exclusion for it.' . PHP_EOL;
                }
                echo 'If the rule still fires, it is a phase-1 rule: a narrowed '
                   . 'exclusion cannot remove one, and it needs a server-wide '
                   . 'exclusion instead.' . PHP_EOL;
                break;
            }

            if ($op === 'rm' || $op === 'remove') {
                need_root();
                License::requireValid('WAF management');
                $id = (int) ($rest[2] ?? 0);
                if ($id <= 0) { fail('usage: serverscrub waf exclude rm <id>'); }
                $r = WAFExclusions::remove($id);
                if (empty($r['success'])) { fail($r['error'] ?? 'could not remove it'); }
                $applied = WAFInstaller::reapplyConfig();
                out(['removed' => WAFExclusions::describe($r['removed']),
                     'applied' => $applied['applied']]);
                if (!$applied['applied'] && $applied['configured']) {
                    echo 'WARNING: removed from the database but Apache was not '
                       . 'updated: ' . $applied['message'] . PHP_EOL;
                    exit(1);
                }
                if (!$applied['configured']) {
                    echo 'NOTE: ' . $applied['message'] . PHP_EOL;
                }
                break;
            }

            /* Re-render the config from the exclusions as they stand. For
             * recovering from a failed apply, and for a server whose config
             * was edited by hand. */
            if ($op === 'apply') {
                need_root();
                License::requireValid('WAF management');
                $applied = WAFInstaller::reapplyConfig();
                if (!$applied['applied'] && $applied['configured']) {
                    fail($applied['message'] ?? 'could not write the config');
                }
                out(['mode'       => $applied['mode'],
                     'applied'    => $applied['applied'],
                     'exclusions' => count(WAFExclusions::all())]);
                if (!$applied['configured']) {
                    /* Exit 0: nothing failed, there is nothing to do. An
                     * operator running this before the WAF exists needs the
                     * next step, not an error. */
                    echo 'NOTE: ' . $applied['message'] . PHP_EOL;
                }
                break;
            }

            /* Show what will be written, without writing it. Reading the
             * directives is the only way to be sure an exclusion says what
             * the operator meant. */
            if ($op === 'show') {
                $txt = WAFExclusions::render();
                echo $txt === '' ? "No exclusions, so nothing is added to the config." . PHP_EOL : $txt;
                break;
            }

            fail('usage: serverscrub waf exclude [list|add|rm|apply|show]');
        }
        if ($sub !== 'mode') { fail("unknown waf subcommand: $sub"); }

        $want = strtolower((string)($rest[1] ?? ''));
        if ($want === '') {
            out(['mode'      => WAFInstaller::currentMode(),
                 'conf'      => WAFInstaller::confDir() . '/serverscrub-waf.conf',
                 'installed' => WAFInstaller::status()]);
            break;
        }

        need_root();
        License::requireValid('WAF management');
        if (!in_array($want, ['on', 'detectiononly', 'off'], true)) {
            fail('usage: serverscrub waf mode [on|detectiononly|off]');
        }

        $r = WAFInstaller::setMode($want);
        if (empty($r['success'])) {
            echo 'ERROR: ' . ($r['error'] ?? 'could not set the mode') . PHP_EOL;
            exit(1);
        }

        // Read back rather than echo what was asked for. Reporting the
        // requested value is exactly the mistake the panel made.
        $now = WAFInstaller::currentMode();
        out(['requested' => $want, 'mode' => $now,
             'applied'   => $now === $want]);
        if ($now !== $want) {
            echo 'WARNING: Apache reloaded but the config still reads '
               . $now . PHP_EOL;
            exit(1);
        }
        break;
    }

    case 'waf-parse-test': {
        require_once $BASE . '/lib/WAF.php';
        $w = new WAF();
        $r = $w->parseTest((int)($args[1] ?? 5));
        if (empty($r['ok'])) {
            echo 'ERROR: ' . $r['error'] . PHP_EOL;
            if (!empty($r['candidates'])) {
                echo 'Looked in:' . PHP_EOL;
                foreach ($r['candidates'] as $c) { echo '  ' . $c . PHP_EOL; }
            }
            break;
        }
        echo "Log:     {$r['log_path']} ({$r['log_size']} bytes)" . PHP_EOL;
        echo "Sampled: {$r['sampled']} entries, {$r['with_ip']} with a readable IP" . PHP_EOL;
        echo "Stored:  {$r['stored_total']} event(s), {$r['stored_blank']} with no IP" . PHP_EOL;
        echo PHP_EOL;
        foreach ($r['samples'] as $i => $x) {
            echo '--- sample ' . ($i + 1) . ' ---' . PHP_EOL;
            echo '  raw:    ' . $x['raw'] . PHP_EOL;
            echo '  client: ' . ($x['client_ip'] ?? '(not found)') . PHP_EOL;
            echo '  server: ' . ($x['server_ip'] ?? '(not found)') . PHP_EOL;
        }
        if ($r['stored_blank'] > 0) {
            echo PHP_EOL . 'Existing rows keep what was parsed when they were ingested.' . PHP_EOL;
            echo 'To re-read the log with the current parser:' . PHP_EOL;
            echo '  serverscrub waf-reingest --clear' . PHP_EOL;
        }
        break;
    }

    // Re-read the audit log from the beginning.
    case 'waf-reingest': {
        require_once $BASE . '/lib/WAF.php';
        $clear = in_array('--clear', $args, true);
        $w = new WAF();
        $r = $w->reingest($clear);
        echo 'Re-ingested ' . $r['ingested'] . ' event(s)'
           . ($clear ? ' after clearing the existing ones' : '') . PHP_EOL;
        if (!$clear) {
            echo 'Note: without --clear, entries older than the 60s dedup window' . PHP_EOL;
            echo 'are stored a second time.' . PHP_EOL;
        }
        break;
    }

    /**
     * What the scheduler is doing, and when each task last did it.
     *
     * Added because there was no way to answer "is my nightly scan actually
     * running?". The scheduler logs to stdout, which cron redirects into
     * logs/cron.log -- one file holding every task's output interleaved, and
     * not where anyone would think to look.
     *
     * Delegated to the scheduler rather than reimplemented here: it owns the
     * task table, and the first draft of this command kept its own copy that
     * was wrong before it shipped.
     */
    case 'schedule': {
        $php = Scanner::phpBinary();
        $cmd = escapeshellarg($php) . ' '
             . escapeshellarg(SG_ROOT . '/backend/cron/scheduler.php') . ' --status';
        $out = [];
        $code = 0;
        @exec($cmd . ' 2>&1', $out, $code);
        echo implode(PHP_EOL, $out) . PHP_EOL;
        if ($code !== 0) { exit($code); }
        break;
    }

    case 'scan-stop-all': {
        $r = Scanner::stopAllScans();
        echo $r['message'] . PHP_EOL;
        if ($r['stopped']) { echo 'Stopped jobs: ' . implode(', ', $r['stopped']) . PHP_EOL; }
        if ($r['failed'])  { echo 'Could not stop: ' . implode(', ', $r['failed']) . PHP_EOL; }

        // Workers no row accounted for. Worth naming: they are the ones that
        // made clamscan look like it respawned no matter how often it was
        // killed, because the worker was never the thing being killed.
        if (!empty($r['runaways'])) {
            echo $r['runaways'] . ' untracked worker(s) were killed' . PHP_EOL;
        }

        // Say what is actually left executing, not what the table thinks.
        $left = Scanner::scanWorkerPids();
        echo $left
            ? 'STILL RUNNING: ' . count($left) . ' scan worker(s): ' . implode(', ', $left) . PHP_EOL
            : 'No scan workers are running.' . PHP_EOL;
        break;
    }

    case 'scan-reap': {
        $jobs = Scanner::reapStaleJobs();
        $pids = Scanner::reapOrphanClamscans();
        echo "Stale jobs cleared: {$jobs}" . PHP_EOL;
        echo 'Orphaned clamscan processes killed: ' . count($pids)
           . ($pids ? ' (' . implode(', ', $pids) . ')' : '') . PHP_EOL;
        // Reported from /proc, not from the table: a worker whose row was
        // wrongly marked interrupted is exactly the case worth surfacing.
        $procs = Scanner::scanWorkerPids();
        echo $procs
            ? 'Scan workers currently executing: ' . implode(', ', $procs) . PHP_EOL
            : 'No scan workers are running.' . PHP_EOL;
        break;
    }

    case 'quarantine': {
        $sub = $rest[0] ?? 'status';
        switch ($sub) {
        case 'status':
            out(Scanner::quarantineUsage());
            break;

        // The full sweep: expiries, reconciliation and record retirement.
        // 'prune' only deletes files by age and leaves the log untouched,
        // which is why a backlog could survive it.
        case 'sweep': {
            $r = Scanner::sweepQuarantine();
            echo 'Expired by policy:        ' . (int)$r['expired'] . PHP_EOL;
            echo 'Removed by age:           ' . (int)$r['aged_out'] . PHP_EOL;
            if ((int)($r['legacy_removed'] ?? 0) > 0) {
                echo '  from a previous location: ' . (int)$r['legacy_removed'] . PHP_EOL;
            }
            echo 'Records reconciled:       ' . (int)($r['reconciled'] ?? 0) . PHP_EOL;
            echo 'Resolved records retired: ' . (int)($r['records_retired'] ?? 0) . PHP_EOL;
            echo 'Still quarantined:        ' . (int)$r['kept'] . PHP_EOL;
            break;
        }

        case 'prune': {
            need_root();
            $days = isset($rest[1]) ? (int)$rest[1] : null;
            $r = Scanner::pruneQuarantine($days);
            out($r + ['freed' => $r['bytes']]);
            break;
        }

        case 'move': {
            need_root();
            $dest = $rest[1] ?? '';
            if ($dest === '') { fail('usage: serverscrub quarantine move /path/on/another/volume'); }
            out(Scanner::moveQuarantine($dest));
            break;
        }

        /* Putting files back.
         *
         * DRY RUN IS THE DEFAULT, and --apply is the only way to move
         * anything. On 10 Nov one third-party ClamAV signature quarantined
         * 154,323 customer files -- 154,252 of them markdown inside
         * node_modules -- and there was no supported way to reverse any of it.
         * The first thing an operator needs is to see what a scope covers;
         * the second is to be able to hand back the 72 archives in it without
         * touching the other 154,251 files. */
        case 'restore': {
            need_root();
            License::requireValid('quarantine restore');

            $flag = static function (string $name) use ($rest): ?string {
                foreach ($rest as $a) {
                    if (strpos($a, '--' . $name . '=') === 0) {
                        return substr($a, strlen($name) + 3);
                    }
                }
                return null;
            };
            $has = static function (string $name) use ($rest): bool {
                return in_array('--' . $name, $rest, true);
            };

            $scope = [];
            foreach (['job', 'signature', 'account', 'path', 'id', 'ext'] as $k) {
                $v = $flag($k);
                if ($v !== null && $v !== '') { $scope[$k] = $v; }
            }
            // --threat-name as a spelling of --signature: it is what the
            // threats table calls the column, and both names are in the
            // incident report an operator will be reading from.
            $tn = $flag('threat-name');
            if ($tn !== null && $tn !== '') { $scope['signature'] = $tn; }

            $apply = $has('apply');
            $opts  = [
                'apply'         => $apply,
                'limit'         => (int) ($flag('limit') ?? 0),
                'batch'         => (int) ($flag('batch') ?? QuarantineRestore::DEFAULT_BATCH),
                'by'            => 'cli:' . (function_exists('posix_getpwuid')
                                             ? (string) (@posix_getpwuid(posix_geteuid())['name'] ?? 'root')
                                             : 'root'),
                'clear_verdict' => $has('clear-verdict'),
            ];
            $modeFlag = $flag('mode');
            if ($modeFlag !== null && $modeFlag !== '') {
                $opts['mode'] = (int) octdec(ltrim($modeFlag, '0') === '' ? '0' : $modeFlag);
            }

            $count = QuarantineRestore::count($scope);
            if (isset($count['error'])) { fail($count['error']); }

            if (!$apply) {
                // What it covers, before anything moves. A number on its own
                // is not enough to decide with: the breakdown is what tells an
                // operator whether the scope is the one they meant.
                $b = QuarantineRestore::breakdown($scope);
                echo 'DRY RUN - nothing will be moved. Add --apply to restore.' . PHP_EOL . PHP_EOL;
                echo 'Scope:        ' . $count['desc'] . PHP_EOL;
                echo 'Files:        ' . number_format($count['count']) . PHP_EOL;
                echo 'Bytes:        ' . number_format($count['bytes']) . PHP_EOL;
                if (!empty($b['signatures'])) {
                    echo 'Signatures:' . PHP_EOL;
                    foreach ($b['signatures'] as $r) {
                        echo '  ' . str_pad(number_format((int) $r['c']), 9, ' ', STR_PAD_LEFT)
                           . '  ' . $r['k'] . PHP_EOL;
                    }
                }
                if (!empty($b['accounts'])) {
                    echo 'Accounts:' . PHP_EOL;
                    foreach ($b['accounts'] as $r) {
                        echo '  ' . str_pad(number_format((int) $r['c']), 9, ' ', STR_PAD_LEFT)
                           . '  ' . $r['k'] . PHP_EOL;
                    }
                }
                if (!empty($b['extensions'])) {
                    echo 'Extensions:' . PHP_EOL;
                    foreach ($b['extensions'] as $e => $n) {
                        echo '  ' . str_pad(number_format((int) $n), 9, ' ', STR_PAD_LEFT)
                           . '  ' . $e . PHP_EOL;
                    }
                }
            }

            $r = QuarantineRestore::run($scope, $opts);
            if (empty($r['success'])) { fail((string) ($r['error'] ?? 'restore failed')); }

            echo PHP_EOL;
            echo ($r['dry_run'] ? 'WOULD restore:   ' : 'Restored:        ')
               . number_format((int) $r['restored']) . ' file(s), '
               . number_format((int) $r['bytes']) . ' bytes' . PHP_EOL;
            echo 'Examined:        ' . number_format((int) $r['considered'])
               . ' of ' . number_format((int) $r['matched']) . ' in scope' . PHP_EOL;

            foreach (['skipped' => 'Skipped', 'failed' => 'FAILED'] as $k => $label) {
                if (empty($r[$k])) { continue; }
                echo $label . ':' . PHP_EOL;
                foreach ($r[$k] as $reason => $n) {
                    echo '  ' . str_pad(number_format((int) $n), 9, ' ', STR_PAD_LEFT)
                       . '  ' . $reason . PHP_EOL;
                    foreach (($r['examples'][$k][$reason] ?? []) as $ex) {
                        echo '             e.g. ' . $ex . PHP_EOL;
                    }
                }
            }
            if (!empty($r['skipped']['the quarantined copy is not on disk any more'])) {
                echo '  Looked in: ' . implode(', ', QuarantineRestore::searchedDirs()) . PHP_EOL;
            }
            if (!$r['dry_run']) {
                $own = $r['ownership'];
                echo 'Ownership:       ' . (int) $own['from_record'] . ' from the record, '
                   . (int) $own['inferred'] . ' inferred from the directory, '
                   . (int) $own['not_changed'] . ' not set' . PHP_EOL;
                echo 'Still in quarantine for this scope: '
                   . number_format((int) $r['remaining']) . PHP_EOL;
                if ((int) $r['verdicts'] > 0) {
                    echo 'Cleared as not-malware: ' . (int) $r['verdicts'] . PHP_EOL;
                }
            }

            /* The thing an operator will otherwise find out the hard way:
             * restoring does not stop the next scan doing it again. Both
             * levers are named rather than one being chosen for them. */
            if (!$r['dry_run'] && (int) $r['restored'] > 0 && empty($opts['clear_verdict'])) {
                echo PHP_EOL
                   . 'NOTE: these files are back, and the next scan will match them again.' . PHP_EOL
                   . '      Suppress the signature:  serverscrub signatures suppress add <name> --reason="..."' . PHP_EOL
                   . '      or clear the files:      add --clear-verdict to this command' . PHP_EOL;
            }
            break;
        }

        default:
            fail('usage: serverscrub quarantine [status|sweep|prune [days]|move <dir>'
               . '|restore <scope> [--apply]]');
        }
        break;
    }

    /* Suppressing ONE signature, by name.
     *
     * The only lever before this was turning ClamAV off, which on 10 Nov was
     * the choice between a signature that quarantined 154,323 customer files
     * and no antivirus at all on a 132-account server. */
    case 'signatures': {
        $sub = $rest[0] ?? 'help';
        if ($sub !== 'suppress') {
            fail('usage: serverscrub signatures suppress [list|add <name> [--reason=...]|rm <id>]');
        }
        $op = $rest[1] ?? 'list';

        if ($op === 'list') {
            $sum = SignatureSuppressions::summary();
            if ($JSON) { out($sum); break; }
            echo 'Suppressed signatures: ' . (int) $sum['count']
               . ' (matched ' . number_format((int) $sum['hits']) . ' file(s) since)' . PHP_EOL;
            foreach ($sum['items'] as $r) {
                echo '  #' . $r['id'] . '  ' . $r['name'] . PHP_EOL;
                echo '      hits: ' . number_format((int) $r['hits'])
                   . ($r['last_hit_at'] ? ', last ' . gmdate('Y-m-d H:i', (int) $r['last_hit_at']) . 'Z' : '')
                   . ', added by ' . $r['created_by']
                   . ' on ' . gmdate('Y-m-d', (int) $r['created_at']) . PHP_EOL;
                if (trim((string) $r['reason']) !== '') {
                    echo '      reason: ' . $r['reason'] . PHP_EOL;
                }
            }
            if ((int) $sum['count'] > 0) {
                echo PHP_EOL . 'Each of these is a hole in the defence: every other signature '
                   . 'still applies, but nothing this one matches is reported.' . PHP_EOL;
            }
            break;
        }

        if ($op === 'add') {
            need_root();
            License::requireValid('signature suppression');
            $name = (string) ($rest[2] ?? '');
            if ($name === '' || strpos($name, '--') === 0) {
                fail('usage: serverscrub signatures suppress add <signature-name> [--reason="..."]');
            }
            $reason = '';
            foreach ($rest as $a) {
                if (strpos($a, '--reason=') === 0) { $reason = substr($a, 9); }
            }
            $who = function_exists('posix_getpwuid')
                ? (string) (@posix_getpwuid(posix_geteuid())['name'] ?? 'root') : 'root';
            $r = SignatureSuppressions::add($name, $reason, 'cli:' . $who);
            if (empty($r['success'])) { fail((string) ($r['error'] ?? 'could not suppress it')); }
            out(['id' => $r['id'], 'name' => $name,
                 'prefix' => !empty($r['prefix']) ? 'yes' : 'no']);
            echo PHP_EOL . 'Nothing this signature matches will be reported from now on. It is '
               . 'counted and listed on the Scanner page.' . PHP_EOL
               . 'Files it has already quarantined are still in quarantine: '
               . 'serverscrub quarantine restore --signature=' . escapeshellarg($name) . PHP_EOL;
            break;
        }

        if ($op === 'rm' || $op === 'remove') {
            need_root();
            $id = (int) ($rest[2] ?? 0);
            if ($id <= 0) { fail('usage: serverscrub signatures suppress rm <id>'); }
            $r = SignatureSuppressions::remove($id);
            if (empty($r['success'])) { fail((string) ($r['error'] ?? 'could not remove it')); }
            out(['removed' => $r['removed']['name'] ?? '',
                 'hits_while_suppressed' => (int) ($r['removed']['hits'] ?? 0)]);
            break;
        }

        fail('usage: serverscrub signatures suppress [list|add <name> [--reason=...]|rm <id>]');
    }

    /* Suppressing ONE signature, by name.
     *
     * The only lever before this was turning ClamAV off, which on 10 Nov was
     * the choice between a signature that quarantined 154,323 customer files
     * and no antivirus at all on a 132-account server. */
    case 'signatures': {
        $sub = $rest[0] ?? 'help';
        if ($sub !== 'suppress') {
            fail('usage: serverscrub signatures suppress [list|add <name> [--reason=...]|rm <id>]');
        }
        $op = $rest[1] ?? 'list';

        if ($op === 'list') {
            $sum = SignatureSuppressions::summary();
            if ($JSON) { out($sum); break; }
            echo 'Suppressed signatures: ' . (int) $sum['count']
               . ' (matched ' . number_format((int) $sum['hits']) . ' file(s) since)' . PHP_EOL;
            foreach ($sum['items'] as $r) {
                echo '  #' . $r['id'] . '  ' . $r['name'] . PHP_EOL;
                echo '      hits: ' . number_format((int) $r['hits'])
                   . ($r['last_hit_at'] ? ', last ' . gmdate('Y-m-d H:i', (int) $r['last_hit_at']) . 'Z' : '')
                   . ', added by ' . $r['created_by']
                   . ' on ' . gmdate('Y-m-d', (int) $r['created_at']) . PHP_EOL;
                if (trim((string) $r['reason']) !== '') {
                    echo '      reason: ' . $r['reason'] . PHP_EOL;
                }
            }
            if ((int) $sum['count'] > 0) {
                echo PHP_EOL . 'Each of these is a hole in the defence: every other signature '
                   . 'still applies, but nothing this one matches is reported.' . PHP_EOL;
            }
            break;
        }

        if ($op === 'add') {
            need_root();
            License::requireValid('signature suppression');
            $name = (string) ($rest[2] ?? '');
            if ($name === '' || strpos($name, '--') === 0) {
                fail('usage: serverscrub signatures suppress add <signature-name> [--reason="..."]');
            }
            $reason = '';
            foreach ($rest as $a) {
                if (strpos($a, '--reason=') === 0) { $reason = substr($a, 9); }
            }
            $who = function_exists('posix_getpwuid')
                ? (string) (@posix_getpwuid(posix_geteuid())['name'] ?? 'root') : 'root';
            $r = SignatureSuppressions::add($name, $reason, 'cli:' . $who);
            if (empty($r['success'])) { fail((string) ($r['error'] ?? 'could not suppress it')); }
            out(['id' => $r['id'], 'name' => $name,
                 'prefix' => !empty($r['prefix']) ? 'yes' : 'no']);
            echo PHP_EOL . 'Nothing this signature matches will be reported from now on. It is '
               . 'counted and listed on the Scanner page.' . PHP_EOL
               . 'Files it has already quarantined are still in quarantine: '
               . 'serverscrub quarantine restore --signature=' . escapeshellarg($name) . PHP_EOL;
            break;
        }

        if ($op === 'rm' || $op === 'remove') {
            need_root();
            $id = (int) ($rest[2] ?? 0);
            if ($id <= 0) { fail('usage: serverscrub signatures suppress rm <id>'); }
            $r = SignatureSuppressions::remove($id);
            if (empty($r['success'])) { fail((string) ($r['error'] ?? 'could not remove it')); }
            out(['removed' => $r['removed']['name'] ?? '',
                 'hits_while_suppressed' => (int) ($r['removed']['hits'] ?? 0)]);
            break;
        }

        fail('usage: serverscrub signatures suppress [list|add <name> [--reason=...]|rm <id>]');
    }

    case 'license': {
        $sub = $rest[0] ?? 'status';
        switch ($sub) {
        case 'status':
            out(License::status() + ['identity' => License::identity()]);
            break;

        case 'activate': {
            need_root();
            $key = $rest[1] ?? '';
            if ($key === '') fail('usage: serverscrub license activate <license-key>');
            $r = License::activate($key);
            out($r);
            // Non-zero exit on a rejected key so scripted installs can branch on it
            if (!$r['valid']) exit(4);
            break;
        }

        case 'refresh': {
            need_root();
            $r = License::refresh();
            out($r);
            if (!$r['valid']) exit(4);
            break;
        }

        case 'identity':
            out(License::identity());
            break;

        case 'diagnose-hash': {
            need_root();
            out(License::diagnoseHash());
            break;
        }

        case 'try-secret': {
            need_root();
            $cand = $rest[1] ?? '';
            if ($cand === '') fail('usage: serverscrub license try-secret <candidate>');
            $r = License::trySecret($cand);
            out($r);
            if (empty($r['matches'])) exit(4);
            break;
        }

        case 'probe': {
            need_root();
            out(License::probe());
            break;
        }

        case 'secret': {
            need_root();
            $val = $rest[1] ?? '';
            if ($val === '') {
                fail('usage: serverscrub license secret <whmcs-addon-secret>');
            }
            $r = License::setSecret($val);
            // Deliberately does not echo the value back: it is the salt that
            // makes a cached local key unforgeable, and shell history is quite
            // enough exposure already.
            out($r);
            if (empty($r['success'])) exit(4);
            break;
        }

        default:
            fail('usage: serverscrub license [status|activate <key>|refresh|identity|secret <value>|probe]');
        }
        break;
    }

    case 'help':
    case '--help':
    case '-h':
    default:
        $v = SG_VERSION;
        echo <<<TXT
ServerScrub CLI v{$v}
Usage: serverscrub <command> [args] [--json]

  version                      Show version and install mode
  status                       Scanner, firewall, CSF and service status
  scan [path] [--full|--quick] Start a scan (default: /home quick)
  scan mass-bound [N]          Show or set how many files ONE signature may
                               have quarantined in one scan before the product
                               flags instead (0 disables). Shows the last trip,
                               its evidence and what to do about it.
                               --clear-trip forgets a recorded trip.
  firewall list                List blocked IPs and custom rules
  firewall block   <ip> [why]  Block an IP (persistent)
  firewall unblock <ip>        Remove a block
  firewall allow   <ip> [note] Whitelist an IP
  reputation <ip>              Look up IP reputation
  update-sigs                  Update malware signatures
  user-reports                 Rebuild the per-user reports the cPanel plugin reads
  schedule                     Show every scheduled task, when it last ran, and whether it is overdue
  scan-reap                    Clear dead scan jobs and orphaned clamscan processes
  scan-stop-all                Stop every running scan and kill its clamscan processes
  install-rootkit-tools        Install rkhunter and chkrootkit (retry of the installer step)
  waf-parse-test [n]           Show what the parser reads from the ModSecurity log
  waf-reingest [--clear]       Re-read the audit log from the beginning
  quarantine status            Show where quarantine is and how big
  quarantine sweep             Apply retention now: expire, reconcile and retire records\n  quarantine prune [days]      Delete quarantined files older than N days\n  quarantine move <dir>        Relocate quarantine to another volume\n  quarantine restore <scope>   Put quarantined files back. DRY RUN unless --apply.\n  signatures suppress list     Signatures switched off by name, and what they hid\n  signatures suppress add <n>  Stop reporting one signature (--reason=\"...\")\n  signatures suppress rm <id>  Put a signature back in service\n  signatures suppress list     Signatures switched off by name, and what they hid\n  signatures suppress add <n>  Stop reporting one signature (--reason=\"...\")\n  signatures suppress rm <id>  Put a signature back in service\n                               Scope: --job=N --signature=NAME --account=USER\n                               --ext=tar,gz,zip --path=/abs/file --id=N[,N...]\n                               Also: --limit=N --batch=N --mode=0644 --clear-verdict\n  license status               Show license state
  license activate <key>       Store and verify a license key
  license refresh              Force a re-check against the server
  license identity             Show the domain/IP this server reports
  license secret <value>       Set the WHMCS licensing addon secret
  license probe                Show exactly what the licence server returns\n  deps                         Third-party tools: what is present and where it came from
  license try-secret <value>   Test a candidate secret WITHOUT storing it
  license diagnose-hash        Identify how the licence server signs replies

Add --json to any command for machine-readable output.
TXT;
        echo "\n";
        break;
    }
} catch (Throwable $e) {
    fail($e->getMessage(), 1);
}
