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
        $job = $sc->startScan($path, $type);
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
            echo "Skipped accounts have no usable home directory, or one that is" . PHP_EOL;
            echo "a symlink or owned by another user - see the log for which." . PHP_EOL;
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

        default:
            fail('usage: serverscrub quarantine [status|sweep|prune [days]|move <dir>]');
        }
        break;
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
  quarantine sweep             Apply retention now: expire, reconcile and retire records\n  quarantine prune [days]      Delete quarantined files older than N days\n  quarantine move <dir>        Relocate quarantine to another volume\n  license status               Show license state
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
