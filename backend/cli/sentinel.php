#!/usr/bin/env php
<?php
/**
 * Sentinel Gate — Command-line interface
 * ──────────────────────────────────────
 * Installed as /usr/bin/sentinel (thin wrapper execs this file).
 * Reuses the exact same config bootstrap and library classes as the web app,
 * so CLI and dashboard always agree on state.
 *
 * Usage:
 *   sentinel version
 *   sentinel status
 *   sentinel scan [path] [--full|--quick]
 *   sentinel firewall list
 *   sentinel firewall block   <ip> [reason]
 *   sentinel firewall unblock <ip>
 *   sentinel firewall allow   <ip> [comment]
 *   sentinel reputation <ip>
 *   sentinel update-sigs
 * Global flag: --json  (machine-readable output for any command)
 */

if (PHP_SAPI !== 'cli') { fwrite(STDERR, "sentinel: CLI only\n"); exit(2); }

// ── Bootstrap: identical to the web app ───────────────────────────────────────
$BASE = dirname(__DIR__);                       // .../backend
require_once $BASE . '/config/config.php';
require_once $BASE . '/lib/Database.php';
require_once $BASE . '/lib/Logger.php';
require_once $BASE . '/lib/Scanner.php';
require_once $BASE . '/lib/Firewall.php';
require_once $BASE . '/lib/IPReputation.php';
require_once $BASE . '/lib/License.php';

// ── Arg parsing ───────────────────────────────────────────────────────────────
$argv0 = 'sentinel';
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
function fail(string $msg, int $code = 1): void { fwrite(STDERR, "sentinel: $msg\n"); exit($code); }
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
        out(['name' => 'Sentinel Gate', 'version' => SG_VERSION, 'mode' => INSTALL_MODE]);
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
                'web'     => $svc('sentinel-gate-web'),
                'monitor' => $svc('sentinel-gate-monitor'),
            ],
        ]);
        break;
    }

    case 'scan': {
        need_root();
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
             'hint' => "check progress: sentinel status --json"]);
        break;
    }

    case 'firewall': {
        $sub = $rest[0] ?? 'list';
        $fw  = new Firewall();
        switch ($sub) {
        case 'list':
            out(['blocked' => $fw->getBlockedIPs(100, 0), 'rules' => $fw->getRules()]);
            break;
        case 'block': {
            need_root();
            $ip = $rest[1] ?? ''; if (!valid_ip($ip)) fail('usage: sentinel firewall block <ip> [reason]');
            out($fw->blockIP($ip, $rest[2] ?? 'cli', true));
            break;
        }
        case 'unblock': {
            need_root();
            $ip = $rest[1] ?? ''; if (!valid_ip($ip)) fail('usage: sentinel firewall unblock <ip>');
            out($fw->unblockIP($ip));
            break;
        }
        case 'allow': {
            need_root();
            $ip = $rest[1] ?? ''; if (!valid_ip($ip)) fail('usage: sentinel firewall allow <ip> [comment]');
            out($fw->allowIP($ip, $rest[2] ?? 'cli'));
            break;
        }
        default:
            fail("unknown firewall subcommand: $sub");
        }
        break;
    }

    case 'reputation': {
        $ip = $rest[0] ?? ''; if (!valid_ip($ip)) fail('usage: sentinel reputation <ip>');
        out((new IPReputation())->check($ip));
        break;
    }

    case 'update-sigs':
        need_root();
        out((new Scanner())->updateSignatures());
        break;

    case 'license': {
        $sub = $rest[0] ?? 'status';
        switch ($sub) {
        case 'status':
            out(License::status());
            break;

        case 'activate': {
            need_root();
            $key = $rest[1] ?? '';
            if ($key === '') fail('usage: sentinel license activate <license-key>');
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

        default:
            fail('usage: sentinel license [status|activate <key>|refresh]');
        }
        break;
    }

    case 'help':
    case '--help':
    case '-h':
    default:
        $v = SG_VERSION;
        echo <<<TXT
Sentinel Gate CLI v{$v}
Usage: sentinel <command> [args] [--json]

  version                      Show version and install mode
  status                       Scanner, firewall, CSF and service status
  scan [path] [--full|--quick] Start a scan (default: /home quick)
  firewall list                List blocked IPs and custom rules
  firewall block   <ip> [why]  Block an IP (persistent)
  firewall unblock <ip>        Remove a block
  firewall allow   <ip> [note] Whitelist an IP
  reputation <ip>              Look up IP reputation
  update-sigs                  Update malware signatures
  license status               Show license state
  license activate <key>       Store and verify a license key
  license refresh              Force a re-check against the server

Add --json to any command for machine-readable output.
TXT;
        echo "\n";
        break;
    }
} catch (Throwable $e) {
    fail($e->getMessage(), 1);
}
