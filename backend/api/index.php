<?php
/**
 * Sentinel Gate — REST API Router
 * Endpoint: /sentinel-gate/api/{module}/{action}
 */

// Suppress PHP notices/warnings so they never corrupt the JSON output
error_reporting(0);
@ini_set('display_errors', '0');

define('SG_API', true);
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../lib/Database.php';
require_once __DIR__ . '/../lib/Auth.php';
require_once __DIR__ . '/../lib/Logger.php';
require_once __DIR__ . '/../lib/Scanner.php';
require_once __DIR__ . '/../lib/Firewall.php';
require_once __DIR__ . '/../lib/WAF.php';
require_once __DIR__ . '/../lib/IPReputation.php';
require_once __DIR__ . '/../lib/RealTimeMonitor.php';
require_once __DIR__ . '/../lib/BotShield.php';
require_once __DIR__ . '/../lib/CMSGuard.php';
require_once __DIR__ . '/../lib/RootkitScanner.php';
require_once __DIR__ . '/../lib/FileIntegrity.php';
require_once __DIR__ . '/../lib/PHPHardening.php';
require_once __DIR__ . '/../lib/UpdateChecker.php';
require_once __DIR__ . '/../lib/License.php';

// ── CORS & Headers ────────────────────────────────────────────────────────────
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Authorization, Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// ── Rate limiting (simple in-memory via APCu) ─────────────────────────────────
$clientIP = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

// ── Route parsing ─────────────────────────────────────────────────────────────
$path   = trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/');
$parts  = explode('/', $path);
// Strip prefix if running under /sentinel-gate/api/
$apiIdx = array_search('api', $parts);
$parts  = $apiIdx !== false ? array_slice($parts, $apiIdx + 1) : $parts;

$module = $parts[0] ?? '';
$action = $parts[1] ?? 'index';
$id     = $parts[2] ?? null;

$method = $_SERVER['REQUEST_METHOD'];
$body   = json_decode(file_get_contents('php://input'), true) ?? [];
$query  = $_GET;

// ── Public routes (no auth required) ─────────────────────────────────────────
$publicRoutes = [
    'auth/login'      => true,
    'auth/status'     => true,
    'auth/auto-login' => true,  // cPanel SSO — trusts REMOTE_USER set by cPanel webserver
];

$routeKey = "$module/$action";
$user     = null;

if (!isset($publicRoutes[$routeKey])) {
    $user = Auth::requireAuth();
}

// ── License gate ──────────────────────────────────────────────────────────────
// Deliberately narrow. This is a security product: protection must never stop
// because of a licensing fault, or a billing/network problem becomes a security
// incident across every customer at once. Background protection (the scanners,
// firewall enforcement, the monitor daemon, cron jobs) does not pass through
// this file at all and is therefore untouched.
//
// What IS gated: read/write management endpoints. What stays open even when
// unlicensed, so an operator can always see state, fix their license, and is
// never locked out of their own security posture:
$licenseExempt = [
    'auth'    => true,   // sign in / out — never lock someone out of the box
    'license' => true,   // must be reachable to ENTER a key
    'system'  => true,   // version/health
];
if ($user !== null && empty($licenseExempt[$module])) {
    $lic = License::status();
    if (!$lic['ui_allowed']) {
        http_response_code(402);   // Payment Required
        echo json_encode([
            'success'       => false,
            'error'         => $lic['message'],
            'license_state' => $lic['status'],
            'code'          => 402,
            // The UI uses this to show an activation panel rather than an error
            'needs_license' => true,
        ]);
        exit;
    }
}

// ── Route dispatcher ──────────────────────────────────────────────────────────
try {
    $response = match($module) {
        'auth'       => routeAuth($action, $method, $body, $user),
        'license'    => routeLicense($action, $method, $body, $user),
        'dashboard'  => routeDashboard($action, $method, $query, $user),
        'scanner'    => routeScanner($action, $method, $body, $query, $id, $user),
        'firewall'   => routeFirewall($action, $method, $body, $query, $id, $user),
        'waf'        => routeWAF($action, $method, $body, $query, $user),
        'iprep'      => routeIPRep($action, $method, $body, $query, $user),
        'events'     => routeEvents($action, $method, $query, $user),
        'settings'   => routeSettings($action, $method, $body, $user),
        'logs'       => routeLogs($action, $method, $query, $user),
        'monitor'    => routeMonitor($action, $method, $body, $query, $user),
        'storage'    => routeStorage($action, $method, $body, $user),
        'botshield'  => routeBotShield($action, $method, $body, $query, $user),
        'cmsguard'   => routeCMSGuard($action, $method, $body, $query, $user),
        'rootkit'    => routeRootkit($action, $method, $body, $query, $id, $user),
        'integrity'  => routeIntegrity($action, $method, $body, $query, $id, $user),
        'phphard'    => routePHPHard($action, $method, $body, $query, $user),
        'update'     => routeUpdate($action, $method, $user),
        default      => ['success' => false, 'error' => "Unknown module: $module", 'code' => 404],
    };
} catch (Throwable $e) {
    Logger::error("API error [$module/$action]: " . $e->getMessage());
    $response = ['success' => false, 'error' => 'Internal server error', 'code' => 500];
}

$code = $response['code'] ?? 200;
unset($response['code']);
http_response_code($code);
echo json_encode($response);

// ════════════════════════════════════════════════════════════════════════════
// Route Handlers
// ════════════════════════════════════════════════════════════════════════════

function routeAuth(string $action, string $method, array $body, ?array $user): array {
    return match($action) {
        'login' => (function() use ($body) {
            $u = trim($body['username'] ?? '');
            $p = $body['password'] ?? '';
            if (!$u || !$p) return ['success' => false, 'error' => 'Missing credentials', 'code' => 400];

            $role = 'admin';
            $ok   = false;

            if (INSTALL_MODE === 'standalone') {
                // ── Standalone mode: local credential check ───────────────────
                // Demo shortcut still works for testing
                if ($u === 'demo' && $p === 'demo') {
                    $ok = true; $role = 'admin';
                } else {
                    $ok   = Auth::validateLocal($u, $p);
                    $role = 'root';
                }
            } else {
                // ── cPanel mode: cpcheck / WHM token ─────────────────────────
                if ($u === 'demo' && $p === 'demo') {
                    $ok = true; $role = 'admin';
                } elseif (!empty($body['token'])) {
                    $ok   = Auth::validateWhmToken($u, $body['token']);
                    $role = 'root';
                } else {
                    $ok   = Auth::validateCpanel($u, $p);
                    $role = ($u === 'root' || $u === 'cpanel') ? 'admin' : 'user';
                }
                // SG_DEMO env override for dev servers
                if (!$ok && getenv('SG_DEMO') === '1') { $ok = true; $role = 'admin'; }
            }

            if (!$ok) {
                Logger::event('login_fail', 'medium', $_SERVER['REMOTE_ADDR'] ?? '', $u, 'Failed login');
                return ['success' => false, 'error' => 'Invalid credentials', 'code' => 401];
            }

            Logger::info("Login: $u ($role) [" . INSTALL_MODE . "]");
            return [
                'success' => true,
                'token'   => Auth::generateToken($u, $role),
                'user'    => ['username' => $u, 'role' => $role, 'mode' => INSTALL_MODE],
            ];
        })(),

        // GET auth/auto-login — cPanel SSO: trust REMOTE_USER from cPanel webserver
        'auto-login' => (function() {
            if (INSTALL_MODE === 'standalone') {
                return ['success' => false, 'error' => 'Not available in standalone mode', 'code' => 400];
            }
            $token = Auth::autoLoginCpanel();
            if (!$token) {
                return ['success' => false, 'error' => 'No cPanel session', 'code' => 401];
            }
            $data = Auth::verifyToken($token);
            $user = ['username' => $data['sub'], 'role' => $data['role'], 'mode' => INSTALL_MODE];
            Logger::info("Auto-login: {$data['sub']} ({$data['role']}) via REMOTE_USER");
            return ['success' => true, 'token' => $token, 'user' => $user];
        })(),

        'status' => [
            'success' => true,
            'version' => SG_VERSION,
            'status'  => 'online',
            'mode'    => INSTALL_MODE,
            'port'    => SG_PORT,
        ],
        'me'     => ['success' => true, 'user' => $user],

        // POST auth/change-password (standalone only)
        'change-password' => $method === 'POST' ? (function() use ($body, $user) {
            if (INSTALL_MODE !== 'standalone')
                return ['success' => false, 'error' => 'Only available in standalone mode', 'code' => 400];
            Auth::requireRole('root', $user);
            $newPass = $body['password'] ?? '';
            if (strlen($newPass) < 8)
                return ['success' => false, 'error' => 'Password must be at least 8 characters', 'code' => 400];
            $newUser = $body['username'] ?? Database::setting('local_admin_user', 'admin');
            Auth::setLocalCredentials($newUser, $newPass);
            Logger::info("Admin credentials updated by {$user['sub']}");
            return ['success' => true];
        })() : ['success' => false, 'code' => 405],

        default  => ['success' => false, 'error' => 'Not found', 'code' => 404],
    };
}

function routeLicense(string $action, string $method, array $body, ?array $user): array {
    return match($action) {
        // GET license/status — always reachable, including when unlicensed
        'status', 'index' => ['success' => true, 'license' => License::status()],

        // POST license/activate {key}
        'activate' => $method === 'POST' ? (function() use ($body, $user) {
            Auth::requireRole('admin', $user);
            $key = trim((string)($body['key'] ?? ''));
            if ($key === '')
                return ['success' => false, 'error' => 'License key required', 'code' => 400];
            $r = License::activate($key);
            // Never log the key itself
            Logger::info("License activation attempted by {$user['sub']} — result: {$r['status']}");
            return ['success' => $r['valid'], 'license' => $r,
                    'error' => $r['valid'] ? null : $r['message']];
        })() : ['success' => false, 'code' => 405],

        // POST license/refresh — force a remote re-check
        'refresh' => $method === 'POST' ? (function() use ($user) {
            Auth::requireRole('admin', $user);
            $r = License::refresh();
            return ['success' => $r['valid'], 'license' => $r,
                    'error' => $r['valid'] ? null : $r['message']];
        })() : ['success' => false, 'code' => 405],

        default => ['success' => false, 'error' => 'Not found', 'code' => 404],
    };
}

function routeDashboard(string $action, string $method, array $q, ?array $user): array {
    return match($action) {
        'stats', 'index' => (function() {
            $scanner  = new Scanner();
            $firewall = new Firewall();
            $waf      = new WAF();

            $scanStats = $scanner->getStats();
            $fwStats   = $firewall->getStats();
            $wafStats  = $waf->getStats();

            // Files scanned (from last job)
            $lastJob = Database::fetchOne("SELECT * FROM scan_jobs WHERE status='done' ORDER BY id DESC LIMIT 1");

            // Recent events
            $events = Database::fetchAll(
                "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 10"
            );

            // Timeline data (last 30 days)
            $timeline = [];
            for ($i = 29; $i >= 0; $i--) {
                $day   = mktime(0, 0, 0, date('n'), date('j') - $i);
                $next  = $day + 86400;
                $wafH  = Database::fetchOne(
                    "SELECT COUNT(*) as c FROM waf_events WHERE timestamp >= ? AND timestamp < ?",
                    [$day, $next]
                )['c'];
                $bfH   = Database::fetchOne(
                    "SELECT COUNT(*) as c FROM security_events WHERE type='brute_force' AND timestamp >= ? AND timestamp < ?",
                    [$day, $next]
                )['c'];
                $malH  = Database::fetchOne(
                    "SELECT COUNT(*) as c FROM threats WHERE detected_at >= ? AND detected_at < ?",
                    [$day, $next]
                )['c'];
                $timeline[] = [
                    'date'        => date('Y-m-d', $day),
                    'waf_blocks'  => (int) $wafH,
                    'brute_force' => (int) $bfH,
                    'malware'     => (int) $malH,
                ];
            }

            return [
                'success'   => true,
                'scanner'   => $scanStats,
                'firewall'  => $fwStats,
                'waf'       => $wafStats,
                'events'    => $events,
                'timeline'  => $timeline,
                'server'    => [
                    'hostname'   => gethostname(),
                    'php_version'=> PHP_VERSION,
                    'uptime'     => shell_exec('uptime -p 2>/dev/null') ?? '',
                    'load'       => sys_getloadavg(),
                ],
            ];
        })(),
        default => ['success' => false, 'error' => 'Not found', 'code' => 404],
    };
}

function routeScanner(string $action, string $method, array $body, array $q, ?string $id, ?array $user): array {
    $scanner = new Scanner();
    return match($action) {
        'start'  => $method === 'POST'
            ? ['success' => true, 'job_id' => $scanner->startScan($body['path'] ?? '/home', $body['type'] ?? 'quick')]
            : ['success' => false, 'error' => 'POST required', 'code' => 405],

        'status' => ['success' => true, 'data' => $scanner->getScanStatus((int)($id ?? $q['job_id'] ?? 0))],
        'stats'  => ['success' => true, 'data' => $scanner->getStats()],

        'threats' => (function() use ($q) {
            $status   = $q['status'] ?? null;
            $sqlWhere = $status ? 'WHERE status = ?' : '';
            $params   = $status ? [$status] : [];
            $threats  = Database::fetchAll(
                "SELECT * FROM threats $sqlWhere ORDER BY detected_at DESC LIMIT 200",
                $params
            );
            return ['success' => true, 'data' => $threats];
        })(),

        'quarantine' => $method === 'POST' && $id
            ? (function() use ($scanner, $id) {
                $threat = Database::fetchOne('SELECT file_path FROM threats WHERE id=?', [(int)$id]);
                if (!$threat) return ['success' => false, 'error' => 'Threat not found', 'code' => 404];
                return ['success' => $scanner->quarantine($threat['file_path'], (int)$id)];
            })()
            : ['success' => false, 'error' => 'Invalid request', 'code' => 400],

        'restore' => $method === 'POST' && $id
            ? ['success' => $scanner->restoreFromQuarantine((int)$id)]
            : ['success' => false, 'error' => 'Invalid request', 'code' => 400],

        'delete' => $method === 'DELETE' && $id
            ? ['success' => $scanner->deleteThreat((int)$id)]
            : ['success' => false, 'error' => 'DELETE required', 'code' => 405],

        'update-sigs' => $method === 'POST'
            ? $scanner->updateSignatures()
            : ['success' => false, 'error' => 'POST required', 'code' => 405],

        default => ['success' => false, 'error' => 'Not found', 'code' => 404],
    };
}

function routeFirewall(string $action, string $method, array $body, array $q, ?string $id, ?array $user): array {
    $fw = new Firewall();
    Auth::requireRole('admin', $user);

    return match($action) {
        'status'     => ['success' => true, 'data' => $fw->getCSFStatus()],
        'stats'      => ['success' => true, 'data' => $fw->getStats()],
        'rules'      => ['success' => true, 'data' => $fw->getRules()],
        'blocked'    => ['success' => true, 'data' => $fw->getBlockedIPs(
            (int)($q['limit'] ?? 100), (int)($q['offset'] ?? 0)
        )],

        'block' => $method === 'POST'
            ? $fw->blockIP(
                $body['ip'] ?? '',
                $body['reason'] ?? 'Manual block',
                !empty($body['permanent']),
                (int)($body['ttl'] ?? 86400)
            )
            : ['success' => false, 'code' => 405],

        'unblock' => $method === 'POST'
            ? $fw->unblockIP($body['ip'] ?? '')
            : ['success' => false, 'code' => 405],

        'allow' => $method === 'POST'
            ? $fw->allowIP($body['ip'] ?? '', $body['comment'] ?? '')
            : ['success' => false, 'code' => 405],

        'add-rule' => $method === 'POST'
            ? $fw->addRule($body)
            : ['success' => false, 'code' => 405],

        'toggle-rule' => $method === 'POST'
            ? $fw->toggleRule((int)($body['id'] ?? 0), (bool)($body['enabled'] ?? false))
            : ['success' => false, 'code' => 405],

        'delete-rule' => $method === 'DELETE' && $id
            ? $fw->deleteRule((int)$id)
            : ['success' => false, 'code' => 405],

        'geo-block' => $method === 'POST'
            ? $fw->setGeoBlock($body['countries'] ?? [])
            : ['success' => false, 'code' => 405],

        'reload' => $method === 'POST'
            ? $fw->reloadFirewall()
            : ['success' => false, 'code' => 405],

        default => ['success' => false, 'error' => 'Not found', 'code' => 404],
    };
}

function routeWAF(string $action, string $method, array $body, array $q, ?array $user): array {
    $waf = new WAF();
    return match($action) {
        'status'     => ['success' => true, 'data' => $waf->getStatus()],
        'stats'      => ['success' => true, 'data' => $waf->getStats()],
        'events'     => ['success' => true, 'data' => $waf->getEvents(
            (int)($q['limit'] ?? 100), $q['severity'] ?? null, $q['ip'] ?? null
        )],
        'categories' => ['success' => true, 'data' => $waf->getRuleCategories()],

        'set-mode' => $method === 'POST'
            ? $waf->setMode($body['mode'] ?? 'On')
            : ['success' => false, 'code' => 405],

        'add-rule' => $method === 'POST'
            ? $waf->addCustomRule($body['id'] ?? uniqid('SG'), $body['pattern'] ?? '', $body['action'] ?? 'block')
            : ['success' => false, 'code' => 405],

        'ingest-logs' => $method === 'POST'
            ? ['success' => true, 'ingested' => $waf->ingestModSecLog()]
            : ['success' => false, 'code' => 405],

        default => ['success' => false, 'error' => 'Not found', 'code' => 404],
    };
}

function routeIPRep(string $action, string $method, array $body, array $q, ?array $user): array {
    $rep = new IPReputation();
    return match($action) {
        'check' => ['success' => true, 'data' => $rep->check($q['ip'] ?? $body['ip'] ?? '')],
        'bulk'  => $method === 'POST'
            ? ['success' => true, 'data' => $rep->bulkCheck($body['ips'] ?? [])]
            : ['success' => false, 'code' => 405],
        'top-attackers' => ['success' => true, 'data' => $rep->getTopAttackingIPs()],
        default => ['success' => false, 'error' => 'Not found', 'code' => 404],
    };
}

function routeEvents(string $action, string $method, array $q, ?array $user): array {
    return match($action) {
        'list', 'index' => (function() use ($q) {
            $limit    = (int)($q['limit'] ?? 50);
            $severity = $q['severity'] ?? null;
            $where    = $severity ? 'WHERE severity = ?' : '';
            $params   = $severity ? [$severity, $limit] : [$limit];
            $events   = Database::fetchAll(
                "SELECT * FROM security_events $where ORDER BY timestamp DESC LIMIT ?",
                $params
            );
            $unresolved = Database::fetchOne(
                "SELECT COUNT(*) as c FROM security_events WHERE resolved = 0"
            )['c'];
            return ['success' => true, 'data' => $events, 'unresolved' => (int) $unresolved];
        })(),

        'resolve' => $method === 'POST'
            ? (function() use ($q) {
                Database::query(
                    "UPDATE security_events SET resolved=1 WHERE id=?",
                    [(int)($q['id'] ?? 0)]
                );
                return ['success' => true];
            })()
            : ['success' => false, 'code' => 405],

        default => ['success' => false, 'error' => 'Not found', 'code' => 404],
    };
}

function routeSettings(string $action, string $method, array $body, ?array $user): array {
    Auth::requireRole('admin', $user);
    return match($action) {
        'get', 'index' => (function() {
            $rows = Database::fetchAll("SELECT key, value FROM settings ORDER BY key");
            $out  = [];
            foreach ($rows as $r) $out[$r['key']] = $r['value'];
            return ['success' => true, 'data' => $out];
        })(),

        'set' => $method === 'POST'
            ? (function() use ($body) {
                foreach ($body as $k => $v) {
                    if (preg_match('/^[a-z_]+$/', $k)) {
                        Database::setSetting($k, (string)$v);
                    }
                }
                return ['success' => true];
            })()
            : ['success' => false, 'code' => 405],

        default => ['success' => false, 'error' => 'Not found', 'code' => 404],
    };
}

function routeLogs(string $action, string $method, array $q, ?array $user): array {
    Auth::requireRole('admin', $user);
    return match($action) {
        'recent' => ['success' => true, 'data' => Logger::getRecentLogs((int)($q['lines'] ?? 200))],
        default  => ['success' => false, 'error' => 'Not found', 'code' => 404],
    };
}

function routeMonitor(string $action, string $method, array $body, array $q, ?array $user): array {
    Auth::requireRole('admin', $user);
    $monitor = new RealTimeMonitor();

    return match($action) {
        'status'  => ['success' => true, 'data' => $monitor->getStatus()],
        'stats'   => ['success' => true, 'data' => $monitor->getDashboardStats()],

        'start'   => $method === 'POST'
            ? $monitor->start()
            : ['success' => false, 'code' => 405],

        'stop'    => $method === 'POST'
            ? $monitor->stop()
            : ['success' => false, 'code' => 405],

        'restart' => $method === 'POST'
            ? $monitor->restart()
            : ['success' => false, 'code' => 405],

        'detections' => [
            'success' => true,
            'data'    => $monitor->getRecentDetections((int)($q['limit'] ?? 50))
        ],

        'logs' => [
            'success' => true,
            'data'    => $monitor->getRecentLogs((int)($q['lines'] ?? 100))
        ],

        'add-path' => $method === 'POST' && !empty($body['path'])
            ? $monitor->addWatchPath($body['path'])
            : ['success' => false, 'error' => 'POST with {path} required', 'code' => 400],

        'remove-path' => $method === 'POST' && !empty($body['path'])
            ? $monitor->removeWatchPath($body['path'])
            : ['success' => false, 'error' => 'POST with {path} required', 'code' => 400],

        'install-service' => $method === 'POST'
            ? $monitor->installService()
            : ['success' => false, 'code' => 405],

        'service-status' => ['success' => true, 'data' => $monitor->getServiceStatus()],

        'enable-service'  => $method === 'POST'
            ? $monitor->enableService()
            : ['success' => false, 'code' => 405],

        'disable-service' => $method === 'POST'
            ? $monitor->disableService()
            : ['success' => false, 'code' => 405],

        'service-logs' => [
            'success' => true,
            'data'    => $monitor->getServiceLogs((int)($q['lines'] ?? 50))
        ],

        default => ['success' => false, 'error' => 'Not found', 'code' => 404],
    };
}

// ── Storage Management ────────────────────────────────────────────────────────
function routeStorage(string $action, string $method, array $body, ?array $user): array {
    Auth::requireRole('admin', $user);

    return match($action) {

        // GET storage/stats
        'stats' => (function() {
            $quarDir = Database::storagePath('quarantine');
            $logDir  = Database::storagePath('logs');
            $dbFile  = SG_DB;

            function sg_dir_size(string $dir): int {
                $size = 0;
                if (!is_dir($dir)) return 0;
                foreach (new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
                ) as $f) { $size += $f->getSize(); }
                return $size;
            }
            function sg_file_count(string $dir, string $ext = ''): int {
                if (!is_dir($dir)) return 0;
                $i = 0;
                foreach (new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
                ) as $f) {
                    if ($ext === '' || $f->getExtension() === ltrim($ext, '.')) $i++;
                }
                return $i;
            }

            return ['success' => true, 'data' => [
                'quarantine' => [
                    'path'       => $quarDir,
                    'size_bytes' => sg_dir_size($quarDir),
                    'files'      => sg_file_count($quarDir, 'quarantine'),
                    'writable'   => is_writable($quarDir),
                ],
                'logs' => [
                    'path'            => $logDir,
                    'size_bytes'      => sg_dir_size($logDir),
                    'files'           => sg_file_count($logDir, 'log'),
                    'writable'        => is_writable($logDir),
                    'monitor_log_bytes' => file_exists($logDir . '/monitor.log')
                        ? filesize($logDir . '/monitor.log') : 0,
                ],
                'database' => [
                    'path'       => $dbFile,
                    'size_bytes' => file_exists($dbFile) ? filesize($dbFile) : 0,
                    'rows'       => [
                        'waf_events'      => (int)(Database::fetchOne("SELECT COUNT(*) as c FROM waf_events")['c'] ?? 0),
                        'security_events' => (int)(Database::fetchOne("SELECT COUNT(*) as c FROM security_events")['c'] ?? 0),
                        'threats'         => (int)(Database::fetchOne("SELECT COUNT(*) as c FROM threats")['c'] ?? 0),
                        'cron_log'        => (int)(Database::fetchOne("SELECT COUNT(*) as c FROM cron_log")['c'] ?? 0),
                    ],
                ],
                'settings' => [
                    'quarantine_dir'            => Database::setting('quarantine_dir', ''),
                    'log_dir'                   => Database::setting('log_dir', ''),
                    'log_retention_days'        => (int)Database::setting('log_retention_days', '30'),
                    'quarantine_retention_days' => (int)Database::setting('quarantine_retention_days', '90'),
                    'db_max_waf_events'         => (int)Database::setting('db_max_waf_events', '100000'),
                    'db_max_security_events'    => (int)Database::setting('db_max_security_events', '50000'),
                    'db_max_cron_log'           => (int)Database::setting('db_max_cron_log', '1000'),
                    'monitor_log_max_mb'        => (int)Database::setting('monitor_log_max_mb', '50'),
                ],
            ]];
        })(),

        // POST storage/prune — run cleanup immediately
        'prune' => $method === 'POST' ? (function() {
            $quarDir = Database::storagePath('quarantine');
            $logDir  = Database::storagePath('logs');

            $logDays   = (int)Database::setting('log_retention_days', '30');
            $logCutoff = time() - ($logDays * 86400);
            $logsDeleted = 0;
            if (is_dir($logDir)) {
                foreach (glob($logDir . '/*.log') as $f) {
                    if (filemtime($f) < $logCutoff && basename($f) !== 'monitor.log') {
                        @unlink($f); $logsDeleted++;
                    }
                }
            }

            $maxMonMB = (int)Database::setting('monitor_log_max_mb', '50');
            $monLog   = $logDir . '/monitor.log';
            $monRotated = false;
            if (file_exists($monLog) && filesize($monLog) > ($maxMonMB * 1048576)) {
                @rename($monLog, $monLog . '.' . date('Ymd-His') . '.old');
                $monRotated = true;
            }

            $qDays   = (int)Database::setting('quarantine_retention_days', '90');
            $qCutoff = time() - ($qDays * 86400);
            $qDel    = 0;
            if (is_dir($quarDir)) {
                foreach (new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($quarDir, FilesystemIterator::SKIP_DOTS)
                ) as $f) {
                    if ($f->isFile() && $f->getMTime() < $qCutoff) {
                        @unlink($f->getPathname()); $qDel++;
                    }
                }
                foreach (glob($quarDir . '/????-??-??') as $d) {
                    if (is_dir($d) && count(scandir($d)) === 2) @rmdir($d);
                }
            }

            $dbPruned = Database::pruneOldRecords();
            Logger::info("Storage pruned: logs=$logsDeleted, quarantine=$qDel, monitor_rotated=" . ($monRotated?'yes':'no'));

            return ['success' => true, 'data' => [
                'logs_deleted'       => $logsDeleted,
                'monitor_rotated'    => $monRotated,
                'quarantine_deleted' => $qDel,
                'db_pruned'          => $dbPruned,
            ]];
        })() : ['success' => false, 'code' => 405],

        // POST storage/save-settings
        'save-settings' => $method === 'POST' ? (function() use ($body) {
            $allowed = [
                'quarantine_dir', 'log_dir', 'log_retention_days',
                'quarantine_retention_days', 'db_max_waf_events',
                'db_max_security_events', 'db_max_cron_log', 'monitor_log_max_mb',
            ];
            foreach ($allowed as $key) {
                if (!array_key_exists($key, $body)) continue;
                $val = trim((string)$body[$key]);
                if (in_array($key, ['quarantine_dir', 'log_dir']) && $val !== '') {
                    if (!str_starts_with($val, '/'))
                        return ['success' => false, 'error' => "$key must be an absolute path", 'code' => 400];
                    if (!is_dir($val) && !@mkdir($val, 0750, true))
                        return ['success' => false, 'error' => "Cannot create directory: $val", 'code' => 400];
                }
                Database::setSetting($key, $val);
            }
            return ['success' => true];
        })() : ['success' => false, 'code' => 405],

        default => ['success' => false, 'error' => 'Not found', 'code' => 404],
    };
}

// ════════════════════════════════════════════════════════════════════════════
// Bot Shield
// ════════════════════════════════════════════════════════════════════════════
function routeBotShield(string $action, string $method, array $body, array $q, ?array $user): array {
    $bs = new BotShield();
    return match($action) {
        'stats'           => ['success' => true, 'data' => $bs->getStats()],
        'events'          => ['success' => true, 'data' => $bs->getBotEvents((int)($q['limit'] ?? 100))],
        'blocked'         => ['success' => true, 'data' => $bs->getBlockedBots()],
        'whitelist'       => $method === 'GET'
            ? ['success' => true, 'data' => $bs->getWhitelistedBots()]
            : ['success' => $bs->addWhitelist($body['pattern'] ?? '', $body['note'] ?? '')],
        'remove-whitelist'=> $method === 'POST'
            ? ['success' => $bs->removeWhitelist((int)($body['id'] ?? 0))]
            : ['success' => false, 'code' => 405],
        'block'           => $method === 'POST'
            ? ['success' => $bs->blockBot($body['ip'] ?? '', $body['ua'] ?? '', $body['reason'] ?? 'Manual')]
            : ['success' => false, 'code' => 405],
        'unblock'         => $method === 'POST'
            ? ['success' => $bs->unblockBot($body['ip'] ?? '')]
            : ['success' => false, 'code' => 405],
        'scan', 'analyze' => $method === 'POST'
            ? ['success' => true, 'data' => $bs->runAnalysis()]
            : ['success' => false, 'code' => 405],
        default           => ['success' => false, 'error' => 'Not found', 'code' => 404],
    };
}

// ════════════════════════════════════════════════════════════════════════════
// CMS Guard
// ════════════════════════════════════════════════════════════════════════════
function routeCMSGuard(string $action, string $method, array $body, array $q, ?array $user): array {
    $cg = new CMSGuard();
    return match($action) {
        'stats'    => ['success' => true, 'data' => $cg->getStats()],
        'installs' => ['success' => true, 'data' => $cg->getInstalls()],
        'scan'     => $method === 'POST'
            ? ['success' => true, 'data' => $cg->runScan()]
            : ['success' => false, 'code' => 405],
        'check'    => $method === 'POST'
            ? ['success' => true, 'data' => $cg->checkInstall((int)($body['id'] ?? 0))]
            : ['success' => false, 'code' => 405],
        default    => ['success' => false, 'error' => 'Not found', 'code' => 404],
    };
}

// ════════════════════════════════════════════════════════════════════════════
// Rootkit Scanner
// ════════════════════════════════════════════════════════════════════════════
function routeRootkit(string $action, string $method, array $body, array $q, ?string $id, ?array $user): array {
    $rk = new RootkitScanner();
    return match($action) {
        'status'   => ['success' => true, 'data' => $rk->getStatus()],
        'scans'    => ['success' => true, 'data' => $rk->getScans((int)($q['limit'] ?? 10))],
        'findings' => ['success' => true, 'data' => $rk->getFindings((int)($id ?? 0))],
        'scan'     => $method === 'POST'
            ? ['success' => true, 'data' => $rk->runScan($body['tool'] ?? 'rkhunter')]
            : ['success' => false, 'code' => 405],
        default    => ['success' => false, 'error' => 'Not found', 'code' => 404],
    };
}

// ════════════════════════════════════════════════════════════════════════════
// File Integrity
// ════════════════════════════════════════════════════════════════════════════
function routeIntegrity(string $action, string $method, array $body, array $q, ?string $id, ?array $user): array {
    $fi = new FileIntegrity();
    return match($action) {
        'stats'      => ['success' => true, 'data' => $fi->getStats()],
        'baselines'  => ['success' => true, 'data' => $fi->getBaselines()],
        'changes'    => ['success' => true, 'data' => $fi->getChanges($q['status'] ?? '')],
        'paths'      => ['success' => true, 'data' => $fi->getWatchedPaths()],
        'baseline'   => $method === 'POST'
            ? ['success' => true, 'data' => $fi->createBaseline($body['path'] ?? '/home')]
            : ['success' => false, 'code' => 405],
        'check'      => $method === 'POST'
            ? ['success' => true, 'data' => $fi->runCheck($body['path'] ?? '')]
            : ['success' => false, 'code' => 405],
        'reset'      => $method === 'POST'
            ? ['success' => $fi->resetBaseline($body['path'] ?? '')]
            : ['success' => false, 'code' => 405],
        'acknowledge'=> $method === 'POST'
            ? ['success' => $fi->acknowledgeChange((int)($body['id'] ?? 0))]
            : ['success' => false, 'code' => 405],
        default      => ['success' => false, 'error' => 'Not found', 'code' => 404],
    };
}

// ════════════════════════════════════════════════════════════════════════════
// PHP Hardening
// ════════════════════════════════════════════════════════════════════════════
function routePHPHard(string $action, string $method, array $body, array $q, ?array $user): array {
    $ph = new PHPHardening();
    return match($action) {
        'stats'            => ['success' => true, 'data' => $ph->getStats()],
        'settings'         => ['success' => true, 'data' => $ph->getCurrentSettings()],
        'recommendations'  => ['success' => true, 'data' => $ph->getRecommendations()],
        'accounts'         => ['success' => true, 'data' => $ph->getCpanelAccounts()],
        'account-settings' => ['success' => true, 'data' => $ph->getAccountPHPSettings($q['account'] ?? '')],
        'apply'            => $method === 'POST'
            ? ['success' => true, 'data' => $ph->applyHardening($body['settings'] ?? [])]
            : ['success' => false, 'code' => 405],
        'apply-account'    => $method === 'POST'
            ? ['success' => true, 'data' => $ph->applyAccountHardening($body['account'] ?? '', $body['settings'] ?? [])]
            : ['success' => false, 'code' => 405],
        default            => ['success' => false, 'error' => 'Not found', 'code' => 404],
    };
}

function routeUpdate(string $action, string $method, ?array $user): array {
    Auth::requireRole('admin', $user);
    return match($action) {
        // Return cached update status (no network call — fast)
        'status' => ['success' => true, 'data' => UpdateChecker::getCachedStatus()],

        // Force an immediate live check against GitHub
        'check'  => $method === 'POST'
            ? ['success' => true, 'data' => UpdateChecker::checkForUpdates()]
            : ['success' => false, 'code' => 405],

        default  => ['success' => false, 'error' => 'Not found', 'code' => 404],
    };
}
