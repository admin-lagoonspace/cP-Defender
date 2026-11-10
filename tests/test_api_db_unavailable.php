<?php
/**
 * A database that cannot be opened must be a sentence, not a stack trace.
 *
 * Every API route, on a host where the database file cannot be opened,
 * answered with this as the HTTP body:
 *
 *     PHP Fatal error:  Uncaught PDOException: SQLSTATE[HY000]: General error:
 *     14 unable to open database file in /opt/serverscrub-src/backend/lib/Database.php:851
 *     Stack trace:
 *     #0 /opt/serverscrub-src/backend/lib/Database.php(851): PDO->prepare()
 *     #3 /opt/serverscrub-src/backend/lib/License.php(591): Database::setting()
 *
 * The throw came from the licence check during bootstrap — before the handler
 * that produces the JSON envelope. So the client, which expects JSON, showed
 * its generic "Server error — please try again": the entire class of failure
 * that envelope exists to prevent. And the response disclosed absolute
 * filesystem paths and the internal call graph to whoever reached the URL.
 *
 * This is not a hypothetical configuration. install.sh makes the database
 * directory 0700 and root-owned on purpose, so a panel running as anything
 * other than root hits exactly this, on every route, with no usable message.
 */

require_once __DIR__ . '/assert.php';
$ctx     = require __DIR__ . '/bootstrap.php';
$repo    = $ctx['repo'];
$sandbox = $ctx['sandbox'];

/*
 * An unopenable database, portably: a FILE where the database DIRECTORY should
 * be. Database::get() does `if (!is_dir($dir)) mkdir($dir)`, which fails, and
 * then `new PDO("sqlite:...")` cannot create the file — "unable to open
 * database file", the same SQLSTATE[HY000] 14 as the permission case, and it
 * does not need a second user account to reproduce.
 */
$blocked = $sandbox . '/blocked';
file_put_contents($blocked, "not a directory\n");
$deadDb = $blocked . '/serverscrub.db';

/**
 * The RAW response body of one request — every byte of stdout, not the JSON
 * part of it.
 *
 * stdout ONLY, deliberately. PHP writes warnings and the error log to stderr
 * when it cannot open its configured log file, and under a web server that
 * goes to the server's error log, not to the client. Folding stderr into the
 * capture here would test the harness rather than the response: the question
 * is what the BROWSER receives.
 */
function raw_route(string $route, string $root, string $db): string
{
    $repo   = dirname(__DIR__);
    $runner = sys_get_temp_dir() . '/sg-dbdown-' . getmypid() . '-' . mt_rand(100, 999) . '.php';
    $payload = '<?php' . "\n"
        . 'define("SG_ROOT", ' . var_export($root, true) . ');' . "\n"
        . 'define("SG_DB", ' . var_export($db, true) . ');' . "\n"
        . 'define("SG_INSTALL_MARKER", ' . var_export($root . '/installed-at', true) . ');' . "\n"
        . '$_SERVER["REQUEST_METHOD"]="GET";' . "\n"
        . '$_SERVER["REMOTE_USER"]="root";' . "\n"
        . '$_SERVER["REMOTE_ADDR"]="127.0.0.1";' . "\n"
        . '$_SERVER["REQUEST_URI"]="/cgi/serverscrub/serverscrub.cgi";' . "\n"
        . '$_GET=' . var_export(['r' => $route], true) . ';' . "\n"
        . 'require ' . var_export($repo . '/backend/api/index.php', true) . ';' . "\n";
    file_put_contents($runner, $payload);
    $errFile = $runner . '.err';
    $out = (string) shell_exec(escapeshellarg(PHP_BINARY) . ' '
                               . escapeshellarg($runner) . ' 2> ' . escapeshellarg($errFile));
    @unlink($runner);
    @unlink($errFile);
    return $out;
}

// ── Every route answers in JSON, and only JSON ─────────────────────────────

foreach (['settings/get', 'events/list', 'dashboard/stats'] as $route) {
    $out  = raw_route($route, $sandbox, $deadDb);
    $json = json_decode(trim($out), true);

    t_ok(is_array($json),
         $route . ': THE WHOLE RESPONSE IS JSON, with nothing in front of it. '
       // The phrase the runner treats as a crash is in this file's docblock,
       // not in an assertion message: printing it here makes the harness
       // report every run of this file as a crash.
       . 'The old body began with an uncaught PDOException and a trace, and the '
       . 'client fell back to "Server error — please try again", which is '
       . 'exactly what the envelope is for. Got: ' . substr(trim($out), 0, 120));

    if (!is_array($json)) { continue; }

    t_ok(($json['success'] ?? true) === false,
         $route . ': and it is reported as a failure');
    t_contains(strtolower((string) ($json['error'] ?? '')), 'database could not be opened',
         $route . ': in words that name the actual problem — "nothing can be '
       . 'read or recorded" is actionable, SQLSTATE[HY000] is not');
    t_eq(503, $json['code'] ?? null,
         $route . ': with a status code that says the server cannot serve this '
       . 'right now, rather than 200 with an error inside it');

    t_ok(strpos($out, 'Stack trace') === false,
         $route . ': NO STACK TRACE in the response. It is a list of absolute '
       . 'paths and internal call sites, in an HTTP body');
    t_ok(strpos($out, $deadDb) === false,
         $route . ': and not the database path either — that belongs in the '
       . 'log, which is where it now goes');
}

// ── auth/status is the exception, and says so ──────────────────────────────
//
// It reads nothing but constants, and it is what the panel polls to find out
// whether the API is alive at all. Refusing it would turn "the panel is
// running and its database is not" -- the most useful sentence an operator can
// be handed here -- into the same 503 as everything else. So it answers, and
// it reports the database state rather than letting "online" stand for the
// whole truth.
$out  = raw_route('auth/status', $sandbox, $deadDb);
$json = json_decode(trim($out), true);
t_ok(is_array($json), 'auth/status still answers in JSON with the database down');
t_ok(($json['success'] ?? false) === true,
     'and still answers at all: it is the liveness probe, and a panel that '
   . 'cannot say "I am up" is indistinguishable from a panel that is down');
t_eq(SG_VERSION, $json['version'] ?? null, 'with the real version');
t_ok(($json['db_available'] ?? null) === false,
     'AND IT SAYS THE DATABASE IS NOT THERE. "status: online" on its own would '
   . 'be a half-truth, which is the whole class of defect this suite exists for');
t_ok(strpos($out, 'Stack trace') === false, 'and no stack trace either');

// ── Database::ready() answers the question rather than throwing it ─────────

$r = Database::ready();
t_ok(!empty($r['ok']),
     'in this process, where the sandbox database is fine, ready() says so');
t_eq(null, $r['error'], 'with no error to report');

$src = t_code($repo . '/backend/lib/Database.php');
$fn  = t_fn_body($src, 'ready', 'php');
t_contains($fn, 'error_log',
     'ready() logs through PHP\'s own log and NOT through Logger: Logger::error '
   . 'writes its row with Database::insert(), so logging a database that '
   . 'cannot be opened would throw from inside the handler for a database '
   . 'that cannot be opened');
t_ok(strpos($fn, 'Logger::') === false,
     'which is to say it does not call Logger at all');

$api = t_code($repo . '/backend/api/index.php');
$gatePos = strpos($api, 'Database::ready()');
$authPos = strpos($api, 'Auth::requireAuth()');
t_ok($gatePos !== false && $authPos !== false && $gatePos < $authPos,
     'the check runs BEFORE the authentication call that used to be the first '
   . 'thing to touch the database — a gate after the throw is not a gate');
t_contains($api, '} catch (Throwable $e) {',
     'and anything else thrown during bootstrap is caught too, since the '
   . 'dispatcher\'s own try/catch starts after the licence gate');
