<?php
/**
 * The faults reported from a production install, asserted at their source.
 *
 * Every one of these was either invisible to the test suite or actively
 * reported as working, so each assertion here names the symptom it prevents.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

/**
 * JavaScript with its comments removed.
 *
 * t_code() runs PHP's tokenizer, which does not understand a .js file, and
 * these assertions must read code: app.js explains each fix by quoting the
 * broken expression it replaced, so an unstripped search finds the bug in the
 * comment describing its own fix and reports it as still present.
 */
function sg_js(string $path): string
{
    $src  = file_get_contents($path);
    $bs   = chr(92);
    $nl   = chr(10);
    $out  = '';
    $n    = strlen($src);

    for ($i = 0; $i < $n; $i++) {
        $c = $src[$i];

        // Skip string literals whole, so a // inside a URL is not taken for a
        // comment and does not swallow the rest of the line.
        if ($c === '"' || $c === "'" || $c === chr(96)) {
            $q    = $c;
            $out .= $c;
            for ($i++; $i < $n; $i++) {
                $out .= $src[$i];
                if ($src[$i] === $bs) {
                    $i++;
                    if ($i < $n) { $out .= $src[$i]; }
                    continue;
                }
                if ($src[$i] === $q) { break; }
            }
            continue;
        }

        if ($c === '/' && $i + 1 < $n && $src[$i + 1] === '/') {
            while ($i < $n && $src[$i] !== $nl) { $i++; }
            $out .= $nl;
            continue;
        }

        if ($c === '/' && $i + 1 < $n && $src[$i + 1] === '*') {
            $end = strpos($src, '*/', $i + 2);
            $i   = $end === false ? $n : $end + 1;
            continue;
        }

        $out .= $c;
    }

    return $out;
}

$html  = file_get_contents($repo . '/frontend/index.html');
$js    = sg_js($repo . '/frontend/js/app.js');
$api   = t_code($repo . '/backend/api/index.php');
$sched = t_code($repo . '/backend/cron/scheduler.php');
$fw    = t_code($repo . '/backend/lib/Firewall.php');

// -- 1. Log Analyzer: a nav entry with no page behind it ----------------------
// "Log scanner UI is not working at all its giving blank window."
// The sidebar carried data-page="logs" and nothing else existed: no
// #page-logs, and no case in showPage(). Clicking it hid the current page and
// showed nothing.
preg_match_all('/data-page="([a-z-]+)"/', $html, $m);
$navPages = array_values(array_unique($m[1]));

preg_match_all('/id="page-([a-z-]+)"/', $html, $m2);
$sections = array_values(array_unique($m2[1]));

$orphans = array_values(array_diff($navPages, $sections));
t_eq(0, count($orphans), 'every sidebar entry has a page section'
    . ($orphans ? ' -- orphaned: ' . implode(', ', $orphans) : ''));

$unreachable = array_values(array_diff($sections, $navPages));
t_eq(0, count($unreachable), 'every page section is reachable from the sidebar'
    . ($unreachable ? ' -- unreachable: ' . implode(', ', $unreachable) : ''));

t_contains($html, 'id="page-logs"', 'the Log Analyzer page exists');
t_contains($js, "case 'logs':", 'showPage() loads the Log Analyzer');
t_contains($js, 'function loadLogs', 'loadLogs is implemented');
t_contains($api, "'days'",  'logs/days is routed');
t_contains($api, "'query'", 'logs/query is routed');

// -- 2. Scanner settings had no save control ---------------------------------
// "when i update scanning schedule to new one, there is no button to click"
// The only save button lived in a different card further up the page.
t_contains($html, 'saveScannerSettings()', 'the Scanner card has its own save button');
t_contains($js, 'function saveScannerSettings', 'and it is implemented');
t_contains($js, 'await loadSettings();',
    'the save re-reads settings so the change is visibly applied');

$savePos  = strpos($html, 'saveScannerSettings()');
$schedPos = strpos($html, 'id="set-scan-schedule"');
t_ok($schedPos !== false && $savePos !== false && $schedPos < $savePos,
    'the save button sits below the schedule fields it saves');

// -- 3. IP reputation never checked the server's own addresses ---------------
// The scheduled job re-checks addresses that ATTACKED the server; the UI only
// pre-filled the first server IP into a manual lookup box.
t_contains($api,  "'check-server-ips'", 'every server IP can be checked at once');
t_contains($js,   'function checkAllServerIps', 'the UI can trigger it');
t_contains($html, 'checkAllServerIps()', 'and offers a button for it');
t_contains($sched, 'BlocklistRegistry::serverIps',
    'the scheduled job now checks the server addresses too');
t_contains($sched, "require_once SG_ROOT . '/backend/lib/BlocklistRegistry.php'",
    'and requires the class it calls, or cron fatals at 03:00');

// -- 4. File integrity reported nothing back ---------------------------------
// Detection worked; the values the UI and scheduler read did not exist, so a
// check said "0 changes" however much it had found.
$fi = t_code($repo . '/backend/lib/FileIntegrity.php');
t_contains($fi, "'changed'", 'runCheck returns a change count');
t_contains($fi, "'files'",   'createBaseline returns a file count');
t_ok(strpos($js, 'd.modified||0) + (d.new_files||0)') === false,
    'the UI no longer adds arrays together as if they were counts');

// -- 6. The firewall page was slow for three avoidable reasons ---------------
t_contains($fw, '-L INPUT -n', 'iptables is listed numerically, with no reverse DNS');
t_ok(strpos($fw, "CSF_BIN . ' -l 2>&1 | head -5'") === false,
    'the csf -l call whose output was discarded is gone');
t_contains($fw, 'static $cached', 'the CSF version is not re-forked on every call');

// -- 7. Security events: bulk resolve, and a resolve that reports honestly ---
t_contains($api,  "'resolve-bulk'", 'events can be resolved in bulk');
t_contains($api,  "'resolve-all'",  'and all at once');
t_contains($js,   'function bulkResolveEvents', 'the UI implements bulk resolve');
t_contains($html, 'id="event-bulk-bar"', 'the events page has a bulk bar');
t_contains($html, 'toggleAllEvents(this)', 'with a select-all checkbox');

// The bar must be above the table it acts on, and outside the table element --
// the same mistake put the scanner bulk bar inside the dashboard events table.
$barPos  = strpos($html, 'id="event-bulk-bar"');
$bodyPos = strpos($html, 'id="events-body"');
t_ok($barPos !== false && $bodyPos !== false && $barPos < $bodyPos,
    'the bulk bar sits directly above the events table');
t_contains($html, '<div id="event-bulk-bar"', 'it is a div, not a child of <table>');

// A resolve that matched no row used to return success:true regardless.
t_contains($api, 'was not found', 'resolving a missing event is reported as a failure');

// Attacker-supplied fields must be escaped: they come from the requests of
// whoever attacked the server, rendered into the operator's page.
t_contains($js, 'esc(e.type)',      'event type is escaped');
t_contains($js, 'esc(e.source_ip)', 'event source IP is escaped');
t_contains($js, 'esc(e.target)',    'event target is escaped');
t_contains($js, 'const cols = full ? 8 : 6',
    'the empty-state colspan matches the column count');

// -- 8. Quarantine path: visible, testable, off the root partition ----------
t_contains($api, "'quarantine-usage'", 'the current quarantine location is readable');
t_contains($api, "'quarantine-check'", 'the location can be tested for read/write');
t_contains($api, "'quarantine-move'",  'and relocated');
t_contains($api, 'file_put_contents($probe',
    'the write test actually writes rather than trusting is_writable()');
t_contains($html, 'id="set-quar-dir"', 'the settings page exposes the path');
t_ok(strpos($html, '<code>/usr/local/sentinel-gate/quarantine</code>') === false,
    'the settings page no longer names the root-partition path as fact');

$cfg = t_code($repo . '/backend/config/config.php');
t_contains($cfg, "'/home'", 'the compiled default prefers /home');

// -- 9. Rootkit schedule: reachable, and only offering intervals that run ----
t_contains($html, 'id="set-rootkit-schedule"', 'the rootkit schedule is settable');
t_contains($js,   'rootkit_schedule:', 'and is submitted with the scanner settings');
t_contains($sched, 'rootkit_last_run', 'the scheduled run records when it ran');

// isDue() implements off/hourly/daily/weekly. Anything else saves cleanly and
// then never fires -- a setting that is only a piece in a settings page.
$sel = substr($html, strpos($html, 'id="set-rootkit-schedule"'), 500);
preg_match_all('/<option value="([a-z]+)"/', $sel, $opts);
$bogus = array_values(array_diff($opts[1], ['off', 'hourly', 'daily', 'weekly']));
t_eq(0, count($bogus), 'every rootkit interval offered is one the scheduler implements'
    . ($bogus ? ' -- unsupported: ' . implode(', ', $bogus) : ''));

// -- 10. The plugin users and resellers see follows the server version ------
$install = file_get_contents($repo . '/install.sh');
$update  = file_get_contents($repo . '/update.sh');
t_contains($install, 'cp -rf "${INSTALL_DIR}/frontend/."',
    'the WHM UI copy is refreshed from the installed frontend');
t_contains($update, '--register-only',
    'an update re-runs registration, which republishes that copy');
// The cPanel user page used to be a redirect to the WHM dashboard, which a
// cPanel user cannot authenticate to. It is now a real page shipped from the
// repo, so what matters is that the installer copies the current one on every
// registration -- including the --register-only pass an update performs.
t_contains($install, 'cpanel/sentinel_gate/index.php',
    'the cPanel user page is copied from the package on every registration');
