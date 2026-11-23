<?php
/**
 * SHAKAAL PROBE — the refusal card states a job is in progress. Is it?
 * The refusal is only cleared when a SCHEDULED scan starts, so on a server
 * whose scan_schedule is 'off' nothing ever clears it.
 */
$BASE = '/usr/local/serverscrub/backend';
require_once $BASE . '/config/config.php';
require_once $BASE . '/lib/Database.php';
require_once $BASE . '/lib/Logger.php';
require_once $BASE . '/lib/Heuristics.php';
require_once $BASE . '/lib/Scanner.php';
function out($s) { echo $s . PHP_EOL; }

out('in-progress rows right now : ' . count(Database::fetchAll(
  "SELECT id FROM scan_jobs WHERE status IN ('running','pending','cancelling')")));
out('does job 12467 exist at all: ' . (Database::fetchOne(
  'SELECT id FROM scan_jobs WHERE id=12467') ? 'yes' : 'NO'));
$r = Scanner::scheduleRefusal();
out('');
out('what the Scanner page is told:');
out('  reason   : ' . $r['reason']);
out('  job      : ' . $r['job']);
out('  job_age  : ' . $r['job_age'] . 's = ' . round($r['job_age'] / 3600, 1) . 'h');
out('');
// A reconcile pass is what closed that job out. Does it clear the claim?
Scanner::reapStaleJobs();
$r2 = Scanner::scheduleRefusal();
out('after a reconcile pass, the claim is still there: '
    . ($r2 === null ? 'no' : 'YES, job ' . $r2['job']
       . ' still reported in progress for ' . round($r2['job_age'] / 3600, 1) . 'h'));
sleep(3);
$r3 = Scanner::scheduleRefusal();
out('and the age keeps growing: ' . $r3['job_age'] . 's (was ' . $r['job_age'] . 's)');
out('');
out('scan_schedule on this server: ' . Database::setting('scan_schedule'));
out('clearScheduleRefusal() is reached only from the scheduled scan task,');
out('so with scan_schedule=off the card never clears.');
