<?php
/**
 * A real-time detection must be CONTAINED, by the same rules as a scan.
 *
 * Reported: "if any malware is detected in realtime we are not quarantining
 * that malware we are leaving it as is ACtive on the server. Whats the use of
 * it. Apply same logic as malware scanner if critical then delete it
 * otherwise quarantine."
 *
 * The monitor identified the file, wrote a threats row, logged a warning,
 * raised a security event -- and then did this, and only this:
 *
 *     if db_get(conn, 'auto_quarantine') == '1':
 *         quarantine(conn, path, tid)
 *
 * Two defects in two lines.
 *
 *   1. A PLAIN MOVE, WITH NO NOTION OF SEVERITY. Scanner::applyThreatPolicy
 *      deletes anything critical or high -- policy_high_action defaults to
 *      'delete' -- and quarantines the rest with an expiry. Real time never
 *      deleted anything, so the same file was treated differently depending
 *      on which engine happened to find it.
 *
 *   2. WHEN THE GATE WAS NOT '1', NOTHING HAPPENED AT ALL. No quarantine, no
 *      disable, no flag, and no log line saying so. Live malware stayed
 *      executable on a server whose monitor had just named it. A detector
 *      that contains nothing is an alarm, not a defence.
 *
 * It also skipped the mass-detection bound, report-only feeds, the
 * disable-before-acting step, and the owner/mode capture that a restore
 * needs -- every one of which already existed, in the scanner.
 *
 * The fix does not reimplement the policy in Python. It calls the PHP one, so
 * there is exactly one set of rules. These tests cover that route end to end:
 * the CLI that exposes the policy, and the daemon code that calls it.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$cli = t_code($repo . '/backend/cli/serverscrub.php');
$mon = file_get_contents($repo . '/backend/daemon/monitor.py');

// ── The daemon no longer contains anything by itself ───────────────────────
t_ok(strpos($mon, "if db_get(conn,'auto_quarantine') == '1':\n        quarantine(conn, path, tid)") === false,
     'THE TWO LINES ARE GONE: real-time detection no longer decides '
   . 'containment on its own with a bare quarantine behind a bare flag');
t_contains($mon, 'apply_policy(conn, path, tid, sev)',
     'and the detection path calls the shared policy instead');

// ── ONE policy, not two ────────────────────────────────────────────────────
//
// The point of routing through PHP is that a second copy of these rules in
// Python would drift from the first the next time either changed.
t_contains($mon, "'apply-policy', str(tid)",
     'THE DAEMON CALLS THE SCANNER\'S POLICY: it shells out to the CLI '
   . 'rather than carrying its own copy of the rules');
// Mentioning the setting in a comment is fine and useful; READING it would
// mean a second copy of the severity decision, which is the thing to prevent.
t_ok(strpos($mon, "db_get(conn, 'policy_high_action'") === false
  && strpos($mon, "db_get(conn,'policy_high_action'") === false,
     'and does NOT reimplement the severity mapping in Python — the daemon '
   . 'never reads policy_high_action, so that decision has one home, in '
   . 'Scanner::policyDaysFor, and the two cannot drift');
t_ok(strpos($mon, 'MassDetection') === false,
     'nor the mass-detection bound');

// ── The CLI really does invoke the policy ──────────────────────────────────
t_contains($cli, "case 'apply-policy':",
     'the CLI exposes apply-policy');
t_contains($cli, 'applyThreatPolicy(',
     'THE SAME FUNCTION A SCAN USES: apply-policy calls '
   . 'Scanner::applyThreatPolicy, so critical deletes and the rest are '
   . 'quarantined exactly as in a scan');
t_contains($cli, "'SELECT id, file_path, severity, threat_name, scan_job_id FROM threats WHERE id=?'",
     'reading the severity and name from the recorded threat, so the policy '
   . 'sees what the scanner would have seen');
t_contains($cli, "exit((\$r['action'] ?? '') === 'failed' ? 1 : 0);",
     'A DECISION NOT TO ACT IS A SUCCESS: auto-quarantine being off, a bound '
   . 'holding or an unpromoted feed are all policy working correctly. Only a '
   . 'failed action is a non-zero exit, because only that warrants a fallback');

// ── Nothing is ever left silently untouched ────────────────────────────────
//
// The original defect was silence: no containment AND no record of declining.
preg_match('/def apply_policy\(conn, path, tid, sev\):.*?\n\ndef /s', $mon, $m);
$fn = $m[0] ?? '';
t_ok($fn !== '', 'apply_policy() is defined in the daemon');
t_contains($fn, 'LEFT IN PLACE',
     'WHEN A FILE IS LEFT IN PLACE, THE LOG SAYS SO: the original bug was '
   . 'not just inaction, it was silent inaction — nothing distinguished '
   . '"contained" from "ignored"');
t_contains($fn, 'Falling back to plain quarantine',
     'and a policy that cannot be reached falls back to the containment this '
   . 'code always had, rather than leaving a known-malicious file alone');
t_contains($fn, "db_get(conn, 'auto_quarantine') == '1'",
     'the fallback still honours the operator\'s switch — quarantining '
   . 'against an explicit "off" would be acting without consent');

// ── The subprocess call has to work on the oldest supported Python ─────────
t_contains($fn, 'stdout=subprocess.PIPE',
     'PYTHON 3.6: stdout=PIPE rather than capture_output=, which does not '
   . 'exist on the RHEL-family builds cPanel ships');
t_contains($fn, 'universal_newlines=True',
     'and universal_newlines rather than text=, for the same reason');
t_contains($fn, 'timeout=120',
     'and a timeout, so a wedged PHP cannot stall the monitor for ever');

// ── Finding the interpreter ────────────────────────────────────────────────
preg_match('/def _php_binary\(\):.*?\n\ndef /s', $mon, $m2);
$php = $m2[0] ?? '';
t_ok($php !== '', '_php_binary() is defined');
t_contains($php, '/usr/local/cpanel/3rdparty/bin/php',
     'cPanel\'s own PHP is tried first — it is the build the rest of the '
   . 'product runs under, and the daemon starts from cron/systemd with a '
   . 'minimal PATH where a bare `php` may not resolve at all');
t_contains($php, 'os.access(p, os.X_OK)',
     'and the candidate is checked for executability, not just existence');

// ── The policy itself still behaves as described ───────────────────────────
//
// The fix is only worth anything if the thing being called really does delete
// criticals. Pinned here so a change to the policy cannot quietly make the
// real-time promise false.
$sc = t_code($repo . '/backend/lib/Scanner.php');
t_contains($sc, "case 'critical':\n            case 'high':",
     'the policy still treats critical and high together');
t_contains($sc, "(Database::setting('policy_high_action', 'delete') ?? 'delete') === 'delete'\n                    ? 0",
     'CRITICAL MEANS DELETE: policy_high_action defaults to delete and maps '
   . 'to zero days, which is the delete branch');
t_contains($sc, '$r = $this->deleteInfected($filePath, $threatId,',
     'and zero days reaches deleteInfected');
t_contains($sc, '$r = $this->quarantine($filePath, $threatId);',
     'while anything else is quarantined');

$db = t_code($repo . '/backend/lib/Database.php');
t_contains($db, "('policy_high_action',      'delete')",
     'and the shipped default is delete, so a server that has never touched '
   . 'the setting deletes criticals found in real time');
