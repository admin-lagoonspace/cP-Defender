<?php
/* Shakaal — Wasooli's claim: the thin per-victim case "fails safe because it
 * never says suppress". Test the actual operator-facing text, not the verdict. */
require_once __DIR__ . '/../assert.php';
$ctx = require __DIR__ . '/../bootstrap.php';
require_once $ctx['repo'] . '/backend/lib/MassDetection.php';

$SIG = '{HEX}linux.ransom.sessionscribe.qtox.toxid.171.UNOFFICIAL';
Database::setSetting(MassDetection::SETTING_MAX, '500');

/* 500 samples, 118 distinct, ~4 copies each: a note personalised per victim,
 * spread thinly. Wasooli says this reads 'undetermined' and that is safe. */
$job = Database::insert('scan_jobs', ['scan_type'=>'full','status'=>'running',
  'started_at'=>time(),'files_scanned'=>400000,'threats_found'=>0,
  'scan_path'=>'/home','requested_by'=>'@schedule']);
for ($i = 0; $i < 600; $i++) {
    $victim = 'acct' . ($i % 118);
    Database::insert('threats', [
      'scan_job_id'=>$job, 'file_path'=>'/home/'.$victim.'/sub'.$i.'/README.md',
      'threat_name'=>$SIG, 'threat_type'=>'malware','severity'=>'critical',
      'status'=>'active','hash'=>hash('sha256','note-for-'.$victim),
      'size'=>1400,'detected_at'=>time(),'cpanel_user'=>$victim]);
}
MassDetection::reset();
$r = MassDetection::allow($job, $SIG);

echo "verdict: " . $r['verdict'] . "\n";
echo "act:     " . var_export($r['act'], true) . "\n\n";
echo "--- reason shown on the row ---\n" . wordwrap($r['reason'], 78) . "\n\n";
$ev = Database::fetchOne("SELECT severity, description FROM security_events WHERE type='mass_detection' ORDER BY id DESC LIMIT 1");
echo "--- alarm (severity " . ($ev['severity'] ?? '?') . ") ---\n"
   . wordwrap((string)($ev['description'] ?? '(none)'), 78) . "\n\n";

$all = $r['reason'] . ' ' . (string)($ev['description'] ?? '');
echo "CLAIM CHECK: text contains 'suppress'? "
   . (stripos($all, 'suppress') !== false ? "YES" : "no") . "\n";
echo "CLAIM CHECK: text contains 'signatures suppress add'? "
   . (stripos($all, 'signatures suppress add') !== false ? "YES" : "no") . "\n";
echo "CLAIM CHECK: says do NOT suppress?                    "
   . (stripos($all, 'do NOT suppress') !== false ? "YES" : "no") . "\n";
