<?php
/* Shakaal — the exact operator-facing text per verdict, and whether the
 * suppress command is COMPOSED (pasteable) or merely NAMED. */
require_once __DIR__ . '/../assert.php';
$ctx = require __DIR__ . '/../bootstrap.php';
require_once $ctx['repo'] . '/backend/lib/MassDetection.php';

$SIG = '{HEX}linux.ransom.sessionscribe.qtox.toxid.171.UNOFFICIAL';
Database::setSetting(MassDetection::SETTING_MAX, '500');

$shapes = [
  'mass-identical (30 Apr: 1 distinct)' => function ($i) { return 'same'; },
  'varied-content (10 Nov: all distinct)' => function ($i) { return 'c' . $i; },
  'undetermined (thin per-victim)'      => function ($i) { return 'v' . ($i % 118); },
];

foreach ($shapes as $label => $content) {
    $job = Database::insert('scan_jobs', ['scan_type'=>'full','status'=>'running',
      'started_at'=>time(),'files_scanned'=>400000,'threats_found'=>0,
      'scan_path'=>'/home','requested_by'=>'@schedule']);
    for ($i = 0; $i < 600; $i++) {
        $v = 'acct' . ($i % 118);
        Database::insert('threats', ['scan_job_id'=>$job,
          'file_path'=>'/home/'.$v.'/d'.$i.'/README.md', 'threat_name'=>$SIG,
          'threat_type'=>'malware','severity'=>'critical','status'=>'active',
          'hash'=>hash('sha256', $content($i)), 'size'=>1400,
          'detected_at'=>time(),'cpanel_user'=>$v]);
    }
    MassDetection::reset();
    $r = MassDetection::allow($job, $SIG);
    $ev = Database::fetchOne("SELECT description FROM security_events "
        . "WHERE type='mass_detection' ORDER BY id DESC LIMIT 1");
    $alarm = (string) ($ev['description'] ?? '');
    $composed = 'signatures suppress add ' . $SIG;

    echo "\n════════ $label ════════\n";
    echo "verdict: " . $r['verdict'] . "\n";
    echo "COMPOSED pasteable suppress command in alarm? "
       . (strpos($alarm, $composed) !== false ? '*** YES ***' : 'no') . "\n";
    echo "says 'do NOT suppress'? "
       . (stripos($alarm, 'do NOT suppress') !== false ? 'yes' : 'no') . "\n";
    echo "names scan mass-bound? "
       . (stripos($alarm, 'mass-bound') !== false ? 'yes' : 'no') . "\n";
    echo "--- alarm ---\n" . wordwrap($alarm, 76) . "\n";
}
