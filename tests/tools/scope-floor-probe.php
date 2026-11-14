<?php
/* Shakaal — where the restore scope floor actually sits, per combination. */
require_once __DIR__ . '/../assert.php';
$ctx = require __DIR__ . '/../bootstrap.php';
require_once $ctx['repo'] . '/backend/lib/QuarantineRestore.php';

$cases = [
  'nothing at all'                      => [],
  "--signature='*'"                     => ['signature' => '*'],
  "--signature='{HEX}*'"                 => ['signature' => '{HEX}*'],
  "--signature='{HEX}php*' (9 chars)"    => ['signature' => '{HEX}php*'],
  "--signature='{HEX}ph*' (8 chars)"     => ['signature' => '{HEX}ph*'],
  "--signature='{HEX}p*' (7 chars)"      => ['signature' => '{HEX}p*'],
  '--signature=<full name> exact'        => ['signature' => '{HEX}php.cmdshell.gifheader.400.UNOFFICIAL'],
  '--signature=<family>* ALONE'          => ['signature' => '{HEX}php.cmdshell.gifheader*'],
  '--ext=md ALONE'                       => ['ext' => 'md'],
  '--ext=tar,gz,zip ALONE'               => ['ext' => 'tar,gz,zip'],
  '--job=12457 alone'                    => ['job' => '12457'],
  '--account=victim alone'               => ['account' => 'victim'],
  '--id=1,2,3 alone'                     => ['id' => '1,2,3'],
  '--path=/abs/file alone'               => ['path' => '/home/a/b.php'],
  '--ext=md + --job=12457'               => ['ext' => 'md', 'job' => '12457'],
  '--signature=* + --job=12457'          => ['signature' => '*', 'job' => '12457'],
  '--signature=<family>* + --job'        => ['signature' => '{HEX}php.cmdshell.gifheader*', 'job' => '12457'],
];
foreach ($cases as $label => $scope) {
    $r = QuarantineRestore::selector($scope);
    $verdict = isset($r['error']) ? 'REFUSED' : 'ALLOWED';
    printf("  %-38s %s\n", $label, $verdict);
}
echo "\n--- the refusal text for a broad-matcher-only scope ---\n";
$e = QuarantineRestore::selector(['ext' => 'md']);
echo wordwrap((string) $e['error'], 76) . "\n";
