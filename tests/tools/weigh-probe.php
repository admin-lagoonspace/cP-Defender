<?php
/* Shakaal — the identicality verdict, at the shapes a real incident has.
 * conclusive, distinct, top-group  =>  verdict */
require_once __DIR__ . '/../assert.php';
$ctx = require __DIR__ . '/../bootstrap.php';
require_once $ctx['repo'] . '/backend/lib/MassDetection.php';

$cases = [
  ['10 Nov FP: 500 changelogs, all different',            500, 500, 1],
  ['30 Apr: 500 byte-identical ransom notes',             500,   1, 500],
  ['30 Apr + 2 stray different files',                    500,   3, 498],
  ['ransom note personalised PER ACCOUNT (118 accounts)', 500, 118, 5],
  ['ransom note personalised PER ACCOUNT (4 accounts)',   600,   4, 150],
  ['ransom note with a trailing counter (all distinct)',  500, 500, 1],
  ['half identical, half varied',                         500, 251, 250],
  ['only 7 files had a recorded hash',                      7,   1, 7],
  ['no hashes at all',                                      0,   0, 0],
];
foreach ($cases as $c) {
    printf("%-55s conclusive=%-4d distinct=%-4d top=%-4d => %s\n",
        $c[0], $c[1], $c[2], $c[3], MassDetection::weigh($c[1], $c[2], $c[3]));
}
