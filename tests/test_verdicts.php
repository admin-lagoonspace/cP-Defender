<?php
/**
 * Not-malware verdicts.
 *
 * The feature exists because the scanner reported five HIGH findings against
 * /opt/ai-bolit/ -- Imunify360's own engine, shipped by CloudLinux. The
 * signatures were right (a malware scanner contains the patterns it hunts for)
 * and the product was still wrong, and the only remedy on offer was a path
 * exclusion: a permanent blind spot over a directory an attacker can write to.
 *
 * So the property these tests exist to defend is not "clearing a file silences
 * it". It is the opposite one:
 *
 *      A CLEARED FILE WHOSE BYTES CHANGE IS REPORTED AGAIN.
 *
 * If that ever stops holding, this feature has quietly become an exclusion and
 * the operator has a blind spot they were explicitly promised they did not
 * have. Every other test here is secondary to that.
 */

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/assert.php';

$sandbox = sys_get_temp_dir() . '/sg-verdict-' . getmypid() . '-' . mt_rand(1000, 9999);
@mkdir($sandbox, 0700, true);

register_shutdown_function(function () use ($sandbox) {
    foreach (glob($sandbox . '/*') ?: [] as $f) { @unlink($f); }
    @rmdir($sandbox);
});

/** A file plus a threat row pointing at it, as a scan would leave them. */
function mkFinding(string $sandbox, string $name, string $body,
                   string $threat = 'SG.RT.eval_base64'): array {
    $path = $sandbox . '/' . $name;
    file_put_contents($path, $body);
    $id = Database::insert('threats', [
        'file_path'   => $path,
        'threat_name' => $threat,
        'threat_type' => 'realtime_detection',
        'severity'    => 'high',
        'status'      => 'active',
    ]);
    return [$id, $path];
}

// ── The core promise ────────────────────────────────────────────────────────

// A real one: ai-bolit genuinely contains this, which is why it was flagged.
$benign = "<?php\n// Revisium PROCUREOR\n\$x = eval(base64_decode(\$sig));\n";

[$id, $path] = mkFinding($sandbox, 'procu2.php', $benign);

$r = Verdicts::clearThreat($id, 'Imunify360 engine', 'rohan');
t_ok(!empty($r['success']), 'a finding with a readable file can be cleared');
t_eq(hash('sha256', $benign), $r['sha256'] ?? '',
     'the verdict records the hash of the bytes actually on disk');

t_ok(Verdicts::isCleared($path, hash('sha256', $benign)),
     'those exact bytes at that exact path are cleared');

// THE test. One byte changes and the clearance must not carry over.
$backdoored = $benign . "\n@eval(\$_POST['c']);\n";
file_put_contents($path, $backdoored);

t_ok(!Verdicts::isCleared($path, hash('sha256', $backdoored)),
     'THE POINT: a cleared file that is modified is NOT cleared any more');

// And it genuinely reaches the gate, not just the predicate.
$again = ThreatStore::record([
    'file_path'   => $path,
    'threat_name' => 'SG.PHP.eval_post',
    'severity'    => 'critical',
    'status'      => 'active',
]);
t_ok($again !== null,
     'the modified file is recorded as a threat again by ThreatStore');

// Put the cleared bytes back: the verdict is still valid for them.
file_put_contents($path, $benign);
t_ok(ThreatStore::record([
        'file_path'   => $path,
        'threat_name' => 'SG.RT.eval_base64',
        'severity'    => 'high',
        'status'      => 'active',
     ]) === null,
     'restoring the cleared bytes suppresses the report again');

// ── The gate must not be bypassable by omission ─────────────────────────────

// A writer that forgets to pass a hash must not thereby escape the verdict --
// that would make the rule depend on every caller remembering it, which is the
// failure mode this gate exists to remove.
t_ok(ThreatStore::record([
        'file_path'   => $path,
        'threat_name' => 'SG.NO.hash.supplied',
        'severity'    => 'high',
        'status'      => 'active',
     ]) === null,
     'a caller that supplies no hash still gets the verdict applied');

// ── A verdict is not a path rule ────────────────────────────────────────────

$other = $sandbox . '/elsewhere.php';
file_put_contents($other, $benign);
t_ok(!Verdicts::isCleared($other, hash('sha256', $benign)),
     'the SAME bytes at a DIFFERENT path are not cleared');

// And the path itself is not excluded from scanning.
t_ok(!Heuristics::isExcluded($path),
     'clearing a file does NOT add a scan exclusion for it');

// ── Refusals ────────────────────────────────────────────────────────────────

t_ok(!Verdicts::isCleared($path, null),
     'a null hash is never cleared');
t_ok(!Verdicts::isCleared($path, ''),
     'an empty hash is never cleared');
t_ok(!Verdicts::isCleared($path, 'not-a-sha256'),
     'a malformed hash is never cleared');
t_ok(!Verdicts::isCleared($path, substr(hash('sha256', $benign), 0, 32)),
     'a truncated hash is never cleared');

// A file that is gone cannot be cleared: a verdict with no bytes behind it
// would match whatever appeared at that path later, which is an exclusion.
[$goneId, $gonePath] = mkFinding($sandbox, 'vanished.php', $benign);
unlink($gonePath);
$r = Verdicts::clearThreat($goneId);
t_ok(empty($r['success']), 'a missing file cannot be cleared');
t_contains(strtolower($r['error'] ?? ''), 'gone from disk',
           'and the refusal says why');

t_ok(empty(Verdicts::clearThreat(999999)['success']),
     'clearing a finding that does not exist fails rather than inventing one');

// ── Bookkeeping ─────────────────────────────────────────────────────────────

$t = Database::fetchOne('SELECT * FROM threats WHERE id = ?', [$id]);
t_eq('not_malware', $t['status'] ?? '',
     'the finding is resolved as not_malware, not deleted');
t_ok(!empty($t['resolved_at']), 'and carries a resolved timestamp');

// Clicking twice is a no-op, not a duplicate or an error. Two operators can
// reach the same conclusion about the same file.
$before = count(Verdicts::listAll());
[$id2, ] = mkFinding($sandbox, 'procu2.php', $benign, 'SG.RT.eval_base64');
$r2 = Verdicts::clearThreat($id2, '', 'someone-else');
t_ok(!empty($r2['success']), 'the same file can be cleared twice');
t_eq($before, count(Verdicts::listAll()),
     'but a second clearance of identical bytes adds no second verdict row');

// ── Drift is visible ────────────────────────────────────────────────────────
//
// A lapsed verdict looks identical to a live one in a plain list of paths, and
// an operator who cannot tell them apart cannot audit this at all.
file_put_contents($path, $backdoored);
$rows = array_values(array_filter(Verdicts::listAll(),
                                  fn($v) => $v['file_path'] === $path));
t_ok(!empty($rows), 'the verdict is listed');
t_ok(!empty($rows[0]['drifted']),
     'and is reported as lapsed once the file no longer matches');

// ── Revoking ────────────────────────────────────────────────────────────────

file_put_contents($path, $benign);
$vid = (int) $rows[0]['id'];
t_ok(!empty(Verdicts::revoke($vid)['success']), 'a verdict can be withdrawn');
t_ok(!Verdicts::isCleared($path, hash('sha256', $benign)),
     'after withdrawal the file is reportable again');
t_ok(ThreatStore::record([
        'file_path'   => $path,
        'threat_name' => 'SG.RT.eval_base64',
        'severity'    => 'high',
        'status'      => 'active',
     ]) !== null,
     'and the gate records it once more');

t_ok(empty(Verdicts::revoke(999999)['success']),
     'withdrawing a verdict that does not exist fails cleanly');

