<?php
/**
 * Quarantine, delete, bulk actions and the file viewer.
 *
 * Reported: "in malware scanner logs, when I see an option for delete or
 * quarantine infected files, both options do not work as there seems to be some
 * issue for accessing files".
 *
 * Two causes, and a third problem found while fixing them:
 *
 *   1. quarantine() used rename(), which cannot cross a filesystem boundary.
 *      On a hosting server /home is routinely a separate volume from
 *      /usr/local, so it failed with EXDEV on exactly the files it exists to
 *      handle.
 *   2. Both routes returned ['success' => bool] and nothing else, so the reason
 *      never reached the user -- hence "there seems to be some issue".
 *   3. deleteThreat() marked the row 'deleted' whether or not unlink()
 *      succeeded. A security product reporting malware removed while it sits on
 *      disk is the worst answer it can give.
 */

require_once __DIR__ . '/assert.php';
$ctx = require __DIR__ . '/bootstrap.php';

$scanner = new Scanner();
$work    = $ctx['sandbox'] . '/victim';
@mkdir($work, 0777, true);

/** Create an infected file and a threat row for it. */
function seed_threat(string $path, string $body = "<?php eval(base64_decode('aGk=')); ?>"): int
{
    @mkdir(dirname($path), 0777, true);
    file_put_contents($path, $body);
    return Database::insert('threats', [
        'file_path'   => $path,
        'threat_name' => 'SG.TEST.sample',
        'threat_type' => 'webshell',
        'severity'    => 'high',
        'status'      => 'active',
        'size'        => filesize($path),
    ]);
}

// ── quarantine() returns a reason, not a bare bool ───────────────────────────
$p1  = $work . '/shell.php';
$id1 = seed_threat($p1);

$r = $scanner->quarantine($p1, $id1);
t_ok(is_array($r), 'quarantine() returns a result array, not a bool');
t_eq(true, $r['success'] ?? false, 'quarantining a readable file succeeds');
t_ok(!file_exists($p1), 'the infected file is gone from its original path');
t_ok(isset($r['dest']) && is_file($r['dest']), 'the file is present in quarantine');

$row = Database::fetchOne("SELECT * FROM threats WHERE id = ?", [$id1]);
t_eq('quarantined', $row['status'], 'the threat row is marked quarantined');
t_ok(is_file($p1 . '.sentinel_removed'), 'a placeholder is left where the file was');

// A missing file must say so rather than failing anonymously.
$missing = $scanner->quarantine($work . '/not-there.php', $id1);
t_eq(false, $missing['success'], 'quarantining a missing file fails');
t_contains($missing['error'], 'no longer on disk', 'and says the file is not there');

// ── The cross-filesystem fallback exists ─────────────────────────────────────
// EXDEV cannot be produced inside one sandbox directory, so the guarantee is
// asserted from the code: rename is tried, and copy+unlink backs it up. Without
// that fallback, quarantine fails on every server where /home is its own volume
// -- which is the reported bug.
$src = t_code(dirname(__DIR__) . '/backend/lib/Scanner.php');
t_contains($src, '@rename($filePath, $dest)', 'rename is attempted first (atomic, cheap)');
t_contains($src, '@copy($filePath, $dest)',   'copy is the cross-device fallback');
t_contains($src, '@unlink($filePath)',        'the original is removed after a successful copy');
t_ok(strpos($src, 'filesize($dest)') !== false,
    'the copy is size-verified before the original is removed');

// ── delete() must not claim success while the file remains ───────────────────
$p2  = $work . '/malware.php';
$id2 = seed_threat($p2);

$d = $scanner->deleteThreat($id2);
t_ok(is_array($d), 'deleteThreat() returns a result array');
t_eq(true, $d['success'] ?? false, 'deleting a writable file succeeds');
t_ok(!file_exists($p2), 'the file is actually gone');
t_eq('deleted', Database::fetchOne("SELECT status FROM threats WHERE id=?", [$id2])['status'],
    'the row is marked deleted');

// Deleting something already gone is a success, but says so.
$again = $scanner->deleteThreat($id2);
t_eq(true, $again['success'], 'deleting an already-absent file is not an error');
t_contains($again['note'] ?? '', 'already gone', 'and it says the file was already gone');

$nope = $scanner->deleteThreat(999999);
t_eq(false, $nope['success'], 'deleting an unknown threat fails');
t_contains($nope['error'], 'not found', 'and says it was not found');

// The regression itself: the status update must be reachable only after unlink.
$deletePos = strpos($src, 'public function deleteThreat');
$body      = substr($src, $deletePos, 2200);
$unlinkPos = strpos($body, 'if (!@unlink($path))');
$updatePos = strrpos($body, "status='deleted'");
t_ok($unlinkPos !== false && $updatePos !== false && $unlinkPos < $updatePos,
    'the row is only marked deleted after unlink has been checked');

// ── The viewer reads without executing ───────────────────────────────────────
$p3  = $work . '/viewme.php';
$id3 = seed_threat($p3, "<?php echo 'DO NOT RUN'; ?>\nplain text line\n");

$v = $scanner->viewThreat($id3);
t_eq(true, $v['success'] ?? false, 'viewThreat() reads the file');
t_contains($v['content'], 'DO NOT RUN', 'the contents come back as text');
t_eq(false, $v['binary'], 'a text file is not reported as binary');
t_ok(strlen($v['sha256']) === 64, 'a sha256 identifies the file');
t_eq(false, $v['truncated'], 'a small file is not truncated');

// Nothing in the read path may execute the file.
$viewPos  = strpos($src, 'public function viewThreat');
$viewBody = substr($src, $viewPos, 2600);
foreach (['include', 'require', 'eval(', 'system(', 'passthru('] as $danger) {
    t_ok(strpos($viewBody, $danger) === false,
        "viewThreat() never calls {$danger} on the file");
}
t_contains($viewBody, 'file_get_contents', 'it reads the bytes as data');

// Large files are capped so the dashboard cannot be handed 500MB.
$big = $work . '/big.php';
file_put_contents($big, str_repeat('A', 5000));
$idBig = seed_threat($big, str_repeat('A', 5000));
$vb = $scanner->viewThreat($idBig, 100);
t_eq(true, $vb['truncated'], 'a file larger than the cap is reported as truncated');
t_ok(strlen($vb['content']) <= 100, 'only the capped number of bytes is returned');

// Binary content is described, not dumped.
$bin = $work . '/payload.bin';
file_put_contents($bin, "MZ\x00\x00\x01binary" . chr(0) . "data");
$idBin = seed_threat($bin, "MZ\x00\x00\x01binary" . chr(0) . "data");
$vbin = $scanner->viewThreat($idBin);
t_eq(true, $vbin['binary'], 'a file containing NUL bytes is reported as binary');
t_eq('', $vbin['content'], 'binary content is not dumped as text');

$vmissing = $scanner->viewThreat(999999);
t_eq(false, $vmissing['success'], 'viewing an unknown threat fails cleanly');

// ── Bulk actions ─────────────────────────────────────────────────────────────
$ids = [];
for ($i = 0; $i < 3; $i++) {
    $ids[] = seed_threat($work . "/bulk{$i}.php");
}
$ids[] = 999998;   // does not exist, so the batch is partially bad

$b = $scanner->bulkAction($ids, 'delete');
t_eq(3, $b['ok'],     'three real files were deleted');
t_eq(1, $b['failed'], 'the unknown id is counted as a failure');
t_eq(false, $b['success'], 'a batch with any failure is not a success');
t_eq(4, count($b['results']), 'every id gets its own result');

// One failure must not stop the rest — that is the whole point of per-item work.
for ($i = 0; $i < 3; $i++) {
    t_ok(!file_exists($work . "/bulk{$i}.php"), "bulk file {$i} was removed");
}
$failed = array_values(array_filter($b['results'], fn($r) => empty($r['success'])));
t_eq(999998, $failed[0]['id'], 'the failing result names its id');
t_ok(!empty($failed[0]['error']), 'and carries a reason');

$bad = $scanner->bulkAction([1], 'set-on-fire');
t_eq(false, $bad['success'], 'an unknown bulk action is refused');
t_contains($bad['error'], 'Unknown action', 'and says so');

$empty = $scanner->bulkAction([], 'delete');
t_eq(0, $empty['ok'], 'an empty selection does nothing');

// Bounded, so a runaway selection cannot hold the request open indefinitely.
t_contains($src, 'array_slice(', 'the batch size is capped');
