<?php
/**
 * Shakaal — the installed-CSF branch of setGeoBlock(), executed.
 *
 * Wasooli could only assert this branch structurally, because CSF_CONF is an
 * unguarded define() in config.php. That is thin for the one code path that
 * rewrites a live firewall's country list, so this reaches it for real: a
 * genuine /etc/csf/csf.conf at the genuine path, a genuine executable at
 * /usr/sbin/csf, and assertions on the BYTES ON DISK after each call.
 *
 * What is still stubbed is csf's own behaviour (the binary), the same way
 * apachectl and `exim -bp` are stubbed. The product's reads, regex, write and
 * exit-code handling are all real.
 *
 * Run inside the container as root.
 */
require_once __DIR__ . '/../assert.php';
$ctx = require __DIR__ . '/../bootstrap.php';

$CONF = CSF_CONF;   // /etc/csf/csf.conf
$BIN  = CSF_BIN;    // /usr/sbin/csf
@mkdir(dirname($CONF), 0755, true);

/** Write a csf.conf that looks like the real thing around the line we touch. */
$seedConf = function (string $ccDeny = 'RU,CN,KP') use ($CONF) {
    file_put_contents($CONF,
        "# Config for csf\n"
      . "TESTING = \"0\"\n"
      . "CC_DENY = \"{$ccDeny}\"\n"
      . "CC_ALLOW = \"\"\n"
      . "LF_DSHIELD = \"0\"\n");
};
/** A csf binary that exits with $rc. */
$seedBin = function (int $rc) use ($BIN) {
    file_put_contents($BIN, "#!/bin/sh\necho 'csf stub: '\"\$@\"\nexit {$rc}\n");
    chmod($BIN, 0755);
};
/** The CC_DENY value actually on disk right now. */
$ccOnDisk = function () use ($CONF): string {
    $c = (string) @file_get_contents($CONF);
    return preg_match('/^CC_DENY\s*=\s*"?([^"\r\n]*)"?/m', $c, $m) ? $m[1] : '(no line)';
};

$seedBin(0);
$fw = new Firewall();
t_ok($fw->isCSFInstalled(), 'CSF IS INSTALLED for this run, so the branch that '
   . 'rewrites a live firewall is the one being executed, not the standalone '
   . 'one that returns early');

// ── 1. The happy path actually rewrites the file ───────────────────────────

$seedConf('RU,CN,KP');
Database::setSetting('geo_block_countries', 'RU,CN,KP');
$r = $fw->setGeoBlock(['ru', ' kp ', 'BY', 'BY']);
t_ok(!empty($r['success']), 'a normal save succeeds');
t_eq(true, $r['enforced'] ?? null, 'and reports that it was ENFORCED, which is '
   . 'a separate fact from having been saved');
t_eq('RU,KP,BY', $ccOnDisk(),
     'AND THE BYTES ON DISK CHANGED: normalised, deduplicated, upper-cased. '
   . 'Read back from /etc/csf/csf.conf, not from the return value');
t_contains((string) @file_get_contents($CONF), 'LF_DSHIELD',
     'and the rest of csf.conf survived the rewrite — the regex replaces one '
   . 'line, not the file');

// ── 2. THE PRODUCTION HAZARD: an empty post must not wipe a live list ──────

$seedConf('RU,CN,KP');
Database::setSetting('geo_block_countries', 'RU,CN,KP');
$r = $fw->setGeoBlock([]);
t_ok(empty($r['success']),
     'THE BUG THAT SHIPPED IN EVERY RELEASE SINCE 3.1.2: an empty selection '
   . 'against a non-empty list is REFUSED. This is what one click of Save Geo '
   . 'Rules did on a page whose grid had failed to render');
t_ok(!empty($r['needs_confirm']), 'and it asks for confirmation rather than guessing');
t_eq('RU,CN,KP', $ccOnDisk(),
     'AND CC_DENY IS UNTOUCHED ON DISK. This is the assertion that matters: '
   . 'not that the call returned an error, but that the live firewall was not '
   . 'rewritten');
t_eq(3, count($r['countries'] ?? []),
     'and the refusal hands back the list it refused to erase, so the panel '
   . 'can show what is actually in force');

// ── 3. An explicit clear_all does clear it ─────────────────────────────────

$r = $fw->setGeoBlock([], true);
t_ok(!empty($r['success']), 'an explicit clear_all is honoured');
t_eq('', $ccOnDisk(), 'and CC_DENY is emptied on disk, deliberately');

// ── 4. No CC_DENY line at all is a FAILURE, not a silent success ───────────

file_put_contents($CONF, "TESTING = \"0\"\nLF_DSHIELD = \"0\"\n");
Database::setSetting('geo_block_countries', '');
$r = $fw->setGeoBlock(['RU']);
t_ok(empty($r['success']), 'a csf.conf with no CC_DENY line is a failure');
t_eq(false, $r['enforced'] ?? null, 'and enforced is false');
t_contains((string) $r['error'], 'no CC_DENY',
     'and says which of the five failure branches it was');

// ── 5. A failed write — THE ONE BRANCH I COULD NOT EXECUTE ─────────────────
//
// I tried and could not reach this, and I am recording the attempt rather
// than quietly asserting the structure and calling it covered.
//
// The product runs as root, and so does this test. chmod 0444 does not stop
// root writing, `chattr +i` needs CAP_LINUX_IMMUTABLE and e2fsprogs is not in
// the image ("chattr: command not found"), and making the path a directory
// trips the earlier `cannot read` branch instead. Verified empirically:
// file_put_contents() on a 0444 /etc/csf/csf.conf as root returns int(1).
//
// On a real server the trigger is ENOSPC, which surfaces as a SHORT write
// rather than false — so the condition that matters is the length comparison,
// not the === false. That is what is asserted here, structurally, and it is
// the only structural assertion in this file.

$fwSrc = t_code($ctx['repo'] . '/backend/lib/Firewall.php');
t_contains($fwSrc, '$wrote === false || $wrote !== strlen($new)',
     'A SHORT WRITE IS A FAILED APPLY. STRUCTURAL — see the comment above: the '
   . 'write cannot be made to fail for root in this container. ENOSPC gives a '
   . 'short count, not false, so the length comparison is the half that '
   . 'actually catches a full disk, and dropping it would leave a truncated '
   . 'CC_DENY reported as applied');

// ── 6. csf -r failing is a FAILURE, and the file state is reported honestly ─

$seedConf('RU');
$seedBin(3);
$r = $fw->setGeoBlock(['CN'], true);
t_ok(empty($r['success']), 'csf refusing to reload is a failure');
t_eq(false, $r['enforced'] ?? null,
     'and NOT enforced, because a written CC_DENY that csf has not reloaded is '
   . 'not blocking anybody');
t_contains((string) $r['error'], 'would not reload', 'and says so');
t_contains((string) $r['error'], 'exit 3', 'with the exit code');
t_eq('CN', $ccOnDisk(),
     'and it does NOT claim the file is unchanged — CC_DENY really was '
   . 'written, and the error says "written but CSF would not reload", which is '
   . 'the true state for an operator to recover from');

// ── 7. A bad code is rejected before anything is read or written ────────────

$seedBin(0);
$seedConf('RU,CN');
$r = $fw->setGeoBlock(['RU', 'XYZ']);
t_ok(empty($r['success']), 'a three-letter code is rejected');
t_eq('RU,CN', $ccOnDisk(), 'and nothing was written — validation is before the write');

// ── 8. getGeoBlock reports the two sources separately ──────────────────────

$seedConf('RU,CN,KP');
Database::setSetting('geo_block_countries', 'RU');
$g = $fw->getGeoBlock();
t_eq(['RU'], $g['countries'], 'the saved list is what the panel saved');
t_eq(['RU', 'CN', 'KP'], $g['csf_countries'],
     'and CSF\'s own CC_DENY is reported SEPARATELY and not merged — a '
   . 'disagreement means something outside the product changed one of them, '
   . 'and merging would hide exactly that');
t_eq('', $g['csf_error'], 'with no error');

unlink($CONF);
$g = $fw->getGeoBlock();
t_eq(null, $g['csf_countries'],
     'AND AN UNREADABLE csf.conf IS NULL, NOT AN EMPTY LIST. "no countries are '
   . 'blocked" and "we could not find out" must not render the same, because '
   . 'the first is what the second looked like for every release so far');
t_contains($g['csf_error'], 'cannot read', 'and the reason is carried');
