<?php
/**
 * Detection patterns live somewhere they can change, and survive.
 *
 * They were twenty regexes in Scanner's constructor. They could only change
 * by shipping a release, could not be switched off when one matched a
 * customer's live site by mistake, and nothing could add to them from a
 * threat feed. The only thing that updated at all was ClamAV's own database,
 * weekly, via freshclam.
 *
 * Three places, each narrower than the last:
 *
 *   database -> the working set, queryable, one rule disablable
 *   file     -> a mirror, so a lost database does not mean starting over
 *   builtin  -> the floor, so no failure leaves the scanner with no patterns
 *
 * That last one matters most: a scanner running on zero patterns reports a
 * clean server, which is the one wrong answer nobody questions.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$path = Signatures::exportPath();
t_ok($path !== null, 'the mirror has a path under SIG_DIR');

// ── Seeding an empty install ───────────────────────────────────────────────
Database::query('DELETE FROM signatures');
@unlink($path);
Signatures::flush();

$p = Signatures::activePatterns();
t_eq(count(Signatures::BUILTIN), count($p),
     'an empty table seeds itself from the built-in rules, so a fresh install '
   . 'scans with a full set rather than nothing');
t_ok(is_file($path),
     'and the mirror is written immediately — a mirror created only on the '
   . 'first update would not exist on the day it is first needed');

// ── A feed can add without a release ───────────────────────────────────────
Signatures::upsert(['feed_webshell_xyz' => '/eval\s*\(\s*\$_POST\s*\[/i'], 'testfeed');
Signatures::export();
Signatures::flush();
t_ok(isset(Signatures::activePatterns()['feed_webshell_xyz']),
     'THE RELEASE COUPLING: a new pattern can be added without shipping code');

// ── The whole point: a lost database is not lost rules ─────────────────────
Database::query('DELETE FROM signatures');
Signatures::flush();
$after = Signatures::activePatterns();
t_ok(isset($after['feed_webshell_xyz']),
     'THE FALLBACK THAT MATTERS: with the table emptied, the mirror restores '
   . 'everything — including rules that came from a feed and exist nowhere '
   . 'in the code, which is exactly what "do not start all over again" means');
t_eq(count(Signatures::BUILTIN) + 1, count($after),
     'and restores all of them, not just the ones that shipped');

// ── And if the mirror is gone too ──────────────────────────────────────────
Database::query('DELETE FROM signatures');
@unlink($path);
Signatures::flush();
t_eq(count(Signatures::BUILTIN), count(Signatures::activePatterns()),
     'THE FLOOR: no database and no mirror still scans on the built-ins. A '
   . 'scanner with zero patterns finds nothing and reports a clean server');

// ── A feed cannot poison the scan loop ─────────────────────────────────────
Signatures::flush();
t_eq(0, Signatures::upsert(['broken' => '/unclosed(/'], 'testfeed'),
     'THE POISONED RULE: a pattern that does not compile is refused on the '
   . 'way in. Stored, it would emit a warning per file and match nothing');

$bad = Signatures::readExport();
t_ok(!isset($bad['broken']), 'and a bad rule in the mirror is skipped on the way out too');

// ── A false positive is one command, not a release ─────────────────────────
Signatures::upsert(['noisy_rule' => '/wp-config/i'], 'testfeed');
Signatures::flush();
$before = count(Signatures::activePatterns());
Signatures::disable('noisy_rule');
Signatures::flush();
t_eq($before - 1, count(Signatures::activePatterns()),
     'A FALSE POSITIVE ON A LIVE SITE: one rule can be switched off without '
   . 'touching the others, and without waiting for a release');

// ── The scanner actually uses it ───────────────────────────────────────────
$src = t_code($repo . '/backend/lib/Scanner.php');
t_contains($src, '$this->phpPatterns = Signatures::activePatterns();',
     'Scanner takes its patterns from the store');
t_ok(strpos($src, "'eval_gzinflate'     => ") === false,
     'and no longer carries its own copy of the list, which could drift from '
   . 'the one being updated');

// The builtins must still BE the old list, or moving them lost detections.
t_ok(isset(Signatures::BUILTIN['eval_base64'], Signatures::BUILTIN['reverse_shell'],
           Signatures::BUILTIN['xmrig_pattern'], Signatures::BUILTIN['c99_shell']),
     'and the built-in floor is the original list, moved rather than trimmed');

foreach (Signatures::BUILTIN as $n => $re) {
    t_ok(@preg_match($re, '') !== false, 'built-in pattern ' . $n . ' compiles');
}

// Restore a sane state for anything that runs after this file.
Signatures::flush();
Signatures::seedIfEmpty();
