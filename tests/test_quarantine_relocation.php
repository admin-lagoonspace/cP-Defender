<?php
/**
 * An admin's deliberate quarantine relocation must survive an update.
 *
 * install.sh moves quarantine off the root partition, because quarantine MOVES
 * infected files into its directory and a busy scan filling / took a live
 * server down. That part is right. What it also did was compute the first
 * writable big volume and write it into quarantine_dir UNCONDITIONALLY, on
 * every --register-only run -- which is every update.
 *
 * So an admin who relocated quarantine through the panel, because the volume
 * it was on filled up, had the setting silently moved back on the next update,
 * and every new detection started landing on the full volume again. Filling a
 * volume with quarantined files is the exact incident this block exists to
 * prevent, and it was reintroducing it once a release.
 *
 * Already-quarantined files were not lost -- every threats row stores its own
 * absolute quarantine_path, so a restore still resolves -- but the recovery
 * path that rebuilds a location from the setting looks in the wrong directory
 * afterwards, and new quarantines go to the wrong volume.
 *
 * The setting is now written only when there is nothing deliberate to respect.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$ins = file_get_contents($repo . '/install.sh');

// ── The destination is decided, not assumed ───────────────────────────────
t_contains($ins, '_SG_QUAR_AUTO=""',
     'the automatic location is computed into its own variable, separate from '
   . 'the destination actually used — conflating the two is what overwrote '
   . 'the admin\'s choice');
t_contains($ins, "SELECT value FROM settings WHERE key='quarantine_dir';",
     'THE CURRENT SETTING IS READ BEFORE IT IS WRITTEN: the old code never '
   . 'looked at what was already configured, which is the whole defect');

// ── A deliberate relocation is left alone ─────────────────────────────────
t_contains($ins, '_SG_QUAR_RECORD=false',
     'A CHOSEN LOCATION IS NOT OVERWRITTEN: a path that is safe and off the '
   . 'root partition was chosen on purpose, so the setting is left as it is');
t_contains($ins, 'info "Quarantine stays where it was configured: ${_SG_QUAR_SET}"',
     'and the installer says so, rather than silently doing nothing where it '
   . 'used to silently do something');
t_contains($ins, '_SG_QUAR_NEW="$_SG_QUAR_SET"',
     'the configured path becomes the destination, so files still in the '
   . 'install directory move THERE rather than to a third location');

// ── The write is gated on that decision ───────────────────────────────────
preg_match('/# Record the location.*?\n  fi/s', $ins, $m);
$rec = $m[0] ?? '';
t_ok($rec !== '', 'the record step is still there');
t_contains($rec, 'if $_SG_QUAR_RECORD \\',
     'THE WRITE IS GATED: the INSERT ... ON CONFLICT DO UPDATE ran every time, '
   . 'so there was no path through this block that preserved a setting');
t_contains($rec, 'ON CONFLICT(key) DO UPDATE',
     'and still upserts when it does write, so a first install records it');

// ── The cases that MUST still be overwritten ──────────────────────────────
//
// Respecting a choice cannot become respecting a broken value.
t_contains($ins, 'elif [[ "$_SG_QUAR_SET" == "${INSTALL_DIR}" || "$_SG_QUAR_SET" == "${INSTALL_DIR}/"* ]]; then',
     'STILL MOVED OFF THE ROOT PARTITION: a setting pointing inside the '
   . 'install directory is the case this block exists for, not a deliberate '
   . 'choice, so it is still migrated');
t_contains($ins, 'info "Quarantine is still on the root partition — moving it off"',
     'and that migration is announced');
t_contains($ins, 'warn "Configured quarantine_dir=\'${_SG_QUAR_SET}\' is not a quarantine directory"',
     'AND AN UNSAFE VALUE IS STILL REPLACED: versions before 4.37.5 accepted '
   . '/home, and update.sh then tried to chmod -R it — respecting a choice '
   . 'must not mean preserving that one');
t_contains($ins, ': # Nothing configured -- take the automatic location and record it.',
     'an unset setting takes the automatic location, as on a first install');

// ── The safety check is the same one, in all three places ─────────────────
//
// update.sh refuses to WALK such a path, install.sh refuses to KEEP one, and
// Scanner::moveQuarantine() refuses to WRITE one. Three scripts, one rule;
// if they disagree, the one that is wrong is the one nobody notices.
preg_match('/_sg_quarantine_path_ok\(\) \{.*?\n\}/s', $ins, $mi);
preg_match('/_sg_quarantine_path_ok\(\) \{.*?\n\}/s',
           file_get_contents($repo . '/update.sh'), $mu);
t_ok(($mi[0] ?? 'a') === ($mu[0] ?? 'b'),
     'ONE RULE, NOT TWO: install.sh and update.sh use a byte-identical '
   . '_sg_quarantine_path_ok(), so the path one script refuses to keep is '
   . 'exactly the path the other refuses to walk');
t_contains($mi[0] ?? '', '[[ "$d" == */*/* ]] || return 1',
     'and it is the depth check that rejects a whole volume');

// ── The stale directory is not created ────────────────────────────────────
//
// mkdir ran against the computed location unconditionally, so the volume the
// admin had moved AWAY from got an empty quarantine directory recreated on it
// every update. The mkdir now targets the chosen destination.
$posAssign = strpos($ins, '_SG_QUAR_NEW="$_SG_QUAR_SET"');
$posMkdir  = strpos($ins, 'mkdir -p "$_SG_QUAR_NEW" 2>/dev/null || true');
t_ok($posAssign !== false && $posMkdir !== false && $posAssign < $posMkdir,
     'THE DESTINATION IS CHOSEN BEFORE ANYTHING IS CREATED: otherwise the '
   . 'volume the admin moved away from gets an empty quarantine directory '
   . 'recreated on it every update');
