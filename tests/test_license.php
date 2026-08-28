<?php
/**
 * Licensing regressions.
 *
 *   3.19.6  License::log() called Logger::write(), which is PRIVATE. That is an
 *           Error, not a warning, so the leading @ suppressed nothing. And log()
 *           is called from the catch block in status(), so the fatal REPLACED
 *           whatever it was reporting — every page that consults a licence went
 *           blank.
 *   3.19.7  License called Database::getSetting(), which does not exist.
 *
 * Licensing sits in front of every feature route, so a fault here is never
 * contained to the licence panel: it takes the whole product down. These tests
 * therefore care most about status() never throwing, whatever the state.
 */

require_once __DIR__ . '/assert.php';
require __DIR__ . '/bootstrap.php';

// ── status() must never throw ────────────────────────────────────────────────
t_no_throw(function () {
    License::status();
}, 'License::status() does not throw on a fresh install');

$s = License::status();
t_ok(is_array($s), 'status() returns an array');
t_ok(isset($s['status']), 'status() reports a status');
t_ok(array_key_exists('protection_allowed', $s), 'status() reports protection_allowed');

// ── Logging must never be the thing that breaks a request ────────────────────
$src = t_code(dirname(__DIR__) . '/backend/lib/License.php');
t_ok(strpos($src, 'Logger::write(') === false,
    'License does not call the private Logger::write()');
t_ok(strpos($src, 'Database::getSetting(') === false,
    'License does not call the non-existent Database::getSetting()');

// Reaching the logger from inside a failure path must be safe.
t_no_throw(function () {
    Logger::info('license: test');
}, 'the public Logger API is callable from outside Logger');

// ── The trial ────────────────────────────────────────────────────────────────
// A fresh install gets a full trial; the marker must be recorded so the clock
// cannot be reset by clearing one of its two homes.
$left = License::trialDaysLeft();
t_ok($left > 0 && $left <= License::TRIAL_DAYS,
    "a fresh install has a trial (got {$left} of " . License::TRIAL_DAYS . " days)");

$installed = License::installedAt();
t_ok($installed > 0, 'the install time is recorded');
t_eq((string)$installed, (string)Database::setting('installed_at', '0'),
    'the install time is persisted to the database');

// Backdating past the trial must end it — the trial is time-based, not a flag.
Database::setSetting('installed_at', (string)(time() - (License::TRIAL_DAYS + 1) * 86400));
t_eq(0, License::trialDaysLeft(), 'an expired trial reports zero days left');

// Even expired, status() must answer rather than throw: the activation screen
// depends on it.
t_no_throw(function () {
    License::status();
}, 'status() still answers once the trial has expired');

// ── The vendor secret must not be a placeholder in a release ─────────────────
// It ships as a placeholder deliberately (the repo is public), but a build must
// never claim to be configured when it is not.
t_ok(method_exists('License', 'secretConfigured'),
    'License exposes whether the licensing secret is configured');
t_eq(false, License::secretConfigured(),
    'the shipped placeholder secret is reported as NOT configured');

// ── An unconfigured licensing secret must not look like a bad key ────────────
// Reported: "I am entering a valid license and it's throwing me an error of
// invalid license". The message was "License response failed verification."
//
// The verification is md5(secret . check_token), matching the official WHMCS
// licensing addon. With SG_LICENSE_SECRET still on its placeholder, that can
// never match whatever WHMCS signed with -- so a correct key is rejected and
// the customer is told to look at the key. secretConfigured() existed from the
// start and nothing called it.

t_ok(method_exists('License', 'secretConfigured'), 'secretConfigured() exists');

// The bootstrap does not define SG_LICENSE_SECRET, so this install is running
// on the placeholder -- exactly the customer's situation.
t_eq(false, License::secretConfigured(),
    'a placeholder secret is reported as not configured');

$res = License::activate('SG-0c9dfa27e78dd2ca8a');
t_eq('Unconfigured', $res['status'],
    'activating without a secret reports Unconfigured, not Invalid');
t_eq(false, $res['valid'], 'an unconfigured install is not valid');
t_contains($res['message'], 'SG_LICENSE_SECRET',
    'the message names the setting that must be fixed');
t_contains($res['message'], 'mode.php',
    'the message names the file to edit');
t_contains($res['message'], 'not the problem',
    'the message says explicitly that the key is not at fault');

// It must not have contacted the licence server, and must not have burnt the
// trial by recording that a key was entered.
t_ok(strpos(strtolower($res['message']), 'failed verification') === false,
    'the misleading "failed verification" wording is gone from this path');

// Every result carries the configuration state so the UI can warn early.
$st = License::status();
t_ok(array_key_exists('secret_configured', $st),
    'status() reports whether the secret is configured');
t_eq(false, $st['secret_configured'], 'status() agrees the secret is unset');

// ── The verification maths must match the WHMCS addon ────────────────────────
// The official client computes md5($secret . $check_token). If this ever drifts,
// every activation fails on a correctly configured server -- a far worse
// outcome than the bug being fixed here, so it is pinned.
$src = t_code(dirname(__DIR__) . '/backend/lib/License.php');
t_contains($src, "md5(self::secret() . \$checkToken)",
    'the response hash is md5(secret . check_token), as WHMCS computes it');
t_contains($src, 'hash_equals(', 'the comparison is constant-time');

// ── The UI warns before a key is wasted ──────────────────────────────────────
$html = file_get_contents(dirname(__DIR__) . '/frontend/index.html');
t_contains($html, 'license-config-warning',
    'the licence panel has somewhere to show a configuration warning');
$app = file_get_contents(dirname(__DIR__) . '/frontend/js/app.js');
t_contains($app, 'secret_configured === false',
    'the UI checks the configuration state');

// ── The installer must be able to set it ─────────────────────────────────────
$install = file_get_contents(dirname(__DIR__) . '/install.sh');
t_contains($install, 'SG_LICENSE_SECRET',
    'install.sh writes SG_LICENSE_SECRET into mode.php');
