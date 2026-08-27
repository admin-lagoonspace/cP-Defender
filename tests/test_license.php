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
