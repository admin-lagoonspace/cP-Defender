<?php
/**
 * Authentication regressions.
 *
 *   3.19.1  Auth::requireAuth() called getallheaders(), which does not exist
 *           under the CGI SAPI that cpsrvd uses. Every authenticated request
 *           was an undefined-function fatal.
 *   3.19.1  CGI also drops the Authorization header on many servers, so the
 *           header has to be read from $_SERVER.
 *   3.19.3  The WHM plugin showed a login form even though cpsrvd had already
 *           authenticated the user and set REMOTE_USER.
 */

require_once __DIR__ . '/assert.php';
require __DIR__ . '/bootstrap.php';

// ── Token round trip ─────────────────────────────────────────────────────────
$token = Auth::generateToken('root', 'admin');
$data  = Auth::verifyToken($token);
t_ok(is_array($data), 'a generated token verifies');
t_eq('root',  $data['sub']  ?? null, 'token carries the username');
t_eq('admin', $data['role'] ?? null, 'token carries the role');

// A tampered payload must not verify. This is the whole point of the signature.
[$h, $p, $s] = explode('.', $token);
$forgedPayload = base64_encode(json_encode([
    'sub' => 'attacker', 'role' => 'admin',
    'iat' => time(), 'exp' => time() + 3600,
]));
t_eq(null, Auth::verifyToken("{$h}.{$forgedPayload}.{$s}"), 'a tampered payload is rejected');
t_eq(null, Auth::verifyToken("{$h}.{$p}.abc"),               'a bad signature is rejected');
t_eq(null, Auth::verifyToken('not-a-token'),                 'a malformed token is rejected');

// An expired token must be refused even though its signature is valid.
$expiredPayload = base64_encode(json_encode([
    'sub' => 'root', 'role' => 'admin',
    'iat' => time() - 7200, 'exp' => time() - 60,
]));
$expiredSig = base64_encode(hash_hmac('sha256', "{$h}.{$expiredPayload}", JWT_SECRET, true));
t_eq(null, Auth::verifyToken("{$h}.{$expiredPayload}.{$expiredSig}"), 'an expired token is rejected');

// ── The CGI header problem ───────────────────────────────────────────────────
// getallheaders() is absent under the CGI SAPI. requireAuth() must not depend
// on it; reading $_SERVER is what makes the plugin work under cpsrvd.
$authSrc = t_code(dirname(__DIR__) . '/backend/lib/Auth.php');
t_contains($authSrc, "function_exists('getallheaders')",
    'getallheaders() is only called when it exists');
t_contains($authSrc, 'HTTP_AUTHORIZATION',
    'the Authorization header is read from $_SERVER');

// ── cpsrvd SSO ───────────────────────────────────────────────────────────────
$_SERVER['REMOTE_USER'] = 'root';
$sso = Auth::autoLoginCpanel();
t_ok(is_string($sso) && $sso !== '', 'REMOTE_USER produces a token (no login form under WHM)');
t_eq('admin', Auth::verifyToken($sso)['role'] ?? null, 'root maps to the admin role');

$_SERVER['REMOTE_USER'] = 'someuser';
t_eq('user', Auth::verifyToken(Auth::autoLoginCpanel())['role'] ?? null,
    'a non-root REMOTE_USER does not become admin');

// No REMOTE_USER means no SSO — it must not mint a token from nothing.
unset($_SERVER['REMOTE_USER']);
t_eq(null, Auth::autoLoginCpanel(), 'no REMOTE_USER yields no token');
