<?php
/**
 * Sentinel Gate — GitHub webhook receiver
 *
 * Deployed into the public docroot so GitHub can call it the moment a release is
 * published. It triggers cdn-sync.sh, which does the actual download/extract.
 *
 * ── SECURITY ─────────────────────────────────────────────────────────────────
 * This endpoint is PUBLIC and causes the server to download and extract an
 * archive, so it must never act on an unverified request. Every request is
 * rejected unless it carries a valid HMAC-SHA256 signature produced with the
 * shared secret, compared in constant time. Without a configured secret the
 * endpoint refuses to run at all — it does not silently fall open.
 *
 * ── INSTALL ──────────────────────────────────────────────────────────────────
 * 1. Generate a secret:      openssl rand -hex 32
 * 2. Save it OUTSIDE the docroot, readable only by this user:
 *      echo '<secret>' > /home/lwss1/.sg-webhook-secret
 *      chmod 600 /home/lwss1/.sg-webhook-secret
 * 3. Copy this file to  <docroot>/webhook.php
 * 4. GitHub → repo → Settings → Webhooks → Add webhook
 *      Payload URL : https://defender.lws-s1.com/sentinel-gate/code/webhook.php
 *      Content type: application/json
 *      Secret      : <the same secret>
 *      Events      : "Let me select individual events" → Releases  (and Pushes
 *                    if you want branch pushes to sync too)
 */

declare(strict_types=1);

// ── Configuration ────────────────────────────────────────────────────────────
$SECRET_FILE = getenv('SG_WEBHOOK_SECRET_FILE') ?: '/home/lwss1/.sg-webhook-secret';
$SYNC_SCRIPT = getenv('SG_SYNC_SCRIPT')         ?: '/home/lwss1/bin/cdn-sync.sh';
$TRIGGER     = getenv('SG_TRIGGER_FILE')        ?: '/home/lwss1/.sg-sync-trigger';
$LOG         = getenv('SG_WEBHOOK_LOG')         ?: '/home/lwss1/logs/webhook.log';
$MAX_BODY    = 1024 * 1024;   // 1 MB — GitHub payloads are far smaller

function logmsg(string $m): void {
    global $LOG;
    $line = sprintf("[%s] %s %s\n", gmdate('c'),
        $_SERVER['REMOTE_ADDR'] ?? '-', $m);
    @file_put_contents($LOG, $line, FILE_APPEND | LOCK_EX);
}

function respond(int $code, string $msg) {
    http_response_code($code);
    header('Content-Type: text/plain; charset=utf-8');
    echo $msg, "\n";
    exit;
}

// ── Only POST ────────────────────────────────────────────────────────────────
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    respond(405, 'Method Not Allowed');
}

// ── The secret must exist. Never fall open. ──────────────────────────────────
if (!is_readable($SECRET_FILE)) {
    logmsg('REJECTED: secret file missing or unreadable');
    respond(500, 'Webhook not configured');
}
$secret = trim((string)file_get_contents($SECRET_FILE));
if ($secret === '') {
    logmsg('REJECTED: secret file is empty');
    respond(500, 'Webhook not configured');
}

// ── Read the body, bounded ───────────────────────────────────────────────────
$body = (string)file_get_contents('php://input', false, null, 0, $MAX_BODY + 1);
if (strlen($body) > $MAX_BODY) {
    logmsg('REJECTED: payload too large');
    respond(413, 'Payload Too Large');
}

// ── Verify the signature ─────────────────────────────────────────────────────
// hash_equals is constant-time; a plain === leaks timing information that can be
// used to forge a signature byte by byte.
$sig = $_SERVER['HTTP_X_HUB_SIGNATURE_256'] ?? '';
if ($sig === '') {
    logmsg('REJECTED: no X-Hub-Signature-256 header');
    respond(401, 'Missing signature');
}
$expected = 'sha256=' . hash_hmac('sha256', $body, $secret);
if (!hash_equals($expected, $sig)) {
    logmsg('REJECTED: signature mismatch');
    respond(401, 'Invalid signature');
}

// ── Decide whether this event should trigger a sync ──────────────────────────
$event = $_SERVER['HTTP_X_GITHUB_EVENT'] ?? '';

if ($event === 'ping') {
    logmsg('ping OK');
    respond(200, 'pong');
}

$payload = json_decode($body, true);
if (!is_array($payload)) {
    logmsg('REJECTED: body is not valid JSON');
    respond(400, 'Bad payload');
}

$shouldSync = false;
$reason     = '';

if ($event === 'release') {
    $action = (string)($payload['action'] ?? '');
    // Only act once the release is actually visible to consumers.
    if (in_array($action, ['published', 'released'], true)) {
        $shouldSync = true;
        $reason = 'release ' . $action . ' ' . (string)($payload['release']['tag_name'] ?? '?');
    } else {
        $reason = 'release action "' . $action . '" ignored';
    }
} elseif ($event === 'push') {
    $ref = (string)($payload['ref'] ?? '');
    // A tag push, or a push to main that touched the manifest/artifacts.
    if (strncmp($ref, 'refs/tags/v', 11) === 0) {
        $shouldSync = true;
        $reason = 'tag push ' . substr($ref, 10);
    } elseif ($ref === 'refs/heads/main') {
        $touched = [];
        foreach (($payload['commits'] ?? []) as $c) {
            foreach (['added', 'modified'] as $k) {
                foreach (($c[$k] ?? []) as $f) { $touched[] = (string)$f; }
            }
        }
        foreach ($touched as $f) {
            if ($f === 'latest.json' || strncmp($f, 'dist/', 5) === 0) {
                $shouldSync = true;
                $reason = 'main push touched ' . $f;
                break;
            }
        }
        if (!$shouldSync) { $reason = 'main push touched no release artifacts'; }
    } else {
        $reason = 'push to ' . $ref . ' ignored';
    }
} else {
    $reason = 'event "' . $event . '" ignored';
}

if (!$shouldSync) {
    logmsg('no-op: ' . $reason);
    respond(200, 'Ignored: ' . $reason);
}

// ── Trigger the sync ─────────────────────────────────────────────────────────
// Respond fast — GitHub times out at 10s and retries, which would stack syncs.
// The trigger file is written FIRST and unconditionally: if exec() is disabled
// (common on shared cPanel hosting) the every-minute cron picks it up instead,
// so the webhook still works with PHP functions locked down.
@file_put_contents($TRIGGER, gmdate('c') . ' ' . $reason . "\n", LOCK_EX);

$launched = false;
if (function_exists('exec') && !in_array('exec', array_map('trim',
        explode(',', (string)ini_get('disable_functions'))), true)) {
    if (is_executable($SYNC_SCRIPT)) {
        // Detached so the HTTP response is not held open by the download.
        @exec(sprintf('nohup %s >> %s 2>&1 &',
            escapeshellarg($SYNC_SCRIPT), escapeshellarg(dirname($LOG) . '/cdn-sync.log')));
        $launched = true;
    }
}

logmsg('SYNC TRIGGERED: ' . $reason . ($launched ? ' (exec)' : ' (queued for cron)'));
respond(202, $launched
    ? 'Sync started: ' . $reason
    : 'Sync queued (cron will pick it up within 60s): ' . $reason);
