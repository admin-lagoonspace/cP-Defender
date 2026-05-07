<?php
/**
 * Sentinel Gate — Standalone PHP Router
 * ─────────────────────────────────────
 * Used with PHP's built-in web server:
 *   php -S 0.0.0.0:31150 /usr/local/sentinel-gate/backend/standalone-router.php
 *
 * URL layout:
 *   http://ip:31150/              → SPA (frontend/index.html)
 *   http://ip:31150/css/*         → frontend/css/*
 *   http://ip:31150/js/*          → frontend/js/*
 *   http://ip:31150/backend/api/* → backend REST API
 */

$root = dirname(__DIR__);                          // /usr/local/sentinel-gate
$uri  = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$uri  = '/' . ltrim($uri, '/');

// ── API requests ──────────────────────────────────────────────────────────────
if (str_starts_with($uri, '/backend/api')) {
    // Let index.php parse the full URI — it strips the /backend/api/ prefix
    require $root . '/backend/api/index.php';
    exit;
}

// ── Static frontend assets ────────────────────────────────────────────────────
$MIME = [
    'css'   => 'text/css; charset=UTF-8',
    'js'    => 'application/javascript; charset=UTF-8',
    'html'  => 'text/html; charset=UTF-8',
    'json'  => 'application/json',
    'png'   => 'image/png',
    'jpg'   => 'image/jpeg',
    'jpeg'  => 'image/jpeg',
    'gif'   => 'image/gif',
    'svg'   => 'image/svg+xml',
    'ico'   => 'image/x-icon',
    'woff'  => 'font/woff',
    'woff2' => 'font/woff2',
    'ttf'   => 'font/ttf',
    'map'   => 'application/json',
];

if ($uri !== '/') {
    $file = $root . '/frontend' . $uri;
    if (is_file($file)) {
        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        if (isset($MIME[$ext])) header('Content-Type: ' . $MIME[$ext]);
        // Cache static assets for 1 hour
        if (in_array($ext, ['css', 'js', 'png', 'jpg', 'ico', 'woff', 'woff2'])) {
            header('Cache-Control: public, max-age=3600');
        }
        readfile($file);
        exit;
    }
}

// ── SPA fallback — all other routes return index.html ─────────────────────────
header('Content-Type: text/html; charset=UTF-8');
header('Cache-Control: no-store');
readfile($root . '/frontend/index.html');
exit;
