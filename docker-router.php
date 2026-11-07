<?php
/**
 * Router for PHP's built-in server, used ONLY by the test container.
 *
 * cpsrvd serves this panel: it resolves /serverscrub/api/* to the API entry
 * point and everything else to the front end. The built-in server has no
 * rewrite rules, so without this /api/* would 404 and every UI test would
 * fail for a reason that has nothing to do with the product.
 *
 * Shipped in the repo rather than generated into the image so that what the
 * UI tests run against is reviewable, and versioned with the code it serves.
 */
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

// Strip the mount prefix cpsrvd would have consumed.
foreach (['/serverscrub', '/sentinel_gate'] as $prefix) {
    if (strpos($path, $prefix) === 0) {
        $path = substr($path, strlen($prefix)) ?: '/';
        break;
    }
}

if (strpos($path, '/api') === 0) {
    $_SERVER['SCRIPT_NAME'] = '/api/index.php';
    $_SERVER['PATH_INFO']   = substr($path, 4) ?: '/';
    require __DIR__ . '/backend/api/index.php';
    return true;
}

$file = __DIR__ . '/frontend' . $path;
if ($path === '/' || is_dir($file)) { $file = __DIR__ . '/frontend/index.html'; }
if (is_file($file)) { return false; }   // let the server deliver it

http_response_code(404);
header('Content-Type: text/plain');
echo "Not found: {$path}\n";
return true;
