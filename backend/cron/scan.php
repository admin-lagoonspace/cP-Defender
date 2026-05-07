<?php
/**
 * Sentinel Gate — Background Scan Worker
 * Called by: php scan.php --job-id=N --path=/home
 */

define('SG_API', true);
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../lib/Database.php';
require_once __DIR__ . '/../lib/Logger.php';
require_once __DIR__ . '/../lib/Scanner.php';

// Parse CLI args
$opts   = getopt('', ['job-id:', 'path:']);
$jobId  = (int)($opts['job-id'] ?? 0);
$path   = $opts['path'] ?? '/home';

if (!$jobId) {
    // Scheduled run — create a new job
    $scanner = new Scanner();
    $path    = Database::setting('scan_paths', '/home');
    $jobId   = Database::insert('scan_jobs', [
        'scan_type'  => 'scheduled',
        'status'     => 'running',
        'started_at' => time(),
        'scan_path'  => $path,
    ]);
}

$scanner = new Scanner();
Logger::info("Scan worker started: job=$jobId path=$path");

// Update job status
Database::query("UPDATE scan_jobs SET status='running', started_at=? WHERE id=?", [time(), $jobId]);

try {
    $start = microtime(true);

    // Count files first
    $fileCount = 0;
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    foreach ($it as $f) {
        if ($f->isFile()) $fileCount++;
    }
    Database::query("UPDATE scan_jobs SET files_scanned=? WHERE id=?", [$fileCount, $jobId]);

    // Run scan
    $threats = $scanner->runClamScan($path, $jobId);
    if (empty($threats)) {
        $threats = $scanner->runPatternScan($path, $jobId);
    }

    $elapsed = round(microtime(true) - $start, 2);

    // Mark complete
    Database::query(
        "UPDATE scan_jobs SET status='done', finished_at=?, files_scanned=?, threats_found=? WHERE id=?",
        [time(), $fileCount, count($threats), $jobId]
    );

    Database::setSetting('last_scan', (string) time());

    Logger::info("Scan done: job=$jobId files=$fileCount threats=" . count($threats) . " time={$elapsed}s");

    // Send email alert if threats found
    if (count($threats) > 0) {
        $alertEmail = Database::setting('alert_email');
        if ($alertEmail && Database::setting('email_alerts') === '1') {
            $subject = "[Sentinel Gate] " . count($threats) . " threat(s) detected on " . gethostname();
            $body    = "Sentinel Gate malware scan completed.\n\n";
            $body   .= "Threats detected: " . count($threats) . "\n";
            $body   .= "Scan path: $path\n";
            $body   .= "Duration: {$elapsed}s\n\n";
            foreach ($threats as $t) {
                $body .= "  - {$t['file']}: {$t['name']}\n";
            }
            $body .= "\nLogin to WHM to take action: https://" . gethostname() . ":2087\n";
            mail($alertEmail, $subject, $body, 'From: sentinel@' . gethostname());
        }
    }

    // Log cron run
    Database::insert('cron_log', [
        'job_name'    => 'malware_scan',
        'status'      => 'success',
        'message'     => "Scanned $fileCount files, found " . count($threats) . " threats",
        'duration_ms' => (int)($elapsed * 1000),
    ]);

} catch (Throwable $e) {
    Logger::error("Scan worker error: " . $e->getMessage());
    Database::query("UPDATE scan_jobs SET status='error' WHERE id=?", [$jobId]);
    Database::insert('cron_log', [
        'job_name' => 'malware_scan',
        'status'   => 'error',
        'message'  => $e->getMessage(),
    ]);
    exit(1);
}
