<?php
/**
 * Sentinel Gate — Logger
 */

class Logger {

    private static function write(string $level, string $msg): void {
        $ts   = date('Y-m-d H:i:s');
        $line = "[$ts] [$level] $msg\n";
        $file = SG_LOGS . '/' . date('Y-m-d') . '.log';
        if (!is_dir(SG_LOGS)) mkdir(SG_LOGS, 0750, true);
        file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
    }

    public static function info(string $msg): void  { self::write('INFO',  $msg); }
    public static function error(string $msg): void { self::write('ERROR', $msg); }
    public static function warn(string $msg): void  { self::write('WARN',  $msg); }
    public static function debug(string $msg): void {
        if (getenv('SG_DEBUG') === '1') self::write('DEBUG', $msg);
    }

    public static function event(string $type, string $severity, string $ip, string $target, string $desc): void {
        self::write($severity, "[$type] $ip -> $target: $desc");
        Database::insert('security_events', [
            'type'        => $type,
            'severity'    => $severity,
            'source_ip'   => $ip,
            'target'      => $target,
            'description' => $desc,
        ]);
    }

    public static function getRecentLogs(int $lines = 200): array {
        $file = SG_LOGS . '/' . date('Y-m-d') . '.log';
        if (!file_exists($file)) return [];
        $all = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        return array_slice(array_reverse($all), 0, $lines);
    }

    /**
     * The days that actually have a log, newest first.
     *
     * getRecentLogs() reads today's file and only today's, so on a quiet
     * morning the Log Analyzer had nothing to show and no way to say why --
     * indistinguishable from being broken.
     */
    public static function getLogDays(int $limit = 30): array
    {
        $days = [];
        foreach (glob(SG_LOGS . '/*.log') ?: [] as $f) {
            $name = basename($f, '.log');
            // Only the dated application logs; scan_<id>.log lives here too.
            if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $name)) {
                continue;
            }
            $days[] = [
                'date'  => $name,
                'bytes' => (int) @filesize($f),
                'lines' => self::countLines($f),
            ];
        }
        usort($days, fn($a, $b) => strcmp($b['date'], $a['date']));
        return array_slice($days, 0, $limit);
    }

    private static function countLines(string $file): int
    {
        $n  = 0;
        $fh = @fopen($file, 'r');
        if (!$fh) {
            return 0;
        }
        while (fgets($fh) !== false) {
            $n++;
        }
        fclose($fh);
        return $n;
    }

    /**
     * Parsed log lines for a given day, newest first, optionally filtered.
     *
     * Returns structured rows rather than raw strings so the UI can render a
     * level, a timestamp and a message instead of re-parsing the format in
     * JavaScript. A line that does not match the expected shape is still
     * returned, with a null level -- dropping it would hide exactly the
     * unusual output worth reading.
     */
    public static function query(string $date = '', string $level = '',
                                 string $search = '', int $lines = 500): array
    {
        if ($date === '' || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) {
            $date = date('Y-m-d');
        }
        $file = SG_LOGS . '/' . $date . '.log';
        if (!is_file($file)) {
            return ['date' => $date, 'entries' => [], 'total' => 0, 'counts' => []];
        }

        $all    = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        $level  = strtoupper(trim($level));
        $needle = trim($search);

        $entries = [];
        $counts  = ['INFO' => 0, 'WARN' => 0, 'ERROR' => 0, 'DEBUG' => 0, 'OTHER' => 0];

        foreach (array_reverse($all) as $line) {
            // Written by write(): [Y-m-d H:i:s] [LEVEL] message
            $ts = null; $lvl = null; $msg = $line;
            if (preg_match('/^\[([^\]]+)\]\s*\[([A-Z]+)\]\s*(.*)$/', $line, $m)) {
                $ts  = $m[1];
                $lvl = $m[2];
                $msg = $m[3];
            }

            $counts[$lvl !== null && isset($counts[$lvl]) ? $lvl : 'OTHER']++;

            if ($level !== '' && $level !== 'ALL' && $lvl !== $level) {
                continue;
            }
            if ($needle !== '' && stripos($line, $needle) === false) {
                continue;
            }
            if (count($entries) >= $lines) {
                continue;   // keep counting so the totals stay honest
            }

            $entries[] = ['time' => $ts, 'level' => $lvl, 'message' => $msg];
        }

        return [
            'date'    => $date,
            'entries' => $entries,
            'total'   => count($all),
            'counts'  => $counts,
        ];
    }
}
