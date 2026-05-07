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
}
