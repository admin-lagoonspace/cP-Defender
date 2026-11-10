<?php

/* Pulls in what it calls. Consulted from the scan worker and the realtime
 * daemon's PHP side, where a missing require_once is a fatal nobody sees. */
require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/Logger.php';

/**
 * ServerScrub — switching off ONE signature, by name.
 *
 * ── WHY ──────────────────────────────────────────────────────────────────────
 *
 * On 10 Nov one third-party ClamAV signature matched 154,323 customer files on
 * the production server — README.md and CHANGELOG.md inside node_modules and
 * vendor trees, because the rule hunts long hex strings and a changelog is
 * full of git SHAs:
 *
 *     {HEX}linux.ransom.sessionscribe.qtox.toxid.171.UNOFFICIAL
 *
 * The only lever the product offered was turning ClamAV off. That trades one
 * bad signature for no antivirus at all, on a server with 132 accounts, which
 * is not a choice anybody should have to make. An operator who has identified
 * the rule needs to exclude the RULE.
 *
 * ── IT SURVIVES A SIGNATURE UPDATE ───────────────────────────────────────────
 *
 * Deliberately a row in our database rather than an edit to a signature file.
 * freshclam replaces the .cvd and .cld files wholesale and a third-party feed
 * rewrites its own directory, so anything written there is gone at the next
 * update — silently, which is the worst kind of expiry for a safety measure.
 * The check happens where a detection is RECORDED instead, which no update can
 * touch.
 *
 * ── AND IT IS NEVER INVISIBLE ────────────────────────────────────────────────
 *
 * A suppressed signature is a hole in the defence. Every match is counted and
 * the last one is timestamped, the list is on the Scanner page and in
 * `serverscrub signatures suppress list`, and each row carries who added it and
 * why. A suppression that nobody can see is indistinguishable from a scanner
 * that has stopped working — which is the fault this product keeps shipping,
 * and this is the one place it would be most dangerous.
 *
 * This is a BLUNTER instrument than a verdict and a different one from a scan
 * exclusion, and the three are not interchangeable:
 *
 *   a verdict      these exact bytes at this exact path are not malware. One
 *                  file, and it is re-reported the moment a byte changes.
 *   a suppression   this signature is wrong, everywhere, until I say otherwise.
 *                  Every other signature still applies to every file.
 *   an exclusion    do not look at this path at all. Every signature stops
 *                  applying there, including the ones that matter.
 */

if (!defined('SG_ROOT')) { die('Direct access denied'); }

class SignatureSuppressions
{
    /** Hits are flushed in groups, so a 154,323-match scan is not that many writes. */
    const FLUSH_EVERY = 100;

    /** @var array<string,array{id:int,prefix:bool,name:string}>|null */
    private static $cache = null;

    /** @var array<int,int> suppression id => hits not yet written */
    private static $pending = [];

    public static function ensureSchema(): void
    {
        Database::get()->exec(
            'CREATE TABLE IF NOT EXISTS signature_suppressions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL,
                is_prefix   INTEGER NOT NULL DEFAULT 0,
                reason      TEXT NOT NULL DEFAULT \'\',
                created_by  TEXT NOT NULL DEFAULT \'\',
                created_at  INTEGER NOT NULL DEFAULT (strftime(\'%s\',\'now\')),
                hits        INTEGER NOT NULL DEFAULT 0,
                last_hit_at INTEGER
            )'
        );
        Database::get()->exec(
            'CREATE UNIQUE INDEX IF NOT EXISTS idx_sigsup_name ON signature_suppressions(name)'
        );
    }

    /**
     * Add one.
     *
     * A trailing * makes it a prefix, which is the only wildcard: ClamAV names
     * carry braces, dots and digits, and a full pattern language here would
     * mean an operator switching off more than they meant to in an incident.
     */
    public static function add(string $name, string $reason = '', string $by = ''): array
    {
        self::ensureSchema();
        $name = trim($name);

        if ($name === '' || mb_strlen($name) > 200) {
            return ['success' => false, 'error' => 'A signature name is 1-200 characters'];
        }
        /* The characters a ClamAV signature name actually uses, plus the one
         * wildcard. Anything else is a typo or a paste accident, and a
         * suppression made by accident is a hole nobody knows about. */
        if (!preg_match('/^[A-Za-z0-9{}\[\]().:_\-\/ ]+\*?$/', $name)) {
            return ['success' => false,
                    'error' => 'That does not look like a signature name: ' . $name];
        }
        $prefix = substr($name, -1) === '*';
        $bare   = $prefix ? rtrim($name, '*') : $name;
        if ($prefix && mb_strlen($bare) < 8) {
            // "{HEX}*" would switch off a whole class of signatures from six
            // characters. If that is really wanted, it can be said in full.
            return ['success' => false,
                    'error' => 'A prefix suppression needs at least 8 characters before the *, '
                             . 'or it switches off far more than one signature'];
        }

        $exists = Database::fetchOne(
            'SELECT id FROM signature_suppressions WHERE name = ?', [$name]);
        if ($exists) {
            return ['success' => false, 'error' => 'Already suppressed (id '
                                                 . (int) $exists['id'] . ')',
                    'existing' => (int) $exists['id']];
        }

        $id = Database::insert('signature_suppressions', [
            'name'       => $name,
            'is_prefix'  => $prefix ? 1 : 0,
            'reason'     => mb_substr(trim($reason), 0, 300),
            'created_by' => mb_substr(trim($by) !== '' ? trim($by) : 'unknown', 0, 64),
        ]);
        self::$cache = null;

        Logger::event('signature_suppressed', 'medium', '', $name,
            'Signature suppressed: ' . $name
            . ($prefix ? ' (prefix)' : '')
            . (trim($reason) !== '' ? ' - ' . mb_substr(trim($reason), 0, 200) : '')
            . '. Matches will be counted and not recorded as findings.');

        return ['success' => true, 'id' => (int) $id, 'prefix' => $prefix];
    }

    public static function remove(int $id): array
    {
        self::ensureSchema();
        $row = Database::fetchOne('SELECT * FROM signature_suppressions WHERE id = ?', [$id]);
        if (!$row) { return ['success' => false, 'error' => 'No suppression with id ' . $id]; }

        Database::query('DELETE FROM signature_suppressions WHERE id = ?', [$id]);
        self::$cache = null;
        Logger::event('signature_unsuppressed', 'medium', '', (string) $row['name'],
            'Signature suppression removed: ' . $row['name'] . ' (it had matched '
            . (int) $row['hits'] . ' file(s) while suppressed)');
        return ['success' => true, 'removed' => $row];
    }

    /** @return array<int,array<string,mixed>> newest first */
    public static function all(): array
    {
        self::ensureSchema();
        return Database::fetchAll(
            'SELECT * FROM signature_suppressions ORDER BY id DESC');
    }

    /**
     * Is this signature suppressed, and if so by which row?
     *
     * Cached per process: the scan asks once per detection, and on the 10 Nov
     * run that would have been 154,323 queries.
     *
     * @return array{id:int,name:string}|null
     */
    public static function match(string $threatName): ?array
    {
        $threatName = trim($threatName);
        if ($threatName === '') { return null; }

        if (self::$cache === null) {
            self::$cache = [];
            try {
                foreach (self::all() as $r) {
                    self::$cache[] = [
                        'id'     => (int) $r['id'],
                        'name'   => (string) $r['name'],
                        'prefix' => ((int) $r['is_prefix']) === 1,
                        'bare'   => rtrim((string) $r['name'], '*'),
                    ];
                }
            } catch (Throwable $e) {
                // A missing table must never make the scanner stop recording
                // findings. Failing closed here means failing SILENT.
                Logger::warn('signature suppressions unreadable: ' . $e->getMessage());
                self::$cache = [];
            }
        }

        foreach (self::$cache as $s) {
            if ($s['prefix']) {
                if (strncmp($threatName, $s['bare'], strlen($s['bare'])) === 0) {
                    return ['id' => $s['id'], 'name' => $s['name']];
                }
            } elseif ($threatName === $s['name']) {
                return ['id' => $s['id'], 'name' => $s['name']];
            }
        }
        return null;
    }

    /**
     * Count a match that was suppressed.
     *
     * Written in groups of FLUSH_EVERY: 154,323 matches is 1,544 updates
     * instead of 154,323, and the worst case is losing the tail of a counter
     * whose job is visibility rather than accounting.
     */
    public static function noteHit(int $id): void
    {
        self::$pending[$id] = (self::$pending[$id] ?? 0) + 1;
        if (self::$pending[$id] >= self::FLUSH_EVERY) { self::flush(); }
    }

    /** Write the pending counters. Called at the end of a scan, and by tests. */
    public static function flush(): void
    {
        foreach (self::$pending as $id => $n) {
            if ($n <= 0) { continue; }
            Database::query(
                'UPDATE signature_suppressions SET hits = hits + ?, last_hit_at = ? WHERE id = ?',
                [$n, time(), $id]
            );
        }
        self::$pending = [];
    }

    /** For the panel: how many, and how much they are hiding. */
    public static function summary(): array
    {
        self::ensureSchema();
        $rows = self::all();
        $hits = 0;
        $last = 0;
        foreach ($rows as $r) {
            $hits += (int) $r['hits'];
            $last = max($last, (int) ($r['last_hit_at'] ?? 0));
        }
        return ['count' => count($rows), 'hits' => $hits, 'last_hit_at' => $last,
                'items' => $rows];
    }

    /** Drop the per-process cache. For tests, and for a long-lived worker. */
    public static function reset(): void
    {
        self::$cache   = null;
        self::$pending = [];
    }
}
