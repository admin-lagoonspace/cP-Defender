<?php
/**
 * Sentinel Gate — File Integrity Monitor
 * Creates and monitors SHA-256 baselines for watched directories
 * Uses the existing `file_integrity` table in the core schema.
 */

class FileIntegrity {

    public function __construct() {
        // file_integrity table is created by Database::migrate(); nothing extra needed.
    }

    // ── Baseline ──────────────────────────────────────────────────────────────

    /**
     * Hash every file under $path and write it to the baseline.
     * Existing records for the same path are updated (re-baselined).
     *
     * @return array  ['path' => $path, 'label' => $label, 'files_added' => int, 'files_updated' => int]
     */
    public function createBaseline(string $path, string $label = ''): array {
        if (!is_dir($path)) {
            Logger::error("FileIntegrity::createBaseline — path not found: $path");
            return ['error' => "Path not found: $path"];
        }

        $added   = 0;
        $updated = 0;
        $now     = time();

        try {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );

            foreach ($it as $file) {
                if (!$file->isFile()) continue;
                $filePath = $file->getPathname();

                $hash  = @hash_file('sha256', $filePath);
                if ($hash === false) continue; // unreadable

                $size  = (int) $file->getSize();
                $perms = substr(sprintf('%o', $file->getPerms()), -4);
                $owner = function_exists('posix_getpwuid')
                    ? (@posix_getpwuid($file->getOwner())['name'] ?? (string) $file->getOwner())
                    : (string) $file->getOwner();

                $existing = Database::fetchOne(
                    "SELECT id FROM file_integrity WHERE file_path = ?", [$filePath]
                );

                if ($existing) {
                    Database::query(
                        "UPDATE file_integrity
                         SET hash_sha256=?, size=?, permissions=?, owner=?,
                             baseline_at=?, last_check=?, status='clean'
                         WHERE file_path=?",
                        [$hash, $size, $perms, $owner, $now, $now, $filePath]
                    );
                    $updated++;
                } else {
                    Database::insert('file_integrity', [
                        'file_path'   => $filePath,
                        'hash_sha256' => $hash,
                        'size'        => $size,
                        'permissions' => $perms,
                        'owner'       => $owner,
                        'baseline_at' => $now,
                        'last_check'  => $now,
                        'status'      => 'clean',
                    ]);
                    $added++;
                }
            }
        } catch (Exception $e) {
            Logger::error('FileIntegrity::createBaseline — ' . $e->getMessage());
        }

        Logger::info("FileIntegrity: baseline created for $path — $added added, $updated updated");

        return [
            'path'          => $path,
            'label'         => $label,
            'files_added'   => $added,
            'files_updated' => $updated,
        ];
    }

    // ── Integrity Check ───────────────────────────────────────────────────────

    /**
     * Compare current files against the baseline.
     * Detects MODIFIED, MISSING, and NEW files.
     *
     * @param string $path  Directory to check (empty = check all baselined paths)
     * @return array  ['modified' => [...], 'missing' => [...], 'new' => [...], 'clean' => int]
     */
    public function runCheck(string $path = ''): array {
        $modified = [];
        $missing  = [];
        $newFiles = [];
        $clean    = 0;
        $now      = time();

        // ── Check existing baseline entries ──────────────────────────────────
        $where  = $path !== '' ? "WHERE file_path LIKE ?" : "";
        $params = $path !== '' ? ["$path%"] : [];

        $rows = Database::fetchAll("SELECT * FROM file_integrity $where", $params);

        // Build a set of known paths for the new-file scan below
        $knownPaths = [];
        foreach ($rows as $row) {
            $knownPaths[$row['file_path']] = true;

            if (!file_exists($row['file_path'])) {
                Database::query(
                    "UPDATE file_integrity SET status='missing', last_check=? WHERE id=?",
                    [$now, $row['id']]
                );
                $missing[] = $row;
                continue;
            }

            $currentHash = @hash_file('sha256', $row['file_path']);
            if ($currentHash === false) continue;

            Database::query(
                "UPDATE file_integrity SET last_check=? WHERE id=?", [$now, $row['id']]
            );

            if ($currentHash !== $row['hash_sha256']) {
                Database::query(
                    "UPDATE file_integrity SET status='modified', hash_sha256=?, last_check=? WHERE id=?",
                    [$currentHash, $now, $row['id']]
                );
                $modified[] = array_merge($row, [
                    'old_hash'    => $row['hash_sha256'],
                    'current_hash'=> $currentHash,
                ]);
            } else {
                Database::query(
                    "UPDATE file_integrity SET status='clean' WHERE id=?", [$row['id']]
                );
                $clean++;
            }
        }

        // ── Scan for new files not in the baseline ────────────────────────────
        if ($path !== '' && is_dir($path)) {
            try {
                $it = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::SELF_FIRST
                );
                foreach ($it as $file) {
                    if (!$file->isFile()) continue;
                    $fp = $file->getPathname();
                    if (isset($knownPaths[$fp])) continue;

                    $hash  = @hash_file('sha256', $fp);
                    $size  = (int) $file->getSize();
                    $perms = substr(sprintf('%o', $file->getPerms()), -4);
                    $owner = function_exists('posix_getpwuid')
                        ? (@posix_getpwuid($file->getOwner())['name'] ?? (string) $file->getOwner())
                        : (string) $file->getOwner();

                    $id = Database::insert('file_integrity', [
                        'file_path'   => $fp,
                        'hash_sha256' => $hash ?: '',
                        'size'        => $size,
                        'permissions' => $perms,
                        'owner'       => $owner,
                        'baseline_at' => $now,
                        'last_check'  => $now,
                        'status'      => 'new',
                    ]);

                    $newFiles[] = [
                        'id'          => $id,
                        'file_path'   => $fp,
                        'hash_sha256' => $hash ?: '',
                        'size'        => $size,
                        'permissions' => $perms,
                        'owner'       => $owner,
                        'status'      => 'new',
                    ];
                }
            } catch (Exception $e) {
                Logger::error('FileIntegrity::runCheck (new file scan) — ' . $e->getMessage());
            }
        }

        Logger::info(sprintf(
            'FileIntegrity: check complete — %d modified, %d missing, %d new, %d clean',
            count($modified), count($missing), count($newFiles), $clean
        ));

        return [
            'modified' => $modified,
            'missing'  => $missing,
            'new'      => $newFiles,
            'clean'    => $clean,
        ];
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    public function getBaselines(): array {
        // Return distinct root paths with file counts and last check time
        return Database::fetchAll(
            "SELECT
                 -- Extract the first 3 path segments as the 'root'
                 SUBSTR(file_path, 1,
                     CASE
                         WHEN INSTR(SUBSTR(file_path, 2), '/') = 0 THEN LENGTH(file_path)
                         ELSE 1 + INSTR(SUBSTR(file_path, 2), '/')
                              + INSTR(SUBSTR(file_path, 2 + INSTR(SUBSTR(file_path, 2), '/')), '/')
                     END
                 ) as root_path,
                 COUNT(*)          as file_count,
                 MAX(last_check)   as last_check,
                 MAX(baseline_at)  as baseline_at
             FROM file_integrity
             GROUP BY root_path
             ORDER BY last_check DESC"
        );
    }

    public function getChanges(string $status = ''): array {
        if ($status !== '') {
            return Database::fetchAll(
                "SELECT * FROM file_integrity WHERE status = ? ORDER BY last_check DESC",
                [$status]
            );
        }
        return Database::fetchAll(
            "SELECT * FROM file_integrity WHERE status != 'clean' ORDER BY last_check DESC"
        );
    }

    public function getStats(): array {
        $total    = Database::fetchOne("SELECT COUNT(*) as c FROM file_integrity")['c'];
        $clean    = Database::fetchOne("SELECT COUNT(*) as c FROM file_integrity WHERE status='clean'")['c'];
        $modified = Database::fetchOne("SELECT COUNT(*) as c FROM file_integrity WHERE status='modified'")['c'];
        $newF     = Database::fetchOne("SELECT COUNT(*) as c FROM file_integrity WHERE status='new'")['c'];
        $missing  = Database::fetchOne("SELECT COUNT(*) as c FROM file_integrity WHERE status='missing'")['c'];
        $lastChk  = Database::fetchOne("SELECT MAX(last_check) as t FROM file_integrity")['t'];

        return [
            'total_monitored' => (int) $total,
            'clean'           => (int) $clean,
            'modified'        => (int) $modified,
            'new_files'       => (int) $newF,
            'missing'         => (int) $missing,
            'last_check'      => $lastChk ? (int) $lastChk : null,
        ];
    }

    public function getWatchedPaths(): array {
        $rows  = Database::fetchAll("SELECT DISTINCT file_path FROM file_integrity");
        $roots = [];

        foreach ($rows as $row) {
            $parts = explode('/', ltrim($row['file_path'], '/'));
            // Use first 3 segments as the logical root (e.g. home/user/public_html)
            $root  = '/' . implode('/', array_slice($parts, 0, 3));
            if (!in_array($root, $roots, true)) {
                $roots[] = $root;
            }
        }

        return $roots;
    }

    // ── Mutations ─────────────────────────────────────────────────────────────

    public function resetBaseline(string $path): bool {
        try {
            Database::query(
                "DELETE FROM file_integrity WHERE file_path LIKE ?", ["$path%"]
            );
            Logger::info("FileIntegrity: baseline reset for $path");
            return true;
        } catch (Exception $e) {
            Logger::error('FileIntegrity::resetBaseline — ' . $e->getMessage());
            return false;
        }
    }

    public function acknowledgeChange(int $id): bool {
        $row = Database::fetchOne("SELECT * FROM file_integrity WHERE id = ?", [$id]);
        if (!$row) return false;

        $currentHash = file_exists($row['file_path'])
            ? (@hash_file('sha256', $row['file_path']) ?: $row['hash_sha256'])
            : $row['hash_sha256'];

        Database::query(
            "UPDATE file_integrity SET status='acknowledged', hash_sha256=? WHERE id=?",
            [$currentHash, $id]
        );
        return true;
    }
}
