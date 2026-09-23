<?php
/**
 * Per-user security reports for the cPanel-side plugin.
 *
 * WHY A FILE AND NOT AN API CALL
 *
 * The cPanel plugin page runs as the cPanel user, under cpsrvd. The database
 * lives in /usr/local/sentinel-gate/database, which is 0700 root, and the API
 * that reads it requires an admin role. A user process therefore cannot reach
 * any of it, and the alternatives -- a setuid helper, or relaxing those
 * permissions -- would hand every hosting customer on the box a path to the
 * server-wide security database.
 *
 * So the privileged side does the reading. This class runs as root, after the
 * scans that produce the data, and writes each user a small JSON file inside
 * their own home directory. The plugin page reads nothing else. Cross-user
 * disclosure is then impossible by construction rather than by a filter
 * somebody has to remember to apply: user A's report is in user A's home,
 * owned by user A, and user B's process cannot open it.
 *
 * WRITING INTO A DIRECTORY THE USER CONTROLS
 *
 * Every write here is root writing into a path a hostile user can rearrange
 * between one call and the next. A symlink at ~/.sentinel-gate, or at
 * report.json, would make root overwrite whatever it points at -- /etc/shadow,
 * an authorized_keys file, anything. Each step below therefore verifies what
 * it is about to touch and refuses rather than following a link.
 */

class UserReport
{
    /** Directory created inside each user's home. */
    private const DIR = '.sentinel-gate';

    /** How many rows of each kind a report carries. */
    private const LIMIT = 200;

    /**
     * cPanel usernames are lowercase alphanumeric with dashes/underscores.
     * Anything else must never reach a filesystem path.
     */
    public static function validUsername(string $user): bool
    {
        return $user !== ''
            && strlen($user) <= 64
            && preg_match('/^[a-z0-9][a-z0-9_-]*$/', $user) === 1;
    }

    /** Every cPanel account on this server. */
    public static function listUsers(): array
    {
        $users = [];
        foreach (glob('/var/cpanel/users/*') ?: [] as $f) {
            if (!is_file($f)) {
                continue;
            }
            $name = basename($f);
            if (self::validUsername($name)) {
                $users[] = $name;
            }
        }
        sort($users);
        return $users;
    }

    /**
     * The user's home directory, confirmed to be a real directory that they
     * own. A home that is a symlink, or owned by somebody else, is not written
     * to: both are signs the account has been tampered with, and following
     * either would have root writing somewhere it was not asked to.
     */
    public static function homeDir(string $user): ?string
    {
        if (!self::validUsername($user)) {
            return null;
        }

        $home = null;
        if (function_exists('posix_getpwnam')) {
            $pw = @posix_getpwnam($user);
            if (is_array($pw) && !empty($pw['dir'])) {
                $home = $pw['dir'];
            }
        }
        if ($home === null) {
            $candidate = '/home/' . $user;
            $home = is_dir($candidate) ? $candidate : null;
        }
        if ($home === null || is_link($home) || !is_dir($home)) {
            return null;
        }

        // Root's own view of who owns it, not the user's claim.
        $uid = @fileowner($home);
        if ($uid === false) {
            return null;
        }
        if (function_exists('posix_getpwnam')) {
            $pw = @posix_getpwnam($user);
            if (is_array($pw) && isset($pw['uid']) && (int)$pw['uid'] !== (int)$uid) {
                return null;
            }
        }
        return rtrim($home, '/');
    }

    /** The report's path for a user, or null if the home is unusable. */
    public static function reportPath(string $user): ?string
    {
        $home = self::homeDir($user);
        return $home === null ? null : $home . '/' . self::DIR . '/report.json';
    }

    /**
     * A query whose table may not exist yet.
     *
     * cms_installs and file_integrity are created lazily by the modules that
     * own them, so on a server where CMS Guard or integrity monitoring has
     * never run they are simply absent. Querying one threw a PDOException that
     * aborted the whole report -- which is the hourly task, for every account
     * on the server. A module that has not run yet means "nothing to report",
     * not "reporting is broken".
     */
    private static function safeFetch(string $sql, array $params): array
    {
        try {
            return Database::fetchAll($sql, $params);
        } catch (Throwable $e) {
            if (stripos($e->getMessage(), 'no such table') === false) {
                Logger::warn('UserReport query failed: ' . $e->getMessage());
            }
            return [];
        }
    }

    /**
     * Build the report body for one user.
     *
     * Everything is filtered by the username the CALLER supplies, which comes
     * from the account list -- never from a request parameter.
     */
    public static function build(string $user, ?string $home = null): array
    {
        // The caller may already have resolved the home (writeFor does, and it
        // must not resolve twice -- the account could change underneath).
        $home = $home ?? self::homeDir($user);

        // Threats are matched on cpanel_user where the scan recorded it, and
        // on the home prefix otherwise: older rows predate that column.
        $prefix = ($home ?? ('/home/' . $user)) . '/';
        $threats = self::safeFetch(
            "SELECT file_path, threat_name, threat_type, severity, status,
                    detected_at, action_taken
               FROM threats
              WHERE (cpanel_user = ? OR file_path LIKE ?)
                AND status != 'deleted'
              ORDER BY detected_at DESC
              LIMIT " . self::LIMIT,
            [$user, $prefix . '%']
        );

        $cms = self::safeFetch(
            "SELECT cms_type, version, install_path, outdated, status, issues, last_check
               FROM cms_installs
              WHERE cpanel_user = ?
              ORDER BY outdated DESC, cms_type ASC
              LIMIT " . self::LIMIT,
            [$user]
        );

        // Integrity rows have no user column; the path prefix is what ties a
        // change to an account.
        $changes = self::safeFetch(
            "SELECT file_path, status, last_check
               FROM file_integrity
              WHERE file_path LIKE ? AND status != 'clean'
              ORDER BY last_check DESC
              LIMIT " . self::LIMIT,
            [$prefix . '%']
        );

        $active = 0;
        foreach ($threats as &$t) {
            if (($t['status'] ?? '') === 'active') {
                $active++;
            }
            // Relative paths: the absolute path adds nothing for someone who
            // only has one home directory, and it is longer than the column.
            $t['relative_path'] = $home !== null && strpos($t['file_path'], $prefix) === 0
                ? substr($t['file_path'], strlen($prefix))
                : $t['file_path'];
        }
        unset($t);

        $outdated = 0;
        foreach ($cms as &$c) {
            if ((int)($c['outdated'] ?? 0) === 1) {
                $outdated++;
            }
            $decoded = json_decode((string)($c['issues'] ?? '[]'), true);
            $c['issues'] = is_array($decoded)
                ? array_values(array_map(
                    fn($i) => is_array($i) ? (string)($i['type'] ?? '') : (string)$i,
                    $decoded
                  ))
                : [];
            $c['relative_path'] = $home !== null && strpos($c['install_path'], $prefix) === 0
                ? substr($c['install_path'], strlen($prefix))
                : $c['install_path'];
        }
        unset($c);

        foreach ($changes as &$ch) {
            $ch['relative_path'] = $home !== null && strpos($ch['file_path'], $prefix) === 0
                ? substr($ch['file_path'], strlen($prefix))
                : $ch['file_path'];
        }
        unset($ch);

        return [
            'schema'       => 1,
            'user'         => $user,
            'generated_at' => time(),
            'version'      => defined('SG_VERSION') ? SG_VERSION : 'unknown',
            'last_scan_at' => (int) Database::setting('last_run_scan', '0'),
            'summary'      => [
                'threats'        => count($threats),
                'threats_active' => $active,
                'cms_installs'   => count($cms),
                'cms_outdated'   => $outdated,
                'file_changes'   => count($changes),
            ],
            'threats'      => $threats,
            'cms'          => $cms,
            'file_changes' => $changes,
        ];
    }

    /**
     * Write one user's report. Returns the path written, or null.
     */
    public static function writeFor(string $user): ?string
    {
        $home = self::homeDir($user);
        if ($home === null) {
            return null;
        }

        $dir = $home . '/' . self::DIR;

        // A symlink here would redirect every write below. Refuse rather than
        // delete: removing something in a user's home because it is in our way
        // is not a decision this class should be making on its own.
        if (is_link($dir)) {
            Logger::warn("UserReport: {$dir} is a symlink — refusing to write through it");
            return null;
        }
        if (!is_dir($dir) && !@mkdir($dir, 0700, false)) {
            return null;
        }
        if (is_link($dir) || !is_dir($dir)) {
            return null;
        }

        $uid = @fileowner($home);
        $gid = @filegroup($home);
        if ($uid !== false) { @chown($dir, $uid); }
        if ($gid !== false) { @chgrp($dir, $gid); }
        @chmod($dir, 0700);

        $path = $dir . '/report.json';
        $tmp  = $dir . '/.report.json.' . getmypid();

        $json = json_encode(self::build($user, $home), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            return null;
        }

        // Written to a temp file and renamed: a reader never sees a half-built
        // report, and the rename replaces whatever report.json was -- including
        // a symlink the user planted -- without ever opening it.
        if (@file_put_contents($tmp, $json) === false) {
            return null;
        }
        if ($uid !== false) { @chown($tmp, $uid); }
        if ($gid !== false) { @chgrp($tmp, $gid); }
        @chmod($tmp, 0600);

        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            return null;
        }
        return $path;
    }

    /**
     * Write reports for every account. Returns [written, skipped].
     */
    public static function writeAll(): array
    {
        $written = 0;
        $skipped = 0;
        foreach (self::listUsers() as $user) {
            // One unusable home must not stop the rest of the server.
            try {
                if (self::writeFor($user) !== null) {
                    $written++;
                } else {
                    $skipped++;
                }
            } catch (Throwable $e) {
                $skipped++;
                Logger::warn('UserReport: ' . $user . ' — ' . $e->getMessage());
            }
        }
        Logger::info("UserReport: wrote {$written} report(s), skipped {$skipped}");
        return ['written' => $written, 'skipped' => $skipped];
    }
}
