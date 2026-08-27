<?php
/**
 * Sentinel Gate — Authentication & JWT
 * Validates against cPanel's native auth system
 */

class Auth {

    /**
     * Validate a cPanel login using the cpcheck binary
     */
    public static function validateCpanel(string $username, string $password): bool {
        $cmd = sprintf(
            '%s/bin/cpcheck %s %s 2>/dev/null',
            CPANEL_BASE,
            escapeshellarg($username),
            escapeshellarg($password)
        );
        exec($cmd, $out, $code);
        return $code === 0;
    }

    /**
     * Validate via WHM API token (for WHM-level access)
     */
    public static function validateWhmToken(string $user, string $token): bool {
        $url = 'https://localhost:2087/json-api/version';
        $ctx = stream_context_create([
            'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
            'http' => [
                'header' => "Authorization: whm $user:$token\r\n",
                'timeout' => 5
            ]
        ]);
        $resp = @file_get_contents($url, false, $ctx);
        return $resp !== false && str_contains($resp, '"status":1');
    }

    public static function generateToken(string $username, string $role = 'user'): string {
        $header  = base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $payload = base64_encode(json_encode([
            'sub'  => $username,
            'role' => $role,
            'iat'  => time(),
            'exp'  => time() + JWT_EXPIRY,
        ]));
        $sig = base64_encode(hash_hmac('sha256', "$header.$payload", JWT_SECRET, true));
        return "$header.$payload.$sig";
    }

    public static function verifyToken(string $token): ?array {
        $parts = explode('.', $token);
        if (count($parts) !== 3) return null;

        [$header, $payload, $sig] = $parts;
        $expected = base64_encode(hash_hmac('sha256', "$header.$payload", JWT_SECRET, true));
        if (!hash_equals($expected, $sig)) return null;

        $data = json_decode(base64_decode($payload), true);
        if (!$data || $data['exp'] < time()) return null;

        return $data;
    }

    /**
     * The Authorization header, however this server chose to deliver it.
     *
     * getallheaders() exists under mod_php and PHP-FPM but NOT under the CGI
     * SAPI, which is what cpsrvd uses to run WHM plugins — calling it there is a
     * fatal error on every authenticated request. CGI also frequently drops the
     * Authorization header entirely, or renames it, so $_SERVER is checked in
     * the several places it is known to appear.
     */
    private static function authHeader(): string {
        foreach (['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION'] as $k) {
            if (!empty($_SERVER[$k])) {
                return (string)$_SERVER[$k];
            }
        }
        if (function_exists('getallheaders')) {
            $headers = getallheaders();
            if (is_array($headers)) {
                foreach ($headers as $name => $value) {
                    if (strcasecmp($name, 'Authorization') === 0) {
                        return (string)$value;
                    }
                }
            }
        }
        // Last resort: rebuild from $_SERVER, which every SAPI populates.
        foreach ($_SERVER as $k => $v) {
            if (strcasecmp($k, 'HTTP_AUTHORIZATION') === 0) {
                return (string)$v;
            }
        }
        return '';
    }

    public static function requireAuth(): array {
        $auth = self::authHeader();

        // Under cpsrvd the request is already authenticated — the user got here
        // through WHM, which sets REMOTE_USER. Accept that rather than rejecting
        // a legitimately signed-in root because CGI dropped a header.
        if ($auth === '' && !empty($_SERVER['REMOTE_USER']) && INSTALL_MODE !== 'standalone') {
            $remote = (string)$_SERVER['REMOTE_USER'];
            return [
                'sub'  => $remote,
                'role' => ($remote === 'root' || $remote === 'cpanel') ? 'admin' : 'user',
            ];
        }

        if (!str_starts_with($auth, 'Bearer ')) {
            self::deny('Missing authorization token');
        }

        $token = substr($auth, 7);
        $data  = self::verifyToken($token);

        if (!$data) {
            self::deny('Invalid or expired token');
        }

        return $data;
    }

    public static function requireRole(string $role, array $user): void {
        $hierarchy = ['user' => 1, 'reseller' => 2, 'admin' => 3, 'root' => 4];
        $required  = $hierarchy[$role] ?? 1;
        $current   = $hierarchy[$user['role']] ?? 0;

        if ($current < $required) {
            self::deny('Insufficient permissions', 403);
        }
    }

    private static function deny(string $msg, int $code = 401): void {
        http_response_code($code);
        echo json_encode(['success' => false, 'error' => $msg]);
        exit;
    }

    /**
     * Validate against local admin credentials (standalone mode).
     * Credentials are stored as a bcrypt hash in the settings table.
     */
    public static function validateLocal(string $username, string $password): bool {
        $storedUser = Database::setting('local_admin_user', 'admin');
        $storedHash = Database::setting('local_admin_hash', '');

        if ($storedHash === '' || $username !== $storedUser) return false;
        return password_verify($password, $storedHash);
    }

    /**
     * Set the local admin password (called during standalone install and from GUI).
     */
    public static function setLocalCredentials(string $username, string $password): void {
        Database::setSetting('local_admin_user', $username);
        Database::setSetting('local_admin_hash', password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]));
    }

    /**
     * Auto-login for cPanel mode: trust REMOTE_USER set by cPanel's webserver.
     * Returns a JWT if REMOTE_USER is present and non-empty, null otherwise.
     */
    public static function autoLoginCpanel(): ?string {
        // cPanel sets REMOTE_USER when the plugin page is loaded inside the
        // cPanel/WHM UI.  If it's absent (direct browser hit, non-cPanel), bail.
        $remoteUser = $_SERVER['REMOTE_USER'] ?? '';
        if ($remoteUser === '') return null;

        $role = ($remoteUser === 'root' || $remoteUser === 'cpanel') ? 'admin' : 'user';
        return self::generateToken($remoteUser, $role);
    }

    public static function hashPassword(string $password): string {
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    }

    public static function verifyPassword(string $password, string $hash): bool {
        return password_verify($password, $hash);
    }
}
