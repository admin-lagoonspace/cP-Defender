# Changelog

All notable changes to Sentinel Gate are documented here. This project follows
semantic versioning (X.Y.Z): patch = fixes, minor = new features, major = infra.

## [3.8.0] — 2026-08-08

### Added
- **Licensing (WHMCS Licensing Addon).** `backend/lib/License.php` verifies the
  license against the WHMCS licensing server and caches the returned signed local
  key, so the server is contacted roughly every 15 days rather than on every page
  load. Local keys are validated through both md5 layers and bound to the issuing
  hostname, so a key cannot be copied to another server. The `md5hash` echo of our
  `check_token` is verified with `hash_equals` to reject replayed responses.
- `sentinel license status | activate <key> | refresh` CLI subcommands. `activate`
  and `refresh` exit non-zero on a rejected key so scripted installs can branch.
- `GET license/status`, `POST license/activate`, `POST license/refresh` API routes.
- **Settings → License** panel: status badge, expiry, last-checked time, key entry
  and a manual re-check.

### Behaviour
- **Protection never stops for licensing reasons.** Scanning, firewall
  enforcement, the real-time monitor and quarantine run regardless of license
  state — they do not pass through the API and are not gated. Only management
  endpoints are. An unreachable license server is a warning for a 10-day grace
  period, not a failure; only an explicit Invalid/Expired/Suspended verdict locks
  the UI. A licensing fault must never turn into a fleet-wide security incident.
- `auth`, `license` and `system` routes stay reachable when unlicensed, so an
  operator can always sign in and enter a key rather than being locked out.
- Gated calls return `402` with `needs_license`; the UI intercepts this centrally
  and opens the License panel instead of showing a generic error.

## [3.7.1] — 2026-08-07

### Fixed
- **Unattended standalone installs hung forever.** When the installer ran piped
  (`curl … | bash`) in standalone mode it still prompted for an admin password.
  `read` hit EOF on the pipe, `ADMIN_PASS` stayed empty, and the minimum-length
  loop spun indefinitely. The installer now never prompts on a non-TTY: supply a
  password via `--admin-pass` / `SG_ADMIN_PASS`, or one is generated and printed
  in the completion summary.
- **Piped installs picked the wrong mode on non-cPanel servers.** A
  non-interactive install with no prior config defaulted to `cpanel`
  unconditionally, so plain Linux servers ran the whole WHM registration path
  against nothing and ended up with no working dashboard. Mode is now probed
  from `/usr/local/cpanel` and falls back to `standalone`.

### Added
- **Self-hosted install channel.** `get.sh` and `update.sh` now resolve releases
  from `https://defender.lws-s1.com/sentinel-gate/code` first and fall back to
  the GitHub raw mirror automatically. This keeps installs and updates working on
  servers whose firewall blocks github.com. The `sha256` in `latest.json` is
  verified no matter which channel served the file, so fallback is safe.
- `--admin-user` / `--admin-pass` installer flags (and `SG_ADMIN_USER` /
  `SG_ADMIN_PASS` env equivalents — preferred, since flags are visible in `ps`).
- `scripts/upload-cdn.sh` publishes a release to the CDN and then verifies the
  live manifest version and zip checksum before reporting success.

## [3.7.0] — 2026-07-23

### Added
- **`sentinel` command-line interface.** New `/usr/bin/sentinel` wrapper backed by
  `backend/cli/sentinel.php`, reusing the same config and library classes as the
  web app. Subcommands: `version`, `status`, `scan [path] [--full|--quick]`,
  `firewall list|block|unblock|allow`, `reputation <ip>`, `update-sigs`. Add
  `--json` to any command for machine-readable output. (Parity with CPGuard's `cpgcli`.)
- **OS dependency bootstrap in the installer.** On a bare server the installer now
  best-effort installs missing runtime dependencies via apt/dnf/yum
  (`sqlite3`, `python3`, `ipset`, `inotify-tools`, ClamAV, and — on non-cPanel
  hosts only — PHP + sqlite PDO). Non-fatal; skip with `--no-deps`. PHP is never
  auto-installed on cPanel servers, which manage their own PHP.

### Notes
- The CLI is installed in the always-run section, so existing installs pick it up
  automatically on their next update via `--register-only`.

## [3.6.0] — 2026-07-23

### Added
- **CSF / LFD firewall integration.** The installer now registers persistent CSF
  includes (`csf.allow`, `csf.ignore`) and exempts Sentinel Gate's long-running
  root daemons from LFD process tracking via `csf.pignore`, then reloads CSF.
- **ModSecurity Apache hook.** The installer injects an `Include` into
  `modsec2.user.conf` pointing at the WAF module's custom rules file, so WAF rules
  load inline in Apache instead of staying app-level only.
- **WHM plugin icon.** A 48×48 icon generated from the brand logo is installed to
  `addon_plugins/` and referenced by the WHM AppConfig entry.

### Fixed
- **Real-time monitor watch limit.** The installer now raises
  `fs.inotify.max_user_watches` (to 1048576) via `/etc/sysctl.d/`. Previously the
  monitor could silently stop receiving events on busy servers once the low
  default limit was exhausted.
- **SELinux cron execution.** On SELinux-enforcing hosts the installer applies the
  `system_cron_spool_t` context to `/etc/cron.d/sentinel-gate` so scheduled scans
  actually run.

### Uninstaller
- All new artifacts (sysctl file, CSF includes, ModSecurity include, plugin icon,
  CLI wrapper, config dir) are removed symmetrically on uninstall.
