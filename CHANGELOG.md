# Changelog

All notable changes to Sentinel Gate are documented here. This project follows
semantic versioning (X.Y.Z): patch = fixes, minor = new features, major = infra.

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
