# Changelog

All notable changes to Sentinel Gate are documented here. This project follows
semantic versioning (X.Y.Z): patch = fixes, minor = new features, major = infra.

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
