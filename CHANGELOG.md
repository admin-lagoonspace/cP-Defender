# Changelog

All notable changes to Sentinel Gate are documented here. This project follows
semantic versioning (X.Y.Z): patch = fixes, minor = new features, major = infra.

## [3.8.2] — 2026-08-08

### Fixed
- **The local-key cache never worked.** The client read `localkey` from the
  WHMCS response, but the addon does not send one — the client is required to
  build it from the reply. Nothing was ever cached, so every page load, cron run
  and CLI call would have made a fresh remote check, hammering the licensing
  server and failing closed the moment it was briefly unreachable.
- **`decodeLocalKey()` used the wrong layout.** It read 8 bytes off the front as
  a date; in the real format the first 32 bytes after `strrev` are
  `md5(checkdate + secret)`, and `checkdate` lives *inside* the serialised
  payload, so it can only be verified after unserialising. Any key that had been
  written would have failed to validate.
- Both are now implemented to the addon's actual format and proven by a
  round-trip test: build → decode recovers `Active`, and wrong secret, flipped
  byte, truncation, host copy and a key forged without the secret are all
  rejected.

### Changed
- `SG_WHMCS_URL` defaults to the real licensing server. Verified live: a POST to
  `/modules/servers/licensing/verify.php` returns `<status>Invalid</status>` for
  an unknown key, matching the parser.
- The local-key salt is read from `SG_LICENSE_SECRET` in `mode.php`, written by
  the installer, rather than being a constant in a public repository.
- The local key is bound to the issuing hostname and IP at build time, so a key
  lifted from one server is rejected on another.

## [3.8.1] — 2026-08-08

### Changed
- **Every feature now requires a valid license.** 3.8.0 gated only the
  management UI; scanning, firewall, WAF, IP reputation and real-time monitoring
  kept running unlicensed, which gave the product away. Enforcement now covers
  every path that can do work:
  - **Web API** — all modules. Only `auth` and `license` stay reachable, because
    without them an unlicensed server could never be given a key and would be
    unrecoverable.
  - **Cron** — `backend/cron/scan.php` exits unless licensed. Scheduled scans
    never touch the API, so without this an unlicensed server kept scanning
    hourly forever.
  - **Monitor daemon** — checked at startup *and* re-checked periodically. A
    startup-only check would let a license that lapses keep a long-running
    daemon alive indefinitely.
  - **CLI** — `scan`, `update-sigs`, `reputation` and firewall write operations.
    `firewall list` stays open so an operator can still inspect state.
- The daemon is Python and cannot validate a signed local key, so PHP publishes
  its decision to the settings table and the daemon reads it. The flag carries a
  timestamp and is rejected once older than 3 days: otherwise a customer could
  license once, remove the cron that refreshes it, and run indefinitely on a
  permission that is never re-verified.
- The grace window is retained and is the only softness: a license that verified
  successfully keeps working for 10 days if the licensing server later becomes
  unreachable. It cannot be reached without having been licensed, since it
  requires a local key already signed for that hostname. It exists so an outage
  at the licensing server does not disable protection across every paying
  customer at the same moment.

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
