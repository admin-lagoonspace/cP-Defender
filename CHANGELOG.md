# Changelog

All notable changes to Sentinel Gate are documented here. This project follows
semantic versioning (X.Y.Z): patch = fixes, minor = new features, major = infra.

## [3.10.3] — 2026-08-08

### Added
- `scripts/prep-logo.py` — prepares supplied artwork for the dark UI. It reports
  what the file actually is (transparency, content box) and writes three
  variants: a trimmed transparent lockup with a light wordmark for the dark UI,
  one with original colours for light surfaces, and a 256x256 shield icon.

  Two problems it solves, both hit repeatedly by hand:
  - An untrimmed export is mostly empty margin, so a `contain` fit sizes the
    MARGINS to the box and the logo renders at roughly a third of the space.
  - A wordmark drawn dark for white backgrounds is dark-on-dark once placed on
    the topbar. Only near-neutral dark pixels are recoloured, so the shield's
    blues survive — a blanket invert would destroy the artwork. Measured on a
    representative asset: 116,476 dark pixels lightened, 98,923 blue retained.

### Changed
- The brand panel is transparent again; the white plate added in 3.10.2 is gone.
  It only existed to keep a dark wordmark readable, and preprocessing removes
  that need.

## [3.10.2] — 2026-08-08

### Changed
- **The topbar brand column is now a single logo space.** It previously held a
  cropped icon plus separate HTML text, which read as two elements rather than
  one brand. It is now one image filling the panel, with no text beside it — the
  supplied lockup already contains the wordmark.
- The panel has a light background. The lockup is dark-navy artwork on white, so
  knocking the white out would leave the wordmark dark-on-dark and effectively
  invisible. Swapping in a transparent asset with light text reduces this to
  `background: transparent`.
- Sizing uses `cover`, not `contain`. The artwork occupies a ~3.2:1 band across
  the middle of a 3:2 frame, so `contain` fitted the empty margins and left the
  logo at 35% of the panel width; `cover` crops the blank top and bottom instead
  and fills 90%. The crop only removes whitespace, never the wordmark.

## [3.10.1] — 2026-08-08

### Changed
- Logo artwork switched to the shield/server/firewall mark. It carries no
  wordmark, so the product name is now always rendered as text on the login
  screen rather than only as an error fallback — otherwise the login would show
  a picture and no product name. The topbar crop was retuned for the new
  composition (the mark occupies roughly the left half of a 3:2 frame).

### Fixed
- **Frontend assets are now cache-busted with the version.** A browser holding a
  cached `app.css` rendered the unstyled logo at its natural 1536px, covering the
  entire page. On a customer server the same staleness would silently pair new
  markup with old styles after an update. `index.html` references
  `app.css?v=<version>`, and `make-release.sh` re-stamps it on every build so it
  cannot drift.
- Both `<img>` tags carry intrinsic `width`/`height`. If the stylesheet is
  cached, delayed or missing, the image is still bounded instead of rendering at
  full size, and the box is reserved so the topbar does not reflow while loading.

## [3.10.0] — 2026-08-08

### Changed
- **New logo, and the UI palette now follows it.** The interface was violet
  (#7f5af0) from the 3.4.0 redesign while the new logo is blue; a blue mark on a
  violet interface reads as inconsistent, most obviously in the topbar where the
  two sit side by side. The logo is the fixed brand asset, so the UI moved:
  primary is now #1e6fe8 sampled from the wordmark, with #4a9eff highlights, and
  backgrounds shifted from neutral charcoal to navy-tinted (#0a0d16) so the
  artwork sits in the surface rather than on top of it. Emerald is retained for
  success states — it matches the server LEDs in the logo.
- The topbar and login screen use the full horizontal lockup. The wordmark is
  part of the artwork, so the separate HTML "Sentinel Gate" text is gone —
  keeping both would render the name twice, which is the duplication fixed in
  3.9.1.
- The lockup is constrained by height, not width, so a wide horizontal asset
  cannot push the navigation out of the topbar.
- If the logo file is missing the markup falls back to styled text, rather than
  leaving a broken-image box in the header.

## [3.9.1] — 2026-08-08

### Fixed
- **The Sentinel Gate brand appeared twice.** The topbar brand already occupies
  the sidebar-width column, and a second identical lockup was added directly
  below it in the sidebar — so the logo and name rendered twice, stacked. The
  sidebar copy is removed, along with its now-dead CSS.
- **Removed the "cPANEL" pill from the top right.** The install mode is already
  shown in the sidebar footer; repeating it in the header added nothing.
- **The brand collided with the navigation below 900px.** `--sidebar-w` drops to
  `0` at that breakpoint so the sidebar can slide away, which also collapsed
  `.topbar-brand` to its padding — the name then wrapped to two lines and
  overlapped the first nav item. The brand lives in the topbar, which is always
  visible, so it now keeps a 200px floor independent of the sidebar, and the
  name and tagline no longer wrap. Verified at 735px and 1280px.

## [3.9.0] — 2026-08-08

### Added
- **User-configurable schedules.** `scan_schedule` existed as a setting and the
  UI already had the dropdown, but nothing consumed it — the crontab was
  hardcoded, so changing it did nothing. `backend/cron/scheduler.php` now runs
  every 15 minutes and decides what is due from the settings, which are the
  single source of truth.
- **Scheduled IP reputation refresh** (default daily, configurable hourly /
  daily / weekly / off). Previously reputation was only ever checked on demand.
  Each run re-checks addresses seen attacking the server in the last 7 days,
  capped at 200, so the work does not grow without bound.
- Settings → Scanner now exposes scan schedule, run time, day, and scan type;
  Virus Definitions exposes update frequency, day, last-updated and an "Update
  now" button; IP Reputation exposes refresh frequency with last-run and count.
- Timing fields are shown only when the chosen schedule uses them, so nobody
  sets a "day of week" on a daily schedule and wonders why it is ignored.

### Changed
- The installer writes one cron line (the dispatcher) instead of four fixed
  jobs. Rewriting `/etc/cron.d` whenever a dropdown changes would need root at
  runtime, race with the file being read, and drift from the UI if any single
  write failed.
- Scheduling is elapsed-time based, not wall-clock match: a task that misses its
  window because of a reboot or a slow tick runs late rather than being skipped
  until the next day. Verified with 13 cases including missed windows and that
  40 consecutive ticks after a completed daily run produce zero re-fires.

### Fixed
- The License panel still stated that protection continues without a license.
  That stopped being true in 3.8.1, when every feature became licensed.

### Note
- Weekly virus-definition updates already existed (`0 1 * * 0`) and continue,
  now driven by the setting rather than the crontab.

## [3.8.3] — 2026-08-08

### Fixed
- **The reported server IP differed between web and CLI contexts**, which would
  have broken one-license-per-IP enforcement. `$_SERVER['SERVER_ADDR']` only
  exists during a web request, so the dashboard reported the address Apache bound
  to while cron and the CLI reported the DNS answer. On multi-homed, NAT'd or
  proxied hosts those differ, and WHMCS would see one license checking in from
  two addresses — which reads as a conflict and can invalidate a paying customer.
  Resolution is now deterministic in every context and pinned on first use, so a
  transient DNS change cannot silently re-identify the server.

### Added
- `sentinel license identity` and an `identity` block on `license status`,
  showing the exact domain/IP/dir sent to WHMCS. A one-license-per-server
  rejection is almost always explained by these values, and previously there was
  no way to see them.
- An `Invalid` verdict now explains that the license may already be active on
  another server and points at reissue. WHMCS returns `Invalid` both for an
  unknown key and for one bound elsewhere; the customer cannot tell those apart,
  and the second becomes the common support case once conflicts are enforced.

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
