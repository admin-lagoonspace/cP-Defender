# Changelog

All notable changes to Sentinel Gate are documented here.

Versioning (X.Y.Z):
  Z (patch) — fixes, UI work on a feature that already shipped, docs, refactors
  Y (minor) — NEW features, or an architectural change
  X (major) — reserved

Bumping Y for a fix inflates the version and hides what actually changed.
`scripts/check-version-bump.sh` enforces this and `publish.sh` will refuse a
release where the bump and the commits disagree.

## [3.19.5] — 2026-08-27

### Fixed
- **The dashboard showed a login screen that could never succeed on cPanel.**
  cpsrvd refuses to execute any CGI in the WHM docroot that is not registered
  with AppConfig, answering with a 403 HTML page:

      WHM is configured to disallow execution of unregistered applications
      when logged in as root or a reseller with the "all" ACL

  Only `sentinel_gate.cgi` was registered, so the dashboard loaded while every
  request to the separate `api.cgi` was refused. `api.js` could not parse the
  403 HTML, every candidate endpoint failed, auto-login never completed, and the
  page fell back to its default state — the login form.

  This survived several releases because the shell bypasses cpsrvd entirely:
  invoking `api.cgi` from a root prompt worked perfectly, and did so right up
  until the browser was finally asked to make the same call.

  The registered CGI now serves both. A request carrying `?r=` is handled as the
  API; anything else returns the dashboard. Static assets are unaffected —
  cpsrvd serves css/js/images as files rather than as applications, which is why
  they always loaded.

  Registering a second application would also have worked but adds a second WHM
  menu entry, and `permit_unregistered_apps_as_root` would weaken the server to
  suit this plugin. Neither is acceptable when one entry point does the job.

- The stale `api.cgi` is removed on upgrade, and `./api.cgi` is kept in the
  client's candidate list only so a part-upgraded install still finds an
  endpoint.

## [3.19.4] — 2026-08-27

The backend reached a working state in 3.19.3 — `auth/auto-login` returns a valid
token and `auth/status` is clean. These are the faults its own error logs then
exposed.

### Fixed
- **Every scheduled task died with "Undefined constant SG_DB".** Three CLI entry
  points (the cron scheduler, the update checker, the firewall boot unit) loaded
  `mode.php` instead of `config.php`. `mode.php` records the install mode and
  paths but does not define `SG_DB`, so `Database::get()` threw on every run —
  meaning scheduled scans, signature updates and IP reputation checks were all
  failing silently. They now load `config.php`, which includes `mode.php` itself.
- **A PHP warning on every request.** `config.php` defines `SG_ROOT` and
  `SG_VERSION` and then includes `mode.php`, which redefined both. The defines in
  `mode.php` are now guarded, so it can be included from either direction.
- **`https://<host>/sentinel-gate/` served a dashboard that could never work.**
  On cPanel that Apache copy has no PHP handler and would run as the web user
  regardless, yet it looks identical to the real UI and fails every API call —
  an old bookmark lands on a login form that cannot succeed. It now redirects to
  the WHM plugin. The hostname is resolved client-side, so nothing is baked in.
- The plugin page is served `Cache-Control: no-store`, so an updated dashboard
  is never masked by a cached copy of the previous one.

## [3.19.3] — 2026-08-27

### Fixed
- **3.19.2 shipped a zero-byte `config.php`.** A bump script wrote it with
  `open(path,'w').write(open(path).read())` — opening for writing truncates the
  file *before* the read runs, so it read back empty and wrote nothing. Since
  every PHP file requires config.php, and the runtime guards test constants it
  defines, the API answered "Direct access denied" to everything. This is almost
  certainly what truncated the same file originally. Restored from the last good
  commit, repaired, and re-stamped.
- **The WHM plugin still showed a login form.** SSO was attempted only when
  `detectMode()` had already succeeded, so one failed request left the user at a
  password prompt on a server where WHM had authenticated them. SSO is now
  attempted unless the install is positively known to be standalone; the
  endpoint refuses in standalone mode anyway, so asking is always safe.

### Changed
- The dashboard **opens in its own tab** instead of inside the WHM content
  frame. When framed it moves to a new tab, falling back to a single prominent
  link when the popup is blocked (a blocked popup is expected, not an error).

### Added
- `scripts/preflight.py` and `scripts/build.py`. The release was being built by a
  throwaway script in a temp directory, so every gate lived in `make-release.sh`
  — which cannot run on the machine releases are cut on, because there is no
  `zip` and no system `php`. Both now live in the repository and run everywhere.
- Preflight rejects **empty** PHP files. `php -l` reports success on a zero-byte
  file, so the parse gate passed 3.19.2's empty config.php cleanly. It also
  asserts config.php defines the constants the runtime guards require, and that
  its `SG_VERSION` matches `./VERSION`.
- The packaged zip is re-checked after zipping, so a payload cannot ship with an
  empty or absent config.php even if the source tree looked fine.

## [3.19.2] — 2026-08-27

### Fixed
- **`backend/config/config.php` was truncated mid-file and had been for at least
  eight releases.** It ended part-way through a string literal in the `RBL_FEEDS`
  array — `'spamco` — so the file was a parse error, and since every other PHP
  file requires it, *nothing* server-side could run. It never surfaced because
  the API returned 501 before PHP was ever asked to parse it; the moment 3.19.1
  got PHP actually executing, this was the first thing it hit. The array is
  closed and the missing entries restored.

### Changed
- The build's syntax gate now uses a repository-local PHP interpreter and
  **fails the build when no interpreter is available**, instead of warning and
  continuing. The gate added in 3.19.0 looked for `php` on PATH; releases are
  built on Windows, where there is none, so it skipped itself every time while
  printing a reassuring line. That is precisely how a file truncated mid-string
  shipped eight times. Set `SG_ALLOW_UNVERIFIED=1` to build without it
  deliberately.
- All 27 PHP files now parse. This is the first release where that has ever been
  verified rather than assumed.

## [3.19.1] — 2026-08-27

### Fixed
- **Every authenticated request died under cpsrvd.** `Auth::requireAuth()` called
  `getallheaders()`, which exists under mod_php and PHP-FPM but not under the CGI
  SAPI that cpsrvd uses — an undefined-function fatal on each call. The header is
  now read from `$_SERVER` first (`HTTP_AUTHORIZATION`, then
  `REDIRECT_HTTP_AUTHORIZATION`), with `getallheaders()` used only where it
  exists. CGI also drops the Authorization header outright on many servers, which
  this covers too.
- **The WHM plugin asked for a username and password.** Arriving through WHM the
  request is already authenticated as root, and cpsrvd sets `REMOTE_USER`. That
  is now accepted, so no sign-in form appears inside WHM — as the wiki always
  said it would not.
- **`api.cgi` could emit its own shebang into the response body.** The CGI SAPI
  does not reliably strip a `#!` line, and when it does not, the body begins with
  the interpreter path followed by JSON — unparseable, and surfacing as the same
  generic "Server error". The endpoint is now a `/bin/sh` wrapper that hands
  php-cgi the target via `SCRIPT_FILENAME`, so the file parsed as PHP has no
  shebang, and status codes (401, 402) still come through.
- The installer's API self-test now requires the body to *begin* with `{` rather
  than merely contain a brace, since the failure it guards against is stray bytes
  in front of otherwise valid JSON.

## [3.19.0] — 2026-08-26

Minor, not patch: this changes how the plugin is served on cPanel.

### Fixed
- **The dashboard loaded but nothing in it worked on cPanel.** Every API call
  returned `501 Not supported`, so each panel independently rendered "Server
  error" or stayed blank. The plugin CGI redirected to an Apache alias, and
  Apache only executes PHP in an aliased directory when a loaded module claims
  the handler — on EA4 that may be mod_php, mod_lsapi, PHP-FPM or suPHP. The
  installer guessed the handler from the CLI PHP binary, which is not
  necessarily an EasyApache build.
- **The API ran as the web user.** Even where the handler resolved, Apache would
  have executed it as `nobody`, which cannot run nft/iptables, quarantine a file
  or read `/proc` — the things this product exists to do.
- **A failed dashboard load left "Protected" on screen.** The markup ships that
  state pre-rendered and the failure path returned silently, so a server whose
  API answered 501 to every request displayed a green tick and a clean bill of
  health. It now shows "Status unknown / API unreachable" and blanks the tiles.
- Errors were both hidden and unlogged (`error_reporting(0)`), so a failure could
  only ever appear as "Server error" with no trace on the server. Errors are now
  logged to `logs/php-error.log`, never displayed, and a shutdown handler
  guarantees a JSON envelope even on a fatal.
- Route parsing searched for a literal `api` path segment and mis-parsed under
  any path without one.

### Changed
- On cPanel the UI and API are now served by **cpsrvd** from the WHM CGI
  directory, as CSF and other established WHM plugins do. cpsrvd runs them as
  root, is always present, and puts the UI and API on one origin. The Apache
  alias remains for standalone Linux, where it is the right mechanism.
- Routing travels in `?r=module/action`, which needs neither mod_rewrite nor
  PATH_INFO and therefore behaves identically under cpsrvd, Apache and the
  standalone router.
- The API client discovers its endpoint by probing candidates and caching the
  first that returns JSON, instead of assuming one relative path.

### Added
- The installer now **invokes the API and requires JSON back** before reporting
  success. The previous installer declared success without ever calling it.
- `make-release.sh` runs `php -l` over `backend/` and refuses to build on a parse
  error.

### Documentation
- The wiki claimed PHP 7.4+. The code uses `match()` and `str_contains()`, both
  PHP 8.0+, so it could never have run on 7.4. Corrected to 8.0+.

## [3.18.2] — 2026-08-11

### Fixed
- Release notes published to the CDN are now the notes for that one version.
  Every `v<version>/CHANGELOG.md` was a verbatim copy of this whole file, so a
  user opening the notes for the release they just installed got the entire
  project history instead of what changed. `scripts/extract-notes.sh` pulls the
  single section; `make-release.sh` writes it to `dist/notes-<version>.md` and
  into the version folder.
- `cdn-sync.sh` no longer falls back to the repo-root `CHANGELOG.md` when the
  per-version notes are missing — that fallback was what produced the full-history
  copies in the first place. It now reports missing notes and publishes none.
- The `notes` URL in `latest.json` points at the version's own notes rather than
  the full changelog on GitHub.

`CHANGELOG.md` in the repository remains the complete history; only what ships
per release changed.

## [3.18.1] — 2026-08-08

### Added
- `scripts/check-version-bump.sh` — compares the bump in `VERSION` against the
  commit subjects since the last tag and fails the release when they disagree.
  `publish.sh` runs it in strict mode.

### Note
- The versioning convention was already stated at the top of this file and was
  still not followed. 3.14.0, 3.16.0 and 3.17.0 all bumped the minor for work
  that was a fix or UI on an already-shipped feature — 3.16.0's own commit
  subject begins `fix:`. A rule that lives only in a document gets ignored, so
  it is now enforced by the release script. Verified by replaying 3.16.0
  through the checker, which correctly rejects it.
- This release is itself a patch: tooling and docs, no new product capability.

## [3.18.0] — 2026-08-08

### Added
- **3-day trial from install.** A fresh installation runs with full protection
  for three days, so the product is usable immediately and licensing can be
  completed afterwards. The dashboard shows a banner with the days remaining —
  protection stopping one day with no warning would look like a fault rather
  than an expiry.
- The installer stamps the trial start at install time, not first login. A
  server set up and left alone would otherwise still show three full days
  whenever someone eventually opened the dashboard.

### Trial cannot be reset
- It applies **only to an install that has never had a key entered**. Storing a
  key — even one that is rejected — sets `license_ever_entered` permanently, so
  a customer whose licence expires cannot clear it and be handed another free
  period, repeatedly.
- The install timestamp is written to both the database and
  `/var/lib/sentinel-gate/installed-at`, and the **earliest** of the two is
  used. Either alone would be trivial to reset; the marker is outside the
  install directory so an update, which rsyncs it with `--delete`, cannot clear
  it, and a missing copy is restored from the other rather than starting fresh.
- Verified across seven scenarios including "expired key cleared on day 1",
  which correctly grants nothing.

## [3.17.0] — 2026-08-08

### Changed
- **Installing is open to everyone; the product asks to be licensed in the UI.**
  Enforcement is unchanged — nothing runs unlicensed — but the unlicensed state
  is now a designed step instead of a failure state.
- **New activation screen.** Shown on first sign-in in place of the dashboard,
  with the key field, what a licence includes, and a re-check link. Previously
  the 402 surfaced as a red error toast plus a jump into Settings, which made a
  working install look broken.
- The gate runs **before** the dashboard loads, not after. Letting the pages
  load first meant every panel fired a request that was refused and rendered
  empty behind the message.
- Each verdict gets its own wording. "Enter your key" is wrong advice for a key
  that exists but has expired, so Expired, Suspended, Invalid and Unknown each
  say what actually applies.
- A licence check that cannot complete no longer blocks the dashboard. The API
  still refuses every gated route, so nothing is exposed — but a paying customer
  is not locked out of their own interface by a network blip.
- The installer now ends by telling the operator to activate. Without it they
  open the dashboard, find everything refused, and reasonably conclude the
  install failed.

## [3.16.0] — 2026-08-08

### Fixed
- **ClamAV was installed and then never used on cPanel servers.** `runClamScan`
  tested the hardcoded `CLAMSCAN_BIN` (`/usr/bin/clamscan`), but cPanel ships
  ClamAV at `/usr/local/cpanel/3rdparty/bin/clamscan`. The installer detects the
  real path and stores it in `clamscan_path` — which nothing read. Every scan on
  those servers silently fell back to the pattern engine while ClamAV sat
  installed and idle. The scanner now resolves the stored path, then the
  constant, then the known locations.
- **Scans no longer run against an empty signature database.** A freshly
  installed ClamAV has no signatures until `freshclam` completes, and clamscan
  errors on every file until then. The scanner now checks for a signature
  database and uses the pattern engine — which needs none — when it is absent.
- **Signature download on Debian/Ubuntu.** The `clamav-freshclam` daemon starts
  automatically on install and locks the database directory, so the installer's
  manual `freshclam` run failed with a lock error. That surfaced only as a vague
  "signature update failed" and left the scanner with no signatures at all. The
  daemon is now stopped for the initial fetch and handed the job afterwards.

### Changed
- The initial signature download is bounded (15 min) so a slow or blocked mirror
  cannot hang the installer indefinitely.
- The installer **verifies** the signature database exists rather than assuming
  the download worked, and says plainly when it does not — reporting the scanner
  as ready when it cannot match anything is worse than admitting the gap.
- `clamav-freshclam` is enabled so signatures stay current between the
  scheduler's weekly update.
- When ClamAV is absent entirely the installer now states that scanning
  continues via the built-in pattern engine, which needs no signature database —
  ClamAV broadens coverage rather than being required.

## [3.15.0] — 2026-08-08

### Added
- **WAF engine provisioning** (`backend/lib/WAFInstaller.php`). Sentinel Gate
  installs and configures ModSecurity and the OWASP Core Rule Set itself,
  closing the last wrapper-without-an-engine gap. Detects the platform
  (EA4/cPanel, RHEL httpd, Debian) and installs the right package.
- WAF page shows engine status and offers a one-click install with a
  step-by-step log, then a mode selector once it is running.
- `GET waf/engine-status`, `POST waf/engine-install`, `POST waf/engine-mode`.

### Safety decisions
- A fresh install runs in **DetectionOnly** — attacks are logged, not blocked.
  A WAF that rejects legitimate traffic is worse than none, because the operator
  hears about it from customers. Switching to blocking is deliberate and
  confirmed.
- **Apache config is validated before any reload.** An invalid include would
  otherwise take the web server down on restart, and with it every hosted site.
  If validation fails the include is removed and nothing is reloaded.
- `/sentinel-gate` is exempted from the rules, so a false positive cannot lock
  the operator out of the page needed to turn the WAF off.
- The install button only appears when a supported package manager exists — a
  button that always fails is worse than no button.
- The uninstaller removes the Apache include; left behind it would reference a
  deleted config and Apache would fail its next restart.

## [3.14.0] — 2026-08-08

### Added
- **Blocklist matrix UI** on IP Reputation. Shows all 25 services with the
  server's own IP prefilled, listed entries sorted to the top and highlighted,
  each with its reason and a delisting link. `refused` is shown distinctly from
  `clean`, since a refused query is an unknown result rather than a pass.
- **Built-in rootkit scan UI** on Rootkit Scan — a second button that runs the
  native engine, with findings sorted by severity and each showing why it
  matters.

### Fixed
- **XSS in the new tables.** They interpolated values into `innerHTML` through
  an `esc()` helper that did not exist anywhere in the codebase, so the calls
  would have thrown. Escaping is not optional here: blocklist reasons derive
  from DNS answers and rootkit findings embed filesystem paths, so a file named
  `<img onerror=…>` would have executed script in the admin's browser — from
  inside the tool meant to detect that attacker. `esc()` is now defined and
  verified against several payloads.

### Known gaps
- **WAF has no engine of its own.** It reads ModSecurity's configuration and
  audit log; with ModSecurity absent it reports status and nothing else. Unlike
  the firewall, rootkit and blocklist modules, no built-in replacement is
  provided — real request filtering has to sit in the request path (an Apache
  module or a PHP prepend), which is a different architecture rather than an
  addition to this class. Documented rather than silently left looking complete.

## [3.13.0] — 2026-08-08

### Added
- **Built-in rootkit engine** (`backend/lib/RootkitEngine.php`). Detection now
  works on a bare server. The previous scanner wrapped rkhunter/chkrootkit and
  returned "rkhunter is not installed" when neither was present — inert on
  exactly the machines most likely to need it. rkhunter is still layered on top
  when available for its curated signature database; this is the floor, not a
  replacement.

  Checks are mostly **behavioural rather than signature-based**, because
  signature lists age badly. A rootkit can rename its files; it cannot hide a
  process or preload a library without ceasing to be a rootkit:
  - `/etc/ld.so.preload` and global `LD_PRELOAD` — the standard userland hook
  - **Hidden processes**: `/proc` compared against `ps`. A PID visible in one and
    not the other means the userland tool is lying, which catches a rootkit whose
    files are entirely unknown to us
  - **Package integrity**: `rpm -Vf` / `dpkg --verify` on core binaries — the
    strongest check available, comparing against the distribution's own hashes
    rather than any list we ship
  - Orphaned kernel modules, unexpected SUID binaries, hidden files in system
    directories, UID 0 accounts, empty passwords, promiscuous interfaces,
    cron droppers (`curl|sh`), and sshd misconfiguration
  - Every finding carries a severity **and an explanation** of why it is
    suspicious, since several checks have legitimate causes
- `POST rootkit/scan-builtin`

- **Full blocklist matrix** (`backend/lib/BlocklistRegistry.php`). IP reputation
  now checks **25 DNSBL/RBL services** and reports each one separately, instead
  of four collapsed into a single score. Delisting requires knowing *which*
  service lists you, which a single number cannot tell an operator — each result
  carries the return code, the decoded reason, and the delisting URL.
  - Lists are **weighted by category**: an exploit/botnet listing scores far
    higher than a policy listing such as a dynamic-IP range, which is normal for
    residential space and not evidence of abuse. A flat count would rank those
    equally.
  - **Refusal answers are not treated as listings.** Several zones (Spamhaus in
    particular) return `127.255.255.x` to public resolvers meaning "query
    refused". Counting that as a hit would report every address on the internet
    as blacklisted. Reported as `refused` — result unknown, explicitly not clean.
  - `iprep/server-ips` detects the host's own public addresses, which is what an
    operator most wants checked.
- `GET iprep/blocklists?ip=…` and `GET iprep/server-ips`

## [3.12.0] — 2026-08-08

### Added
- **Built-in firewall engine** (`backend/lib/FirewallEngine.php`). Sentinel Gate
  now manages the packet filter itself — no separate firewall has to be
  downloaded, installed or learned first.
  - Backends, in precedence order: **CSF** (respected if already installed),
    **firewalld**, **nftables**, **iptables**. Order matters: detecting iptables
    first would be wrong on every modern RHEL host, where iptables exists but
    firewalld owns the ruleset and would flush our rules on its next reload.
  - All rules live in a dedicated namespace — `table inet sentinel_gate` or the
    `SENTINEL_GATE` chain — so nothing belonging to another tool or the operator
    is ever touched, and the uninstaller can remove exactly what we added.
  - nftables uses named sets, so matching stays O(1) no matter how many
    addresses are blocked. One rule per IP degrades badly past a few thousand.
  - `flags interval` sets accept CIDR, so a whole offending range can be blocked.
- **Automatic firewall provisioning.** If no packet filter exists at all, the
  installer installs nftables rather than leaving the firewall UI inert.
- `GET firewall/engine` and `POST firewall/engine-init`.

### Fixed
- **Blocked IPs no longer disappear on reboot.** nftables and iptables keep
  rules in kernel memory only, and nothing was persisting them — so after a
  restart every block was gone while the database still listed them as active.
  The product was reporting protection it was not providing. Rules are now saved
  to `/etc/sentinel-gate/` and re-applied by a `sentinel-gate-firewall` boot
  unit ordered before the network comes up.
- **No longer writes loose rules into INPUT.** The previous fallback ran
  `iptables -I INPUT -s <ip> -j DROP`, which is indistinguishable from anyone
  else's rules, cannot be cleanly removed, and is silently erased by firewalld.
- `latest.json` had drifted to 3.9.1 while `VERSION` said 3.11.0, so the update
  channel was advertising an old build. Realigned.

### Note on provenance
- The engine is a **clean-room implementation**, deliberately not derived from
  CSF or CPGuard. CSF was discontinued on 2025-08-31 and released as-is under
  **GPLv3**; code derived from it would make Sentinel Gate a derivative work and
  oblige us to publish its source under GPLv3, which is incompatible with
  licensing it commercially. CPGuard is proprietary. Behaviour and features are
  not copyrightable — only code is — so the same capabilities are implemented
  from first principles against the kernel's own interfaces.

## [3.11.0] — 2026-08-08

### Added
- **One-click update from the dashboard.** A pulsing amber button appears top
  right when a new version is published. Clicking it runs the update behind a
  progress overlay; on success the dashboard reloads, on failure the previous
  version is restored automatically. Settings, database and quarantine are
  preserved either way.
- **Automatic rollback in `update.sh`.** It previously backed up user data only
  and, on failure, printed manual restore instructions — a half-applied overlay
  left a mixed-version install with no way back. It now snapshots the current
  code before the overlay begins, arms an ERR trap, and on any failure restores
  code then data (data last, so settings always win) and reports `rolled_back`.
- Progress is published to `/var/lib/sentinel-gate/update-state.json` —
  deliberately outside the install directory, which the updater rsyncs with
  `--delete` mid-run.
- `POST update/run` starts the updater **detached** via `setsid nohup`; a
  synchronous run would be killed partway through, because the update replaces
  the very PHP serving the request. `GET update/progress` reports state, marks a
  run that stops writing for 15 minutes as failed rather than spinning forever,
  and refuses to start a second run over a live one.
- The poller tolerates the API being unavailable for ~80 seconds. Mid-update the
  backend is being overwritten, so failed polls are expected rather than errors.
- The update button honours `prefers-reduced-motion`.

### Fixed
- Asset cache-busting reinstated (`app.css?v=<version>`, stamped by
  `make-release.sh`). It was reverted with the logo work in 3.10.4, and for this
  feature it is not cosmetic: a cached `app.js` has no `startUpdate()`, so the
  update button would silently do nothing after an upgrade.

## [3.10.4] — 2026-08-08

### Reverted
- **All logo work from 3.10.0–3.10.3 is reverted.** `frontend/css/app.css` is
  byte-identical to 3.9.1 and `frontend/index.html` differs only by the version
  string. Restored:
  - The inline SVG shield mark plus HTML wordmark in the topbar
  - The violet palette (#7f5af0 primary, #0d0d10 background)
  Removed: the image-based lockup, the white brand plate, the crop rules,
  `scripts/prep-logo.py`, and the generated logo assets.

### Note
- Asset cache-busting (`app.css?v=<version>`) was introduced during the logo work
  and is reverted with it, so the stylesheet is served from a plain URL again.
  That is an independent fix worth reinstating on its own — without it a browser
  keeps serving a cached stylesheet after an update, which is exactly why this
  revert appeared not to work until the cache was bypassed.

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
