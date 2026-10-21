# Changelog

All notable changes to Sentinel Gate are documented here.

Versioning (X.Y.Z):
  Z (patch) — fixes, UI work on a feature that already shipped, docs, refactors
  Y (minor) — NEW features, or an architectural change
  X (major) — reserved

Bumping Y for a fix inflates the version and hides what actually changed.
`scripts/check-version-bump.sh` enforces this and `publish.sh` will refuse a
release where the bump and the commits disagree.

## [4.12.1] - 2026-10-20

### Fixed

- **Real-Time Monitor never loaded when you opened it.** The page dispatch was
  a sixteen-arm `switch` and `monitor` was simply not one of the arms. Every
  other page had a case; that one did not. So the panel sat on "Loading…" and
  "Checking…" indefinitely and had to be refreshed by hand every single time.

  The Refresh button worked, because it calls the loader directly — which made
  it look like a refresh problem rather than a missing wire.

  It also needed **two** loaders, not one: `loadMonitor()` fetches the daemon's
  status but not the systemd unit, which is why the Service panel stayed on
  "Checking…" even after a manual refresh.

- **Only one page in the product showed that it was loading.** `API.withBusy()`
  existed and was called exactly once, from `loadFirewall()`. Every other page
  loaded in silence, so a slow endpoint was indistinguishable from a broken
  one.

  The dispatch is now a **table**, and every page goes through one call site
  that wraps the load in the busy overlay. A page added tomorrow gets the
  indicator automatically and cannot be missed. Each entry returns its promise,
  so the overlay lifts when the work actually finishes rather than flashing.

- **A failed load left the page claiming to be loading.** `loadMonitor()`
  returned silently when the API call failed, so an error and a page that was
  never wired looked identical — both just sat on the placeholder text the
  markup ships with. That is precisely how the missing dispatch went unnoticed.
  It now shows "Status unknown" and says the monitor API could not be reached.

### Notes

- `tests/test_navigation.php` asserts **every** `data-page` in the sidebar has
  a loader, and every loader corresponds to a real page. A missing arm in a
  long switch is invisible; a missing key in a table now fails the build.

- Six existing tests pinned the exact `case 'x':` text or took a fixed-length
  slice of a function. They failed on a correct refactor, for reasons unrelated
  to what they were checking — the same brittleness that made `test_update_space`
  fail when `cpanel/` was added to the packager. They now assert the property
  rather than the spelling.

## [4.12.0] - 2026-10-20

Both fixes come from a live incident: a mail queue stuck for four days while
the panel reported nothing wrong.

### Added

- **Delivery failures, with the reason the receiving server gave.** The Spam
  Monitor only ever counted what was *sent*. A queue that had not moved in four
  days therefore showed as silence — and the answer was in the log the whole
  time:

  ```
  421-4.7.0 [IP] Gmail has detected an unusual rate of unsolicited mail
  452-4.2.2 The recipient is out of storage space
  routing defer: retry time not reached
  ```

  Three problems that all present as "mail is stuck" and need three completely
  different responses. `==` deferral lines were previously discarded entirely.

  Each is explained rather than just counted:
  - **421 / rate limit** → high. The IP's reputation is damaged. **And the
    advice says not to run `exim -qff`** — against a 421 that sends the
    provider exactly the burst it is objecting to, which is what happened
    during the incident.
  - **452 / full mailbox** → medium, and says plainly that nothing is wrong
    with this server; somebody needs telling their mail is bouncing.
  - **routing defer** → low, a symptom not a cause, pointing at
    `exinext <address>` where the real error lives.

  Reasons are normalised — IPs, message ids, addresses and digits collapsed —
  so a thousand identical refusals aggregate into one row instead of a thousand
  distinct strings. A failure at volume becomes a finding; a handful does not,
  because every server defers some mail.

### Fixed

- **The queue viewer named the wrong customer.** Every
  `bgkgvs@host.lws-s1.com` row was attributed to `lwss1`, because it resolved
  the *domain* — and the server's own hostname belongs to `lwss1`. Technically
  correct ownership, materially useless: seventy messages pointed the operator
  at an account that had nothing to do with them.

  WordPress sends as `<account>@<server hostname>` whenever a site has no From
  address configured, which is most of them. When the domain is the server
  itself, the **local part is the account** — checked against
  `/var/cpanel/users` so a system user or a hostile string can never become an
  "account".

- `mail_delivery` is pruned alongside `mail_activity`; the new table would
  otherwise have grown without bound.

## [4.11.1] - 2026-10-20

### Fixed

- **The Spam Monitor invented its own numbers, and sent an operator hunting a
  backdoor that was never there.**

  `collect()` computed one hour bucket from `time()` and filed **every log line
  it read** into it. A first run starts at offset 0 and reads up to 8 MB of
  **history** — days of mail on a busy server — so all of it was recorded as
  having happened in the last sixty minutes.

  On a live server that produced:

  > **critical** — inditdel sent 5,036 messages to 5,036 recipients in the last
  > hour (threshold 500)
  > **medium** — 19,862 messages passed through the system account "mailnull"

  The real figure was **22 messages across 300,000 log lines** — a normal
  multi-site reseller account doing nothing wrong. The subjects were WordPress
  update notices and password-change confirmations.

  The cost of that false alarm: an evening spent looking for a backdoor, and a
  25-domain reseller account capped to 100 messages an hour, which broke its
  password resets, contact forms and order mail. All of it caused by a number
  this module made up.

  Each line is now dated from **its own timestamp**. An unreadable timestamp
  returns null so the caller decides, instead of the parser quietly guessing
  "now" — which was the whole mistake. Undated lines are counted and logged, so
  a log this module cannot date is reported rather than silently producing soft
  rates.

  A monitor that cannot say *when* something happened cannot say how fast it is
  happening, and a rate is the only thing this module reports.

- **Existing records are discarded on upgrade.** The rows written before this
  fix cannot be corrected — the hour they belonged to was never recorded — so
  they are deleted and the log offset is reset, rebuilding history with correct
  timestamps. Without this, an upgraded server would keep showing the false
  critical until it aged out.

## [4.11.0] - 2026-10-20

### Fixed

- **The Spam Monitor's loudest alarm was a false positive, on a live server.**
  It reported `mailnull` as the top sender at **3,114 messages an hour**,
  marked it **critical**, ranked it above a real customer account, and offered
  a "Cap rate" button beside it.

  `mailnull` is the user **exim itself runs as** on cPanel. That traffic is
  exim processing mail, overwhelmingly bounces — not an account sending spam.
  `magicspam` appeared for the same reason: it is MagicSpam's own system user.
  Capping either would have run `whmapi1 modifyacct` against something that is
  not a cPanel account at all.

  A detector whose loudest alarm is always the same false positive trains the
  operator to ignore it, which costs more than having no detector. Mail-system
  accounts are now excluded from send-burst findings.

  Their volume is **not** discarded: 3,114/hour through exim's own user is
  almost always bounces, and a flood of bounces means spam has already left and
  is being rejected elsewhere. It is reported as `system_mail_volume` at
  medium, with advice that says plainly not to cap it and to look at the
  per-account table for who actually sent it.

### Added

- **The Queue and Frozen cards are clickable** and list the messages behind
  them — age, size, sender, owning cPanel account, recipients and state — with
  a filter by sender or recipient.

- **Per-message deletion.** Select messages, confirm, delete. **There is still
  no "empty the queue" button and there will not be one:** during the incident
  this module was built after, 92,954 of 93,255 queued messages were the relay,
  which still left **301 that a real customer was waiting for**. A flush
  destroys those with no record of what they were.

  Deletion is capped at 500 per call so one click cannot clear a 93,000-message
  queue, every id is validated against exim's id format before it can reach a
  root command, and what is being destroyed is logged **before** it is
  destroyed — afterwards there is nothing left to log.

- **Message header inspection**, including cPanel's `X-Source` headers, which
  name the script that generated the mail. That is the same answer exim's
  `cwd=` gives in the log, from the other side — and on servers whose log does
  not carry `cwd=`, it is the only place the script name exists. **Headers
  only, never the body:** the body is a customer's private mail and nothing
  here needs it to tell a relay from a receipt.

- The list says when it is showing a page of a larger queue. A table showing
  200 of 93,000 with nothing saying so invites a "delete selected" that looks
  complete and is not.

### Notes

- Input validation in `deleteMessages()` now runs **before** the exim binary is
  located. Validation must not depend on a binary being present, or a server
  without exim would answer "exim not found" to a hostile id and never record
  that it was hostile.

## [4.10.1] - 2026-10-20

### Changed

- **Renamed "Outbound Mail" to "Spam Monitor"** in the left navigation, so the
  protection is obvious at a glance. Two words, matching every other entry
  (Bot Shield, CMS Guard, Brute Force). The page subtitle now leads with
  **"Outgoing mail"** and notes that incoming is handled separately — on a
  server also running MagicSpam, an operator must not have to guess which
  direction this one covers.

- **Settings are now editable from the page**: monitor on/off, messages per
  hour per account, queue depth, frozen-message threshold, history retention,
  and the bulk-sender exemption list.

  Values save through `MailGuard`'s own clamps and **the stored value is the
  effective value**. Writing a raw number and letting the getter clamp it on
  read would mean the panel displays a threshold that is not in force — an
  operator who sets 10/hour, sees 10/hour and never gets an alert has been
  misled by their own security tool. Anything adjusted is reported back in
  words and the form is refilled from the server. Each field shows its
  accepted range before a value is rejected, not after.

### Fixed

- **The exemption list could silently exempt an account nobody named.** It
  split on whitespace as well as commas, so `bad name!` became `bad` plus
  `name!` — the second was rejected and the first, which looks like a perfectly
  valid account, was quietly added. An exemption stops all rate reporting for
  that account, so this disabled the alerts the module exists for with nothing
  appearing to go wrong. It now splits on commas and newlines only, and rejects
  an invalid entry whole.

## [4.10.0] - 2026-10-20

Outbound mail monitoring — the gap that had already cost this server its mail
reputation once.

### Added

- **Outbound mail monitoring (`MailGuard.php`), and a page for it.**

  On 2026-10-18 a single Contact Form 7 autoresponder relayed **92,954
  messages** off a live server in about a day, roughly 1,690 an hour. **No file
  was modified**, so the malware scanner had nothing to find, and no tool
  noticed. It was discovered by hand, afterwards, by reading `exim_mainlog`.
  Every signal needed to catch it inside the first hour was already on the
  server the whole time.

  What it watches, all from data already present:
  - **Queue depth** (`exim -bpc`). 93,255 queued is not a busy day.
  - **Send rate** per account per hour, default 500.
  - **The sending script.** exim's `cwd=` on a locally injected message names
    the directory that sent it. This is the signal that turns *"inditdel is
    sending a lot"* into *"this form on this site is the relay"* — the part
    that took hours to establish manually.
  - **Authenticated sends** (`A=dovecot_login:…`), which are a *different*
    incident: a real mailbox password is in use, so credentials leaked rather
    than a script being exploited. Reported separately, with different advice,
    because changing a password fixes one and does nothing for the other.
  - **Failures and frozen messages.** A frozen spike is usually the first
    outside sign of a relay, because the spam is being refused by its targets.

- **`serverscrub`-side throttling** through cPanel's own per-account hourly
  limit — the mechanism cPanel already enforces and reports on, rather than a
  second one exim would not consult.

### Notes

- **Outbound only.** Inbound filtering belongs to whatever handles it on the
  server (MagicSpam here), and two tools fighting over inbound policy is worse
  than one. Nothing in this module reads a message body or makes a spam/ham
  judgement — it counts and attributes.

- **It does not clear the queue and does not suspend accounts.** 92,954 of
  93,255 queued messages were the relay, which still left **301 that a customer
  was waiting for**. Throttling requires an explicit number: there is no
  default, because the right cap for a newsletter is not the right cap for a
  contact form.

- **Nothing was adopted from the projects suggested for this.** `spamscanner`
  is under the **Business Source License**, whose Additional Use Grant forbids
  using it for "a commercial offering that allows third parties… to access the
  functionality" — which is precisely this product. GitHub reports it as
  `NOASSERTION`, so the LICENSE file has to be opened to see that.
  `smtp-monitor` (MIT) watches outbound SMTP *connections*, but on cPanel PHP
  `mail()` hands off to local exim, so it would attribute sends to exim rather
  than to the account. `outgoer` (MIT) is an SMTP *proxy*, unmaintained since
  October 2023, and would sit in the mail path of every account.

- **Cost control.** The log grew by hundreds of megabytes during the incident,
  so reads are incremental with a remembered offset and capped at 8 MB a pass.
  A cap defers work rather than losing it, and rotation is detected by the file
  being smaller than the offset. A monitor that read "everything new" would
  have read all of it at once on a server already in trouble.

- **An unreadable queue reports as "unknown", never as 0.** Those mean opposite
  things, and "0 queued" on a server whose exim cannot be reached is the most
  misleading thing the panel could say.

- 3× the configured threshold is critical, not 4×. The relay ran at 3.4× the
  default and sustained it for a day — at 4× the one incident this was built
  from would have been reported merely as "high".

### Fixed

- **A duplicate top-level JavaScript function would have silently changed every
  number in the product.** A `fmtNum()` helper was written for the new page
  without noticing `app.js` already had one 4,600 lines earlier. JavaScript
  allows this and the later declaration replaces the earlier for every caller
  in the file; the two were not identical. `scripts/check-js-duplicates.py` now
  fails preflight on any top-level `function` or `var fn =` declared twice.

## [4.9.0] - 2026-10-20

Network-layer guards, so the built-in firewall covers what CSF covers rather
than being a fallback for it.

### Added

- **Port-scan detection.** A connection to a port nothing is listening on
  leaves a short-lived SYN_RECV entry and no established socket, so reading
  which ports one address has touched that are *not* in the local listening set
  separates a scan from traffic — a real client connects to the one port it
  wants. Default threshold: 10 distinct closed ports.

- **Connection flood limits.** Concurrent connections per source address, over
  a configurable ceiling (default 150). **Ports 80 and 443 are exempt by
  default and that is load-bearing:** a browser opens six connections per page,
  a corporate NAT or CDN presents hundreds of real users as one address, and
  this product's own dashboard is served over 443 — a flood limit there locks
  the operator out of the page they would need to turn it off.

- **Egress filtering**, off by default, with no automatic enable anywhere. A
  wrong *inbound* rule blocks visitors and you hear about it. A wrong
  *outbound* rule breaks the server's own updates, DNS, NTP, mail, licence
  checks and backups — quietly, usually at the next cron run. So it previews by
  default, refuses an empty allow-list, and **refuses any policy that does not
  allow port 53**, because without resolution nothing works and every
  downstream failure looks like something else.

### Notes

- **No new blocking path.** The detectors record into the brute-force table
  under their own service names, and `BruteForce::evaluate()` escalates them
  through the ladder that already exists (3h → 6h → 24h → permanent), honours
  the same whitelist, and `releaseExpired()` lets them go again. A second
  blocking path would mean a second set of rules about who must never be
  blocked — and that list includes the operator's own address and two
  JetBackup servers. A backup server opening dozens of parallel connections
  looks exactly like a flood, and losing backups to a false positive is worse
  than the attack being guarded against.

- **Clean-room, and the provenance is recorded in the source.** These
  capabilities exist in CSF (`PS_INTERVAL`, `CT_LIMIT`, `TCP_OUT`) and
  capabilities are not copyrightable; code is. CSF and both surviving forks are
  GPLv3, so deriving from them would make this product a derivative work and
  oblige it to ship under GPLv3 — incompatible with licensing it commercially.
  Everything here is written against the kernel's own interfaces: `/proc/net`,
  nftables and iptables. No CSF or CPGuard source was consulted.

- **It samples rather than watches**, on the scheduler's 15-minute tick. A
  continuous watcher means a daemon reading kernel connection state in a loop
  on a shared host, and an unbounded read of that is itself a performance
  incident — this server had one in October. A sample is sufficient: a scanner
  touching enough closed ports to matter is still mid-scan or in TIME_WAIT when
  the sample lands, and a flood persists by definition.

- **Refusing to guess.** If the local listening set cannot be read, every port
  looks closed and every ordinary visitor looks like a scanner. Rather than
  reporting that, the detector stops and says it declined to guess — reporting
  the whole internet as scanning and escalating it through the ladder would
  take the server off the air.

- `tests/test_networkguard.php` (66 assertions) covers the `/proc/net` byte
  order against three IPv4 addresses and IPv6 — decoding that wrong does not
  fail loudly, it blocks the wrong address — plus every refusal, the clamps,
  and CIDR whitelisting of the five addresses the October handoff says must
  never be blocked.

### Not built, deliberately

- **Country blocking** needs a GeoIP feed. MaxMind now requires an account and
  licence key; the free CIDR-per-country sources vary in accuracy and update
  cadence. That is a data-sourcing decision, not a coding one, and it should be
  made explicitly rather than by whichever feed was easiest to wire in.
- **Cluster mode** (sharing blocks between servers) is a protocol and trust
  design, not a feature — it needs authentication between nodes before any of
  it is safe.

## [4.8.0] - 2026-10-20

ServerScrub now installs the third-party tools it integrates with, so a fresh
install is a complete security stack rather than a list of prerequisites.

### Added

- **ModSecurity is installed during setup**, from the package manager, and left
  in **detection-only**. Installing the engine is what makes this a complete
  package; deciding what to block is not an installer's call — a rule that
  matches ordinary traffic blocks paying customers. `--no-waf-pkg` declines.

- **CSF is installed on cPanel servers** from `cpanel-csf`, cPanel's maintained
  fork (source: github.com/cpanel/cpanel-csf). It is left in CSF's own
  **TESTING mode** — rules not enforced, lfd down — because turning a brand-new
  firewall live on a production server unattended is not a decision an
  installer should make. The SSH port is read from `sshd_config` (not assumed
  to be 22) and added to `TCP_IN` first, since losing SSH is the one failure
  here that cannot be undone remotely. `--no-csf` declines.

- **A CSF upstream check.** Way to the Web Ltd closed on **2025-08-31** and
  `download.configserver.com` no longer resolves. CSF's updater **runs as
  root**, so a server still running the retired vendor's build with
  `AUTO_UPDATES` on would fetch and execute code from an unregistered domain
  the day somebody buys it. ServerScrub now reports this, entirely locally —
  it never contacts those hosts. A build newer than 15.00, the vendor's final
  release, is recognised as a maintained community fork and not flagged.

- **`serverscrub deps`** — what is installed, where it came from, and what is
  degraded without each one, so the "complete package" claim is auditable on a
  real server rather than taken on trust.

### Notes

- **Everything comes from the OS package manager. Nothing is downloaded.** This
  is a security decision, not a convenience one:
  - A tarball fetched at install time is **pinned forever** — the server's own
    `dnf update` does not know it exists. The package manager *is* the patch
    channel, so downloading to "always have the latest" achieves the opposite.
  - ModSecurity must match Apache's ABI. On EasyApache 4 it has to be
    `ea-apache24-mod_security2`; a generic binary or a wrong-headers build means
    httpd will not start, which on a shared host is every site down at once.
  - CSF and ClamAV are GPL. Installing them as separate OS packages is
    aggregation and carries no obligation onto this product. Vendoring either
    would. `FirewallEngine.php` is a clean-room implementation for the same
    reason.

- **CSF is an integration, not a prerequisite.** ServerScrub manages
  nftables/iptables through its own engine and `FirewallEngine::detect()` simply
  prefers CSF where it already exists. Off cPanel, `cpanel-csf` refuses to
  install by design, so ServerScrub uses its own engine — a supported
  configuration, not a degraded one.

- **The community fork is documented, not installed.** Black-HOST's fork
  (github.com/Black-HOST/csf) is actively maintained and has no cPanel
  dependency, which makes it the only maintained CSF for a non-cPanel server.
  ServerScrub detects it and uses it as the firewall backend, but will not
  install it: its installer is `bash <(curl -sL …)` from a third-party domain,
  and CSF runs as root. That is the same shape as the configserver.com problem,
  untriggered. Handing root to a third party is a decision to leave with the
  operator rather than make silently on every server this product touches. The
  guidance points at a pinned release rather than the one-liner.

### Fixed

- **`t_code()` was a PHP tokeniser being applied to shell scripts.** Four tests
  asserted on `install.sh`, `update.sh`, `make-release.sh` and `build.py`
  through it. `install.sh` writes PHP heredocs, so `token_get_all()` entered PHP
  mode at the first `<?php` and stripped `#` comments and syntax from there on
  — the assertions were being evaluated against mangled text. `t_code()` now
  refuses a non-PHP file, and `t_shell()` handles `#`-comment languages,
  leaving `#` inside quoted strings alone.

## [4.7.2] - 2026-10-20

Three bugs found by one real upgrade on a production server. The rollback did
its job — the server came back on 4.4.2 with nothing lost — but it should never
have been triggered.

### Fixed

- **A completed update was rolled back by a `chmod` on an optional directory.**
  v4.7.1 applied in full on a live server: files copied, user data restored,
  migrations run, plugin re-registered. Then:

      chmod: cannot access '/usr/local/serverscrub/quarantine': No such file or directory
      Update failed — rolling back to v4.4.2…

  Quarantine is **configurable** and routinely sits outside the install
  directory — that server had it at `/home/.serverscrub/quarantine`, because
  `/home` is the big volume. So the assumed path did not exist, `chmod` exited
  non-zero, `set -e` called that a failed update, and a successful upgrade was
  undone by a permissions tweak on a directory that was never there.

  `database`, `quarantine` and `logs` are now tightened only when present, and
  the real quarantine path is read from settings instead of assumed.

- **Updates never delivered `cpanel/`, `test.sh` or `upgrade.sh`.** `update.sh`
  carried its own list — `UPDATE_DIRS=( backend frontend whm )` — which was a
  **third** description of what this product consists of, alongside
  `build.py`'s `ITEMS` and `make-release.sh`'s allowlist. All three disagreed.

  The release zip was correct the whole time, which makes this the hardest
  version of the bug to see: nothing is missing from the package and a fresh
  install is perfect. Only servers that *updated* were affected, and the
  consequences were:

  - `cpanel/` holds the page every **customer** opens from their own cPanel.
    Any server updated after that directory was introduced showed an **empty
    menu entry to every user on it**. The only symptom was two lines in an
    installer log: `cPanel user page missing from the package`.
  - `test.sh` missing meant every update ended `test.sh not found — skipping
    verification`. Post-install verification had silently not run in months.
  - `upgrade.sh` missing meant the one script whose purpose is to fetch a newer
    updater could never arrive by update.

  `tests/test_packaging.php` now asserts all three lists are identical, and
  names these three individually.

### Notes

- After updating to 4.7.2, cPanel users get their menu entry back. It arrives
  with the first update that carries the corrected copy list.

## [4.7.1] - 2026-10-20

### Fixed

- **The updater could abort in total silence, and did, on a production server.**
  A v4.4.2 install ran `update.sh` twice; both times it printed
  `Checking releases channel for latest version…` and returned to the prompt,
  having changed nothing and reported nothing.

  The cause was one informational line cross-checking
  `<channel>/latest/VERSION` to print a nicer message. Under `set -e` a plain
  assignment takes the exit status of its command substitution, and under
  `pipefail` a pipeline fails if any stage fails — so

      LIVE_VER="$(curl -fsSL "$URL" 2>/dev/null | tr -d '[:space:]')"

  does not leave `LIVE_VER` empty on a 404. It terminates the script, and
  because stderr went to `/dev/null`, without a word. It failed on the *first*
  channel, so the GitHub mirror that was working perfectly was never tried.

  **Eleven assignments in `update.sh` had this shape**, and every one of them
  was already followed by an `[[ -z … ]]` check or a fallback: the code was
  written expecting an empty value and the shell options silently defeated it.
  Two others were live landmines of their own — a `df` that cannot stat the
  install directory killed the updater one step before it started, and
  `ls -1dt "$BACKUP_ROOT"/*/` killed it mid-prune on any server whose backup
  directory exists but holds nothing, which is the second update a server ever
  runs.

- `scripts/check-shell-pipefail.py`, wired into preflight, fails the build on
  any new pipeline assignment in a shipped script that is not guarded.
  Dev-only scripts are reported as advisory: the same bug there fails on a
  maintainer's laptop with someone watching, not at 04:30 on a customer's
  server.

## [4.7.0] - 2026-10-20

Unattended updating. ServerScrub already checked for new versions daily and
cached the result; nothing installed anything. A security product that is
itself months out of date behind an "update available" badge nobody reads is
the wrong default, so updates now install themselves.

### Added

- **Automatic updates, on by default** (`Updater.php`). `update.sh` already
  knew how to apply a release safely — verify the SHA-256, back up, rsync,
  restart, roll back if the new version does not answer. What was missing was
  the decision to run it. That decision is the whole of the risk here, because
  it replaces the security software on a production server with nobody
  watching, so it refuses in five cases and **states the reason in words**:
  - a **major** version (X is reserved for a breaking change — opt in with
    "Include major versions" if you want them)
  - a **scan** is running (`update.sh` rsyncs over the install directory with
    `--delete`, which would pull the scanner's code out from under a worker)
  - a **backup** is running
  - an update is **already running** — and a state file claiming to run but
    untouched for 15 minutes is treated as a crash, not as slow, so one failed
    attempt cannot block that server for ever
  - after a failure it **backs off** 1h → 2h → 4h, and after three it stops and
    names the log to read. Each attempt rsyncs over a live install directory; a
    daily retry of an update that cannot work is not harmless.

- **A `wpdbscan`-style `autoupdate` scheduler task**, daily at 04:30 — after
  the 03:30 database sweep and 04:00 CMS discovery, so a service restart does
  not land on top of either. It reconciles the *previous* run first, because
  the updater rsyncs over its own code and cannot be relied on to record its
  own outcome.

- **An Updates panel** in Settings: installed vs available, when it last
  checked, when it last succeeded, the toggles, and — the important line — what
  it will do next, verbatim from the server. "Automatic updates: on" must never
  quietly mean "blocked by something".

- **`upgrade.sh`**, for upgrading a server by hand. It fetches the *current*
  `update.sh` from the release channel before handing over, because the copy on
  a server is always the one that shipped with the version already installed —
  so a fix to the updater can never reach the servers that need it. It
  downloads nothing else and replaces nothing itself; `update.sh` keeps that
  job and its rollback. Refuses to downgrade, warns on a major version, and
  rejects a downloaded updater that is not valid shell.

### Fixed

- **The update checker and the updater read different sources, and disagreed.**
  `UpdateChecker` asked the GitHub Releases API; `update.sh` downloads
  `latest.json` from the release channel. `publish.sh` skips creating the
  GitHub Release when the machine doing the release has no `gh` and no
  `GH_TOKEN` — **which is exactly how 4.6.0 shipped** — so the API still
  described 4.5.1 while the manifest, the CDN and the committed zip all
  described 4.6.0.

  The panel would have reported "up to date" on a server a version behind, and
  automatic updating, which asks this class whether to run, **would never have
  fired at all**. Both now read `latest.json`, CDN first and GitHub raw second,
  in the same order. The Releases API is not consulted even as a fallback: a
  fallback to a source that can lag would reintroduce the same disagreement
  under a rarer condition, which is worse than not having one.

- **An unreachable release channel no longer reads as "up to date."** A failed
  check kept the previous `checked_at`, so the dashboard showed a recent
  successful check on a server that had not reached the channel in weeks —
  which is the state an unpatched install sits in, looking healthy throughout.
  The error is now stored and shown.

- **`POST update/run` existed in the API and was called by nothing.** The
  "update" button showed a toast telling the operator to SSH in and run
  `update.sh` — the exact script that route starts, detached, with locking. The
  button now works, with progress and an honest outcome: the API goes away
  mid-update, so a failed poll is expected and only the state file decides
  whether it worked.

- **Two owners for update checking.** `install.sh` wrote a second cron entry at
  08:00 that only cached a notice, while the scheduler's task checks and
  installs. New installs get one entry; `update.sh` removes the duplicate from
  existing ones, after copying the cron file aside, matching only the line this
  project wrote.

### Changed

- `publish.sh` now commits the source the release zip was built from.
  `STAGE_LIST` is release metadata and has never covered `backend/lib`,
  `backend/daemon`, `frontend/js` or `tests`, while `make-release.sh` packages
  from the working tree — so 4.6.0 shipped a zip containing two new library
  modules and committed a repository without them. The tag described something
  other than what customers received, and nothing reported the difference.

### Notes

- `tests/test_autoupdate.php` is almost entirely refusals: the one "yes" is a
  line, and the rest is the conditions under which this must not touch a live
  server. It also asserts that `UpdateChecker` and `update.sh` read the same
  manifest and know the same two channels, which is the defect above expressed
  as a test.
- Automatic updates can be switched off in Settings → Updates. Turning them off
  does not disable the daily check, so the panel still tells you what is
  available.

## [4.6.0] - 2026-10-20

Everything in this release comes out of two days of incident response on a live
118-account cPanel server with 503 WordPress installs, compromised since at
least June 2025. 187 malicious files were removed and 235 quarantined, and 150
fake administrator accounts deleted. **Not one of the files that mattered would
have been found by the scanner as it shipped in 4.5.1**, and most of what
mattered was not a file at all.

### Added

- **A heuristic rule engine (`Heuristics.php`).** The existing signatures ask
  one question per rule: "does this regex appear?" Every genuinely dangerous
  file found during the incident answered no to all of them. A rule here is a
  conjunction of conditions, optionally scoped to a path, and it can match
  files that are not PHP at all. Three cases drove it:

  - An arbitrary-file-upload backdoor whose only tell was
    `hash_equals('<32 hex>', $_POST['api_key'])` sitting next to
    `move_uploaded_file()`. Each of those three things is ordinary; together
    they are a shell. Eight live copies, two on accounts a previous sweep had
    declared clean. One of them was `wp-content/advanced-cache.php`.
  - `health-monitor.php`, 456 bytes of entirely documented WordPress calls:
    read `?_wplogin=`, match a token in usermeta, call `wp_set_auth_cookie()`.
    No obfuscation, no eval, no base64 — **no signature will ever match it**.
    What condemns it is that it sits in `mu-plugins`, where nothing has any
    business logging a user in from a query string.
  - A self-healing framework spread across 22 files, including
    `wp-content/db.php` and `object-cache.php` — WordPress drop-ins, which load
    before every plugin on every request. Deleting the mu-plugin and declaring
    it stopped was wrong twice: each of those files could rebuild the other 21.

- **A WordPress database scanner (`WPDatabaseScanner.php`), and a page for it.**
  Until now every module in this product looked at files. Most of what mattered
  was a database row:
  - 148 administrator accounts on one site, inserted straight into `wp_users`.
  - A payload mirrored across `wp_options`, `wp_postmeta` and a draft post
    titled "Cache compatibility notes". Removing every malicious file on that
    site changed nothing; it rebuilt itself on the next request.
  - A login backdoor keyed on one usermeta row, whose loader was the
    456-byte file above and whose dropper had already deleted itself.
  - **92,954 spam messages** relayed in a day through one Contact Form 7 form's
    autoresponder, with nothing on disk modified.

  It reports: rogue administrators, fabricated roles, login tokens, payload
  options, draft-post stashes, mail relays and injected `wp-config.php`. It is
  read-only and has no delete button — see "Notes" below.

- **Sentinel paths in the real-time monitor.** A daemon can report something no
  scanner ever can: that a file has *appeared* somewhere it should not change.
  `wp-content/{db,object-cache,advanced-cache}.php`, anything in `mu-plugins`,
  `wp-config.php` and theme `functions.php` are now reported on sight,
  regardless of content — because the worst backdoor on that server was clean
  by every test available.

- **Recurrence detection.** If a file the monitor has already dealt with comes
  back, that is escalated to critical and labelled as a recurrence, with advice
  to look for the executor rather than delete it again. A mu-plugin was deleted
  and returned twice during the incident, and each round was reported a success.

- **Nightly `wpdbscan` task**, weekly at 03:30, with a wall-clock budget that
  resumes where it stopped rather than scanning the first 200 installs every
  week and the rest never.

### Changed

- **The scanner reads files it never used to.** The hardcoded `*.php` filter is
  gone. The framework stashed an encrypted copy of itself at
  `wp-content/uploads/.<64 hex>.cache` — no PHP extension, so invisible to
  every scan this product had ever run. Selection is now
  `Heuristics::shouldInspect()`, which still takes PHP by extension and adds
  the three drop-in names plus hidden hex-named blobs under `wp-content`. It
  stays bounded; it does not become "read every file on the server".
- **`getPhpFiles()` is a generator and prunes `/home/virtfs`.** It used to
  collect every path before examining any of them. cPanel bind-mounts a copy of
  the filesystem there for *every* account, so walking it makes the cost
  multiplicative — 118 times over on that server. An unbounded walk of `/home`
  pushed load past 35 during the incident. Snapshot and CageFS trees are pruned
  too, and symlinks are no longer followed.
- Threat records carry a `detail` column: why a rule fired, in a sentence. A
  conjunction rule cannot be read off its name, and an operator deciding
  whether to delete a customer's file needs to be told what the file does.
- The real-time daemon evaluates the same conjunction rules as the scanner, so
  an alert and a follow-up scan agree. They must: an operator who sees an alert
  and then runs a scan that finds nothing stops trusting both.

### Notes

- **Nothing in the database scanner is auto-remediated, and that is deliberate.**
  These are judgements about a customer's users and content, and they are wrong
  often enough to matter. On that server an account matching three rogue-admin
  signals was the client's real administrator on a VPN; a site flagged on ten
  `302` responses turned out to be WP Toolkit redirecting bots.
- **`wp-config.php` is parsed as text, never executed.** Running `wp-cli`
  against one compromised site during the incident executed its injected
  `wp-config.php` as root and re-created, as root, the malware that had just
  been deleted.
- **The hash-format test for fake admins is no longer sufficient.** "A raw
  32-char MD5 means SQL insertion" is still true and still found 148 accounts —
  but one tool on that server created administrators with proper bcrypt hashes
  and `user_registered` backdated to 2020–2024. A fabricated *role* turned out
  to be the better detector, and that is now checked in both modules.
- Failed queries are reported as failures, never folded into a finding count. A
  query that errors and a clean site produce the same empty result set, and
  reading one as the other is the easiest way there is to call a compromised
  server healthy.
- `tests/test_heuristics.php` (171 assertions) and `tests/test_wpdb_scanner.php`
  (48) carry real samples from the incident alongside the legitimate code that
  sits next to them — WordPress's own nonce checking, a Redis object cache,
  W3 Total Cache writing generated PHP, a nonce-checked SSO plugin, and
  WooCommerce's `shop_manager` role. The clean samples are the point: a high or
  critical finding deletes without a copy by default. Two real false positives
  were caught by these tests during development and fixed in the rules.

## [4.5.1] - 2026-10-16

### Changed
- The running-scan label shows **paths** rather than account names:
  `/home/alice/public_html` instead of `alice`. The path says which account
  and which part of it is being walked, and since quick and full scans cover
  different trees that second half is the half worth knowing. Many web roots
  are listed as paths too, abbreviated past three rather than collapsed into a
  bare count, with the full list still on hover.
- The label shown the instant a scan starts now uses the same paths the server
  reports on the first poll, so it no longer changes from `alice` to
  `/home/alice` two seconds later.

## [4.5.0] - 2026-10-16

### Added
- **A running scan now says what it is covering.** The job row has always
  carried the scan path and the progress card always ignored it, so a custom
  scan of three accounts looked identical to a full scan of the whole server.
  Paths map back to account names -- "alice", not `/home/alice/public_html` --
  with many web roots counted rather than listed, and a long selection
  abbreviated with the full list kept on hover. It appears the moment the scan
  starts rather than at the first poll two seconds later.

### Fixed
- **The stall warning never cleared.** It was set once and left, so a scan that
  paused briefly -- loading the ClamAV signature database, or working through
  one large file -- displayed "the scan process may not be running" for the
  rest of its life while the counter beside it climbed past 5,600 files. A
  warning that contradicts the number next to it teaches an operator to ignore
  both.
- That warning told operators to check `logs/scanner.log`, which has never
  existed anywhere in the product. Each worker writes to
  `logs/scan_<job>.log`, and the scan status payload now carries the real name.

## [4.4.3] - 2026-10-16

### Fixed
- **Stopping a running scan is now obvious.** The control existed, but it was a
  ghost extra-small button at the far right of the progress row -- the least
  visible element on the page, for the one action an operator urgently wants
  while a scan is loading the server. The toolbar button, which is where they
  are actually looking, read "Scanning..." and was disabled. That button is now
  the stop control while a scan runs: red, enabled, and labelled **Stop Scan**.
  The control beside the progress bar is a full-size danger button.
- Five separate places set that button's label and disabled state by hand,
  which is how it came to disagree with itself. One function owns it now, and
  stopping or finishing a scan clears the followed job so the button reliably
  returns to starting one.

## [4.4.2] - 2026-10-15

### Fixed
- **The custom-scan account picker never appeared, and two other features were
  dead on arrival.** `g()` -- the element lookup nearly every handler uses --
  was declared as a `const g` *inside* two functions and nowhere else, so every
  module-scope caller threw `ReferenceError` the instant it ran: silently,
  inside an event handler, with nothing logged. Three shipped features did
  nothing at all as a result -- the account picker and the adoption of an
  already-running scan (both 4.3.0), and the brute-force ladder preview
  (4.2.0). `g()` is now defined once at module scope.
- The picker is a dialog rather than an inline panel: checkboxes, a filter that
  preserves what is already ticked, select all and clear, and a button that
  stays disabled until at least one account is chosen. Pressing Start Scan with
  Custom selected and nothing ticked reopens it rather than failing.

### Added
- `scripts/check-js-scope.py`, wired into preflight: it fails the build when a
  helper is called from module scope but only declared inside some other
  function. Bracket balance and handler resolution both passed while these
  three features were broken, so neither gate could have caught it.

## [4.4.1] - 2026-10-15

### Fixed
- **Daily and weekly tasks now run at the time they are configured for.**
  `isDue()` required 23h55m to have elapsed since the *last run* before it
  would look at the clock at all, so a single late run pinned a task to that
  later time permanently: every run could drift later and none could drift
  back. On the server that reported this, a malware scan configured for 09:00
  was running at 20:30, `iprep` set for 03:00 ran at 04:18, and `rootkit` set
  for 00:00 ran at 04:19 -- with cron firing correctly the entire time. The
  time-of-day check alone already prevents a double-fire and lets a drifted
  task recover its proper hour.
- An unrecognised `*_schedule` value ran its task exactly once and then never
  again: the never-run shortcut came before the schedule was validated. A
  misconfigured schedule now simply does not fire.

### Changed
- The scheduling decision moved to `backend/lib/Schedule.php` so it can be
  tested. It never had been -- it lived inside a script that runs its tasks on
  include, so the only way to exercise it was to let it fire real scans.

## [4.4.0] - 2026-10-15

### Added
- **`serverscrub schedule`** lists every scheduled task with its schedule, when
  it last ran, and whether it is overdue. There was previously no way to answer
  "is my nightly scan actually running?": the scheduler writes to stdout and
  cron redirects that into `logs/cron.log`, one file holding every task's
  output interleaved. The report is built from the scheduler's own task table,
  so it cannot drift from what is really scheduled.

### Fixed
- **The installer could install a version older than the one just published.**
  `get.sh` reads `latest.json` through raw.githubusercontent.com, which serves
  via a CDN with a short TTL, so for a few minutes after a release it kept
  returning the previous manifest and the installer believed it. Reported
  directly: 4.3.0 was published and the server ended up on 4.2.0. Manifest
  reads are now cache-busted. The archive deliberately is not -- its sha256 in
  the manifest is what guards it, and busting that would defeat mirroring.
- `dist/latest.json` is tracked but was never staged by `publish.sh`, so it sat
  at 4.1.5 while three releases shipped. A tracked manifest that lies is a trap
  for anyone pointing a mirror at `dist/`.

## [4.3.0] - 2026-10-15

### Added
- **Custom scan now picks accounts, with checkboxes.** It previously offered a
  free-text directory box; on a shared server an operator thinks in accounts,
  not paths. The list comes from `/var/cpanel/users` where cPanel is present
  and from the configured scan roots otherwise, and each entry says whether it
  has a `public_html`. Select all and Clear are there for the common cases. The
  request names accounts and the server resolves them against the real account
  list, so a path in the request body cannot send the scanner elsewhere.

### Fixed
- **The nightly scan never ran.** The scheduler marks a task as having run
  whenever its closure returns normally, and the scan task returns normally
  when it defers for a backup. On a server whose JetBackup window covers the
  02:00 scan time, every nightly scan was deferred *and* recorded as run, and a
  `daily` task is not due again for 24 hours -- so it was skipped every night,
  indefinitely. The deferral was right; counting it as a run was not. A task
  that returns `false` now stays due and is retried on the next tick. The same
  applies when a scan is already running at the scheduled time.
- **Quick, Full and Custom scanned exactly the same thing.** `scan_type` was
  written to the database and never read again, so all three walked the same
  tree and took the same time. Quick now scans every account's web root, where
  public code runs and where almost everything gets in; Full scans the
  configured roots entire; Custom scans the chosen accounts. Quick falls back
  to a full scan where no web root exists and says so, rather than silently
  scanning everything under the word "quick".
- **A running scan can now be stopped from any page load.** The Stop button
  lived inside a progress card that appeared only for a scan the current
  browser tab had started, so a scan launched by cron, by another admin, or
  before a page reload could not be stopped from the interface at all. The
  Scanner page now adopts whatever scan is in progress and follows it.
- A custom scan with nothing selected is refused, in the interface and in the
  API, instead of falling back to scanning the whole server.

## [4.2.0] - 2026-10-15

### Added
- **Escalating blocks for repeat offenders.** More than four failed logins from
  one address inside the window now earns a three-hour block; coming back after
  serving it earns six hours, then twenty-four, then a permanent block. The
  strike count — not the attempt count — drives the ladder, so an address that
  returns patiently still climbs it. The ladder is editable per-server
  (`bf_ladder`, in the Brute Force settings panel); leaving off the final `0`
  means the last term repeats and nothing is ever blocked permanently, which is
  a deliberate choice an operator is allowed to make.
- The offenders table now says which term is being served and how long is left,
  and for an address merely being watched, what its next offence will cost.

### Fixed
- **Expired firewall blocks are now actually lifted.** `blockIP()` has written
  `expires_at` since the firewall module shipped, and nothing anywhere ever read
  it: every "temporary" block was permanent at the firewall while the database
  reported a deadline. An operator who believes a block is temporary does not go
  looking for the customer it is silently holding out. `Firewall::expireBlocks()`
  now sweeps them on the schedule. Permanent blocks are never touched.
- **Brute force now blocks at all.** The block path required the address to have
  never been blocked before, and since nothing ever cleared that flag, an address
  was blocked at most once ever — in practice, with nothing expiring anything,
  addresses accumulated hundreds of failures while the page showed "Watching"
  and did nothing. Reported from a live server with 234 and 266 failures listed
  as watched.
- The strike count is no longer pruned on the attempts clock. Attempts are
  evidence and expire in a week; strikes are history and are kept for 30 days
  (`bf_offence_memory_days`), or an attacker returning every eighth day would
  have been blocked for three hours for ever.
- Attempts recorded before a block are discarded when its term ends, so a
  released address is not instantly re-blocked on evidence it has already been
  punished for — which would have collapsed the whole ladder to "permanent"
  within minutes.

### Changed
- The failure threshold default drops from 10 to 5. Existing installs are
  migrated once; a threshold an operator sets afterwards is left alone.
- `bf_block_duration` is removed. It no longer drove anything once the ladder
  landed, and the settings panel offering it was a control that did nothing.

## [4.1.7] - 2026-10-14

### Fixed
- **Quarantine directories the product used to use are now swept.** The
  default quarantine path is derived from the product name, so the rename to
  ServerScrub changed where the product *looks* without moving a single file.
  A server holding two hundred quarantined files in
  `/home/.sentinel-gate/quarantine` had `quarantine status` report `files: 0`
  against the new, empty `/home/.serverscrub/quarantine`. The sweep follows
  each threat row's recorded path and so still expires those files, but
  anything whose record had been retired had nothing left to find it, and
  `pruneQuarantine()` walked only the configured directory — so the old
  location leaked for ever. It is now swept too, and the same applies whenever
  an operator relocates quarantine.
- In a directory that is merely inferred, only files we can name as ours
  (`*.quarantine`) are removed. An operator's own file sitting there is left
  alone however old it is.
- `quarantine status` now lists previous locations and what they hold, so
  `files: 0` can no longer describe the wrong directory without saying so.
- `serverscrub quarantine` usage now lists `sweep`, which it had omitted since
  the subcommand was added in 4.1.6 — running it on an older build printed the
  usage line instead, which read as though the command did not exist.

## [4.1.6] - 2026-10-14

### Fixed
- **Our own working directories are now skipped by name**, not only by
  resolved path. The path check added in 4.1.5 is the precise one, but it
  trusts `quarantine_dir` to still point where the files actually are — and on
  a server renamed from the old product, with quarantine left at
  `/home/.sentinel-gate/quarantine`, a stale setting is exactly when that check
  stops protecting anything. `.serverscrub` and `.sentinel-gate` are skipped
  wherever they appear. A customer's own dot-directory is still scanned; this
  is not a blanket rule.

- **The quarantine sweep can be run on demand.** It only ever ran from the
  nightly scheduler, so a backlog could not be cleared without waiting until
  04:30. `serverscrub quarantine sweep` now applies the retention immediately:
  expiries, reconciliation of records whose file has gone, and retirement of
  resolved records.

  `quarantine prune` deletes files by age and does not touch the log, which is
  why running it left the entries in place.

## [4.1.5] - 2026-10-14

### Fixed
- **The scanner was re-scanning its own quarantine.** Quarantined files *are*
  malware, and nothing stopped the walk entering the quarantine directory. With
  quarantine moved to `/home/.serverscrub/quarantine` — sensible, since that is
  where the disk space is — it sat directly inside the default scan path. Every
  scan then re-detected every file it had already caught, wrote a fresh threat
  record for each, and quarantined the quarantined file.

  That is where a log full of 200 identical entries came from, all pointing at
  quarantine paths, with the account column showing the install directory
  rather than a customer. The quarantine directory is now excluded by resolved
  path (it is configurable, so matching on its name would not do), and any
  stray `.quarantine` file is skipped wherever it sits.

- **The log kept saying "Quarantined" for files that had been deleted.**
  `pruneQuarantine()` removed files by age and never touched the database, so a
  status outlived the thing it described by days. Rows whose quarantined file
  has gone are now reconciled to `deleted`.

- **Records written before per-threat deadlines existed were never swept.**
  Nothing before 3.37.0 has a `quarantine_expires_at`, and the policy pass only
  looks at rows that have one — so they sat at "Quarantined" indefinitely while
  their files were quietly removed underneath. They are now given a deadline
  derived from when they were detected, and the normal rules apply.

- **Threat records were never pruned at all.** Resolved records are now retired
  after `threat_retention_days` (7). Anything still **active** is kept
  regardless of age — an unresolved threat is exactly what the log is for.

### Notes
- The threat list is ordered `detected_at DESC` — newest first. That is now
  pinned by a test, since a log that silently reversed would be read upside
  down without anyone noticing.

## [4.1.4] - 2026-10-06

### Fixed
- **The sidebar still showed the old logo on an updated server.** The markup
  and the file were both correct — the browser was serving a cached
  `icon-64.png`. That filename held the old cropped shield in 4.0.0 and the new
  mark in 4.1.0: same name, different picture. A file whose *contents* change
  between releases is cached exactly as hard as one whose name never changes,
  and images were not being cache-busted at all.

  This is the second half of the same lesson as `charts.js` in 4.1.3. Images
  are now stamped alongside css and js.

- **Images built in JavaScript are stamped too.** Stamping the markup alone
  missed them: the loading mark and the dashboard cards each build their own
  `<img>`. `window.SG_ASSET_V` carries the release version and `assetUrl()`
  applies it, with a test that fails if any image is built without it.

  The product name stays to the right of the mark, unchanged.

## [4.1.3] - 2026-10-06

### Fixed
- **The new dashboard's donut and both bar charts were blank.** The
  cache-busting step stamped a hand-kept list of three files — `app.css`,
  `api.js`, `app.js` — and **`charts.js` was not on it**. So after updating, a
  browser kept the pre-4.1.0 `charts.js`: `Charts` was defined and the older
  charts still drew, but `donut()` and `bars()` did not exist. The dashboard's
  guards correctly skipped those panels rather than throwing, so three sections
  were simply empty with nothing in the console to explain it.

  Everything else on the page — the headline cards, the comparison bars, the
  legend, the alerts — rendered from data, which is why the page looked half
  alive.

- **The release script now stamps every local `css/` and `js/` reference by
  pattern**, not by name. A guard that is a list of filenames is out of date
  the first time someone adds a file, which is exactly what happened here.

- `tests/test_asset_cache.php` fails if any local asset is unstamped or carries
  a stale version, and pins the chart methods the dashboard depends on.
  Verified against the shipped state: an unstamped `charts.js` fails two
  assertions, a stale stamp fails a third.

## [4.1.2] - 2026-10-06

### Fixed
- **The app would not load: the splash covered it permanently.** The call that
  removes the first-load splash was inserted into the wrong function in 4.1.0.
  It landed *after a `return`* in `reltime()`, where it could never run, so
  `openPage()` never dismissed anything. On any server with a session — which
  is every cPanel install — the first and only thing shown was the logo.

  Nothing errored. The app was running perfectly behind a cover that never
  lifted, which is why there was no clue on screen.

  The browser check at the time only exercised the *unauthenticated* path,
  where a separate timer happened to clear it. The broken path was the one
  nobody looked at.

- **The splash can no longer strand anyone.** It is now also removed when the
  window finishes loading, and on a timer, whether or not the render path
  remembered to. Verified by deleting the render-path call entirely: the app
  still becomes usable. A cover that can stick is worse than no cover.

- `tests/test_splash.php` reproduces the exact accident — a `dismissSplash()`
  placed after a `return` — and fails on it, as well as on the failsafes being
  removed or nested where they would never arm.

## [4.1.1] - 2026-10-06

### Added
- **The navigation is pinned by a test.** The dashboard rebuild in 4.1.0 worked
  by inserting markup into the dashboard page, and a mis-placed insertion point
  is one of the easiest ways to damage a single-file UI: land inside the sidebar
  and nav entries vanish; land past the wrong closing tag and a whole page ends
  up nested in another. Neither fails a syntax check, and the only symptom is a
  menu entry that is quietly gone.

  `tests/test_navigation.php` now names all fifteen sidebar entries explicitly
  (a count still passes when one item is swapped for another), checks each has
  a page container and each page is reachable, keeps the three group headings,
  and asserts every piece of the new dashboard markup sits inside the dashboard
  page rather than in the nav or a neighbouring page.

  Verified against both accidents: removing one nav entry fails three
  assertions, and moving dashboard markup into the sidebar fails the
  containment check.

## [4.1.0] - 2026-10-06

### Added
- **The dashboard is rebuilt around period comparison.** Three headline
  figures — threats stopped, web attacks blocked, connections blocked — each
  showing this period, the change against the period before it, and the overall
  total. Below them an attacks-overview donut with this-period-against-last
  bars, an alerts panel, per-day charts for web attacks and for threats, and a
  summary list. The period is selectable (7 / 30 / 90 days).

  A number on its own says nothing about direction, which is why the comparison
  is the centre of the layout rather than a detail.

- **The product icon replaces every spinner.** The full lockup is the
  first-load splash; the icon with a caption underneath is the blocking
  overlay and the per-page loading state. A mark the user already associates
  with the product says *which* thing is working, where a generic ring could
  belong to anything on the page. It sits still for anyone who has asked for
  reduced motion.

- The new icon is now the browser tab icon, the touch icon, and the WHM and
  cPanel plugin icon.

### Fixed
- **Every chart guarded by `window.Charts` has been silently disabled.**
  `charts.js` declares `const Charts`, and a top-level `const` is not a
  property of `window` — so `window.Charts?.timeline` was always `undefined`
  and the guard meant to be defensive turned the chart off instead. The
  brute-force chart added in 3.36.0 had therefore **never drawn once**. Found
  by rendering the new dashboard in a browser rather than trusting it.

### Notes
- The summary reports only what the product actually measures. A metric we do
  not collect is left out rather than shown as zero: "Database infections: 0"
  on a product that never looks at a database is a claim, not a reading, and
  there is now a test that fails if one is added.
- Percentage change has awkward cases. A period with no predecessor reports
  "no earlier period" rather than a fabricated figure.

## [4.0.2] - 2026-10-06

### Fixed
- **The firewall page was never the problem.** Three previous attempts looked
  only at firewall code. The cost was on the licence gate, which runs on
  **every** API request: with a licence key whose cached local key has gone
  stale, `License::status()` called the licence server with a 12-second
  timeout — and a failure was recorded nowhere, so the next request tried
  again, and the next. The firewall page fires three requests and cpsrvd
  serialises them, which is why it was the worst page rather than the only slow
  one.

  A failed check now backs off for 15 minutes, and a check that happens while
  someone is waiting for a page gets a 3-second timeout instead of 12. The
  scheduler and the Refresh button still get a full, unthrottled check, so a
  licence that comes back is picked up promptly.

  Measured: first request 535ms, every request after it **0–1ms**. Each one
  previously paid the full timeout.

### Changed
- **The firewall page loads in stages, behind a blocking overlay.** The three
  calls were awaited together, so the slowest decided when *any* panel
  appeared and the page sat blank until the last landed. Now the counts render
  first, then the rules table, then the blocked list — each drawn as its data
  arrives. The overlay is up for the whole sequence, so the page cannot be
  clicked into a queue of overlapping work while it fills in.

## [4.0.1] - 2026-10-06

### Fixed
- **The installer banner still spelled SENTINEL.** It is ASCII art — the name
  drawn in block characters, not written as text — so no search for the old
  name could find it, and it was the first thing an operator saw when
  installing ServerScrub. It now reads SERVER over SCRUB, in the silver and
  green of the logo. Two lines because eleven letters in that font is 99
  columns, which wraps on an 80-column terminal and turns the banner into
  noise.

  There is now a test that asserts the drawn letters, so a brand name hidden in
  art cannot survive the next rename either.

- **Two more references the sweep could not match**, both because the product
  name wrapped across two comment lines: one in `install.sh` about exempting
  the daemons from LFD, one in `FirewallEngine.php` about licensing. A
  line-by-line replacement cannot see a name split over a newline.

- `backend/signatures/custom.sig` still carried the old name in its header;
  `.sig` was not in the swept extension list.

### Note on what you saw
The install in that session downloaded **3.37.2**, not 4.0.0 — the CDN still
serves the old layout at `/sentinel-gate/code/`, so `get.sh` resolved an old
`latest.json` and fetched an old release. That install was genuinely Sentinel
Gate; it was not 4.0.0 showing old names. The CDN needs the new
`/serverscrub/code/` path before the primary channel will serve 4.x.

## [4.0.0] - 2026-10-06

### Changed — the product is now ServerScrub

Everything that answered to "Sentinel Gate" now answers to ServerScrub: the
install directory, the systemd units, the WHM and cPanel registrations, the
command-line tool, the database file, the WAF include and the logo.

| Was | Is |
|---|---|
| `/usr/local/sentinel-gate` | `/usr/local/serverscrub` |
| `sentinel-gate-monitor.service` | `serverscrub-monitor.service` |
| `sentinel-gate-web.service` | `serverscrub-web.service` |
| `/usr/bin/sentinel` | `/usr/bin/serverscrub` |
| `database/sentinel.db` | `database/serverscrub.db` |
| `sentinel-waf.conf` | `serverscrub-waf.conf` |
| WHM plugin `sentinel_gate` | `serverscrub` |

**Upgrading migrates in place; it does not install alongside.** An existing
server has its database, its quarantined files and its settings under the old
path, so the installer stops the old services, kills the detached scan workers
that outlive them, removes the old cron entries, deregisters the old WHM plugin
and Driver module, and then **moves** the directory — a move, not a copy, so
several hundred quarantined files cannot be left half-written. The database is
renamed along with its write-ahead log, so an uncheckpointed transaction is not
stranded. If something already exists under the new name, the old install is
set aside rather than either being overwritten.

The WAF include is renamed rather than deleted: Apache references it by name,
and removing it would silently drop every rule.

### Added
- The new logo throughout: the login screen, the header mark, the activation
  card, the browser tab icon, and the WHM and cPanel plugin icons. The two
  hand-drawn shield marks are gone — two different shields in one interface is
  one too many.

### Notes
- **You will be signed out once.** The session secret is derived from the
  product name, so existing tokens stop validating. Signing in again is all
  that is needed.
- The release history below is left as it was written. It records what the
  product was called at the time; rewriting it would be a false record rather
  than a rename.
- The internal `SG_` constant prefix is unchanged. It appears in roughly 400
  places, is never shown to a user, and renaming it would multiply the chance
  of one missed reference becoming a runtime fatal for no visible benefit. Say
  the word and it can follow as its own change.

## [3.37.2] - 2026-10-06

### Fixed
- **The firewall page is fast now, and cannot go slow again.** This was
  reported three times. The first fix removed a pointless `csf -l`; the second
  bounded the commands and cached them for 60 seconds. Both missed the real
  problem: **the work was still on the request path.**

  A 60-second cache still means one request a minute pays for an `iptables -L`
  that can sit waiting on the xtables lock — and because cpsrvd serialises
  requests, that one request stalls every other page behind it. Caching made
  the slowness intermittent, which is why it kept being reported after being
  "fixed".

  Nothing on a page load spawns a process any more. `iptables` and CSF are
  measured by the scheduler, once at install, and the page only reads what they
  left behind. Measured with 3,000 blocked addresses: `getStats()` returns in
  **0.4ms**, and the test fails if any shell call reappears on that path.

- **"Not measured yet" is now distinguishable from "zero rules".** Reporting an
  unmeasured server as `0 iptables rules` reads as "no firewall", which is a
  very different claim. There are three states: measured, measured-and-failed,
  and not yet measured.

### Added
- **Every API response carries how long it took** (`ms`), and anything over a
  second is logged as a slow request. Two attempts at this page were spent
  reasoning about which call was slow without ever timing one.

## [3.37.1] - 2026-10-06

### Added
- **Values printed on the attack timeline.** The chart showed the shape of a
  line and nothing else, so a peak could be seen but not read.

  Not on every point: thirty days across three series is ninety numbers on one
  small chart, which is less readable than none. Labels go on the regularly
  spaced points, the most recent one, and **each series' own peak** — never on
  a zero, because a flat run of "0 0 0 0 0" hides the numbers that matter.
  They carry thousands separators, since 97,400 beside 3,174 is otherwise hard
  to compare at a glance.

  Labels are placed around each other rather than at a fixed offset. Offsetting
  by series alone is not enough — two series at *adjacent* dates with similar
  values collide, which put "120" and "58" on top of one another in testing.
  Each label is now moved clear of the ones already placed, flipping below the
  point when there is no room above.

- **Every day has a hover value**, including the unlabelled ones: hovering a
  date shows all three series for it. That covers the rest of the chart without
  printing ninety numbers on it.

### Fixed
- **The timeline only ever showed its first render.** It replaced the `<svg>`
  with `outerHTML`, and the markup it generated carried no `id` — so from the
  second refresh onward `getElementById('timeline-chart')` found nothing and
  the update silently did nothing. `refreshDashboard()` is called from six
  places, so the chart on screen was whatever was true when the page was
  opened. It now replaces the contents and leaves the element alone.

## [3.37.0] - 2026-10-03

### Added
- **What happens to an infected file now depends on how bad it is.**

  | Severity | Action |
  |---|---|
  | high / critical | disabled, then deleted outright |
  | medium | disabled, quarantined, deleted after 5 days |
  | low | disabled, quarantined, deleted after 7 days |

  All three detection paths previously ran the same three lines — "if
  auto-quarantine is on, quarantine it" — so a webshell and a suspicious
  comment were treated identically. They now share one decision in
  `applyThreatPolicy()`.

- **Files are made inert before anything else happens.** Between detection and
  the move, a file is still executable by the web server; every permission bit
  is removed first. If the move or delete then fails, the original mode is put
  back — leaving a customer with an unreadable file *and* the malware still
  present would be the worst of both outcomes.

- **Quarantine is swept on a schedule.** Each file goes when its own deadline
  passes, and anything still present beyond the retention period goes
  regardless — which is what clears files quarantined before deadlines existed
  at all.

### Changed
- **Quarantine retention is 7 days, down from 30.** The seed is
  `INSERT OR IGNORE` and cannot change an existing row, so there is an explicit
  one-time migration. It only ever *shortens* the setting, so an operator who
  deliberately chose less than 7 keeps it, and it is marked so a later
  deliberate change is not overruled by the next upgrade.

### Security
- **A high-severity detection is deleted with no copy kept, so a false positive
  destroys a customer's file permanently.** That is the behaviour that was
  asked for and it is what ships, but it is the sharpest edge in this product,
  so: the path, size and SHA-256 are recorded in the threat row, the log and a
  security event *before* the file is removed, and a note is left in its place
  saying what was taken and that recovery means going to backups. None of that
  restores the file — it means an operator can see exactly what happened.
  `policy_high_action` can be set to `quarantine` to give high severity the
  same grace period as the rest, without turning protection off.
- Per-severity periods are capped by the global retention, so a deadline can
  never promise a grace period the sweep will not honour.

## [3.36.0] - 2026-10-01

### Added
- **Brute-force detection, which the dashboard had been charting since it was
  written.** The attack timeline queries `security_events` for
  `type='brute_force'`; nothing had ever written one, so the line sat flat at
  zero on servers that were certainly being attacked. `rate_limit_ssh` was
  seeded as a setting and read by nothing at all.

  `BruteForce` reads authentication logs — SSH (`/var/log/secure`,
  `auth.log`), cPanel's `login_log`, Exim/Dovecot and pure-ftpd — counts
  failures per source address, and acts when one crosses a threshold inside a
  window. Reading is incremental: an auth log on a server under attack grows
  quickly, and re-reading it from the top every few minutes is how a detector
  becomes the load problem it was meant to report on.

- **A Brute Force page** in the sidebar: counts for 24 hours and 7 days, a
  14-day chart, the offending addresses with the usernames they tried, and
  which log sources were actually found — because "nothing is attacking you"
  and "we are reading nothing" otherwise look identical.

- **Settings that do something**: detection on/off, automatic blocking on/off,
  failures before blocking, the window they are counted in, how long a block
  lasts, retention, and an allow list. Minutes in the interface, seconds in the
  setting.

- **Counts on the dashboard** beside the timeline, with a link through to the
  new page.

- Automatic blocking goes through the existing firewall. Loopback, private
  ranges and allow-listed addresses are never blocked: locking the operator out
  of the server while defending it is not a trade worth making. One event per
  offender per window, not one per failed password, so a single attack cannot
  bury everything else on the dashboard.

### Fixed
- **A found-while-building defect worth recording.** PDO's SQLite driver binds
  every parameter as TEXT. A *column* comparison is unaffected, because SQLite
  applies the column's INTEGER affinity to the text operand — but `COUNT(*)` is
  an expression with no affinity, so `HAVING COUNT(*) >= ?` is false for every
  count. The detector collected failures correctly and then silently never
  crossed its own threshold. The comparison now casts, and a test proves both
  halves rather than trusting the explanation.

## [3.35.0] - 2026-10-01

### Added
- **rkhunter and chkrootkit are installed with the product.** The Rootkit
  Scanner page offered both tools and then reported them "Not installed",
  leaving the operator to work out what to do about it. A tool the product
  offers should be there when the product is.

  On RHEL-family hosts these live in EPEL, and cPanel cautions against enabling
  it because it can shadow packages cPanel manages. So the configured
  repositories are tried first, and only if that fails is EPEL added — with the
  repository left **disabled** and enabled for that single transaction
  (`--enablerepo=epel`). Nothing else on the server is exposed to it, then or
  at any later update.

  Nothing here can fail the install: `RootkitEngine` is built in and needs
  neither tool. `--no-rootkit-tools` declines them outright.

- **rkhunter's file property database is initialised at install**, in the
  background. Until it exists every system binary looks modified, so the first
  scan is a wall of warnings that means nothing.

- `sentinel install-rootkit-tools` retries the install — for a host with no
  network at install time, or an operator who declined and changed their mind.
  The Rootkit page now says this rather than just showing "Not installed".

### Changed
- **Rootkit scanning is nightly by default** (03:00, after the usual backup
  window). The schedule, its settings and its scheduler task all already
  existed and were fully wired, but shipped *unseeded* — so it fell back to the
  code default of weekly. A rootkit that arrives on Monday should not wait
  until Sunday to be noticed.

### Fixed
- The new installer step first landed inside the cPanel-only Apache restart
  block, where a standalone install would have skipped it entirely. There is
  now a test asserting it sits at top level, ahead of that section.

## [3.34.1] - 2026-10-01

### Fixed
- **The newest WAF event was never stored.** The parser only flushed an entry
  when it met the *next* one, so the most recent was always left pending — and
  because the read offset still advanced to the end of the file, it was never
  seen again either. On a quiet server that is every event. Entries are now
  committed when their `-Z--` terminator is read, and the offset only advances
  past entries that are complete, so one still being written is read in full
  next time rather than half-parsed and skipped.

- **The IP column, third attempt — this time tested against the real thing.**
  Both previous fixes were positional and each missed a real layout:

  - The original looked for an address immediately after the timestamp's
    closing bracket, which is where the unique id sits. It matched nothing.
  - 3.34.0 assumed the unique id was always present. Servers without
    `mod_unique_id` have no such token, and it missed all of them.

  Addresses are now found by tokenising the line and taking those that validate
  as IPs, which is true of both layouts and of IPv6. More importantly,
  `tests/test_waf_parse.php` now writes audit logs in each layout, runs the
  real ingester over them, and checks what reaches the database — the only kind
  of assertion that would have caught either bug.

### Added
- `sentinel waf-parse-test [n]` and `waf/parse-test`: show the raw section-A
  lines from this server's log beside what the parser extracted. After getting
  this wrong twice from assumptions about the format, the fix is to be able to
  look.
- `sentinel waf-reingest [--clear]` and `waf/reingest`: read the audit log
  again from the beginning. Events already stored keep whatever was parsed when
  they were ingested, so a parser fix does nothing for them on its own — the
  offset has long since moved past. `--clear` removes the existing rows first,
  because re-reading without it stores a second copy of everything older than
  the 60-second dedup window.

## [3.34.0] - 2026-10-01

### Added
- **Clicking a WAF event opens a detail dialog.** The table truncates the
  message and the URI — the two fields that say what was actually attempted —
  so a row could be read but not understood, and there was no way to see the
  rest. The dialog shows every stored field in full, wrapped rather than cut
  off, and offers the actions that follow from reading one: block the source
  address, check its reputation, or copy the details. Rows are reachable by
  keyboard, and the two IP actions are disabled for events that have no source
  address.

### Fixed
- **Every event was stored with an empty source IP.** ModSecurity's section A
  is `[time] uniqueId clientIp clientPort serverIp serverPort`, and the pattern
  looked for an address immediately after the closing bracket — where the
  unique id actually is. It never matched. The WAF page was therefore listing
  attacks with no way to act on their source, which is most of the value of
  having the log. The server address is now captured separately, and IPv6
  parses.
- **`user_agent` had a column and nothing ever filled it.** It is parsed now
  and shown in the dialog.

### Security
- **The WAF table rendered attacker-controlled data as raw HTML.** Every field
  in it arrives in an HTTP request from whoever is probing the server — the
  URI, the user agent, and the rule message, which quotes the data that
  matched. The renderer interpolated them straight into `innerHTML`, so a
  request crafted to carry markup would execute as script in the dashboard of
  whoever read the log. An attack log is the last place that should be true.

  Every column is escaped now, and the dialog sets `textContent` rather than
  `innerHTML`. Verified in a browser against the shipped renderer with a
  payload in the URI, the user agent and the rule message: it renders as text
  and does not execute.

## [3.33.0] - 2026-10-01

### Fixed
- **The WAF recorded nothing, on every install.** `ingestModSecLog()` existed
  and worked, but its only caller was an API route nothing ever invoked — no
  scheduled run, no call on page load. `waf_events` therefore stayed empty for
  ever, and the WAF page showed no attacks on servers that were certainly
  receiving some. Without events there is nothing to judge a ruleset by, which
  is the point of having them.

  It now runs on every scheduler tick (every 15 minutes).

- **It was also reading the wrong file.** `MODSEC_AUDIT` is
  `/var/log/modsec_audit.log` — the Debian default, and the path our own
  installer writes into its config. cPanel's EasyApache 4 logs to
  `/var/log/apache2/modsec_audit.log`, so on a server using cPanel's own
  ModSecurity there was never a file at our path. The ingester checked
  `file_exists()` and returned 0 silently, which is indistinguishable from a
  quiet server. The path is now resolved against the places ModSecurity is
  actually known to write, remembered once found, and re-resolved if it
  disappears. `waf_audit_log_override` covers anything unusual.

- **Reading is now incremental.** The old version opened the file and read from
  the top on every call. Put on a schedule, that would re-parse the entire
  audit log every 15 minutes — gigabytes of I/O on a busy server — and
  duplicate every entry older than the 60-second dedup window. It now resumes
  from the recorded offset and restarts only when the file shrinks, which means
  rotation.

- **An empty WAF table now explains itself.** "No attacks were blocked" and
  "nothing is reading a log" rendered identically. The page now says which,
  names the paths it looked in, and offers a button to read the log
  immediately.

### Added
- **A blocking busy overlay for actions.** Every request that changes something
  raises it, so the page cannot be clicked into a queue of overlapping work.

  Deliberately not shown for plain reads: the monitor page polls itself every
  15 seconds and an overlay flashing on each poll would be worse than none.
  Showing it is delayed by 180ms so a fast request does not produce a flash
  that reads as a glitch; the count is released in a `finally`, so a thrown
  fetch or an early return cannot strand it and lock the user out of the error
  it is reporting. `API.withBusy()` is available for slow reads.

- `scripts/check-cron-requires.php`, wired into preflight: every class a cron
  script names must be required by it. A scheduled task referencing an unloaded
  class fatals the moment it becomes due, and cron output goes to a log nobody
  reads — so the symptom is a feature that silently never runs. This had
  happened three times: `UserReport`, `RealTimeMonitor` and now `WAF`.

## [3.32.0] - 2026-09-29

### Added
- **Malware scans now stand down during a backup, as the real-time monitor
  already did.**

  Reported with a `top` capture taken during a JetBackup run: the monitor was
  sitting at 1% CPU, correctly suspended, while `clamscan` ran at 58% in
  uninterruptible I/O wait against the same disks rsync was using. The pause
  added in 3.30.0 lives inside the monitor daemon, and a malware scan is a
  separate process that knew nothing about it. The quiet half of the product
  stood down and the loud half did not — and the loud half is the one that
  reads every file on the server.

  A running scan now checks between batches and waits while a backup is in
  progress, rather than abandoning the scan: it resumes and finishes, and a
  sleeping worker costs one idle process. It keeps its lock slot while waiting,
  since a second scan starting because this one is politely asleep would defeat
  the purpose. A stop request still takes effect while it waits, and after
  `scan_backup_max_wait` (4 hours) it gives up and leaves the work to the next
  scheduled run rather than sleeping indefinitely.

  A scan will not *start* into a backup either — `startScan()` refuses, and the
  scheduler defers with a log line instead of trying.

  `scan_pause_on_backup`, on by default. Both halves use the same probe, so
  they cannot disagree about what counts as a backup.

## [3.31.1] - 2026-09-28

### Fixed
- **"Paused — jetbackup" over a server with no backup running.** The detector
  added in 3.30.0 matched `jetbackupd` by name and `/jetapps/` in the command
  line. JetBackup runs a *permanent* daemon, and every JetBackup process lives
  under `/usr/local/jetapps` whether or not a backup is happening — so on any
  server with JetBackup installed the monitor suspended itself immediately and
  never resumed. Real-time scanning was permanently off on exactly the servers
  the feature was written for, and the process responsible was an idle daemon
  at 0% CPU, invisible in a CPU-sorted `top`.

  Matching now asks "does this mean a backup is running", not "is this part of
  the backup software". The always-on daemons are excluded explicitly
  (`rt_backup_exclude`), and a JetBackup match requires a command line naming a
  queue or job rather than an install path. `rsync` is unchanged: it only runs
  while it is transferring.

  The same defect was in `RealTimeMonitor::backupProcesses()`, the PHP probe
  added in 3.31.0 — which means auto-resume could never have fired either, as
  the probe always believed a backup was in progress.

- **A pause now records what matched.** The pid and command line are stored and
  shown in the UI, so "Paused — jetbackup" can be checked rather than argued
  with.

- **A suspension could outlive the daemon that set it.** The flags live in the
  database and only the daemon writes them; one killed while suspended never
  reaches its resume path, and its replacement starts with no suspension in
  memory so it never clears them either. The daemon now clears a leftover
  suspension at startup, and the status API refuses to report a suspension when
  the daemon is not running or when the flag has outlived the configured
  maximum.

- **The Real-Time Monitor page never refreshed itself.** It loaded once when
  opened and then showed that snapshot until Refresh was pressed — so a state
  that changes on its own, which is the entire point of pausing and
  auto-resuming, was routinely wrong on screen. The page and the dashboard
  widget now poll every 15 seconds while visible, and stop when they are not,
  when a start/stop is mid-flight, or when the tab is in the background.

## [3.31.0] - 2026-09-28

### Fixed
- **The monitor could not be turned on at all once a backup had finished.**
  `stop()` gained `systemctl reset-failed` in 3.30.1; `start()` did not. A unit
  sitting in `failed` will not start, and once systemd's start rate limit is
  reached it refuses outright with "start request repeated too quickly" -- so
  pressing Start achieved nothing, however many times it was pressed. Starting
  now clears a failed unit first, and recognises the rate-limit refusal and
  retries after resetting it.

### Added
- **Monitoring comes back on its own once the backups are done.** A `rtguard`
  task runs on every scheduler tick -- cron already fires the scheduler every
  15 minutes -- probes for JetBackup and rsync directly in `/proc`, and starts
  the monitor once they have gone.

  This is a different problem from the pause added in 3.30.0. That one lives
  inside the daemon and suspends its scanning; it works only while the daemon
  is running. A daemon that has been *stopped* can do nothing for itself, so
  something outside it has to notice the backup has ended. Without that, a
  monitor that went down during a backup window stays down until a person
  notices and presses Start.

- **It will not overrule a deliberate decision.** Stopping the monitor while no
  backup is running records that somebody wanted it off, and auto-resume leaves
  it off. Stopping it *during* a backup does not record that: it reads as "off
  for the backup", which is the case this exists to undo. Starting it by hand
  clears the flag either way.

- `rt_autostart_after_backup` (on by default) and a toggle in the Real-Time
  Monitor settings card. Auto-starts are recorded as security events, so the
  monitor coming back is visible rather than silent.

- An `every` schedule cadence, meaning every scheduler tick. Previously a
  schedule string the scheduler did not recognise fell through to "not due",
  which is indistinguishable from being switched off.

## [3.30.6] - 2026-09-28

### Fixed
- **Killing a clamscan did nothing, because the worker immediately started
  another.** Reported as processes being "spawned immediately" however often
  they were killed. That is the worker doing exactly what it is built to do: it
  forks one `clamscan` per batch, so killing one ends that batch and the next
  begins. The worker is what has to die, and it has to die *first*.

  `Scanner::killRunawayScans()` does it in the only order that works: note each
  worker's `clamscan` children while the parent link still exists, kill the
  workers so nothing can spawn a replacement, then kill the children that were
  noted. Doing it the other way round is what makes `clamscan` look immortal.

- **A running scan could become invisible, and nothing could then stop it.**
  Two faults combined:

  `reapStaleJobs()` marked any job with no recorded `worker_pid` as
  `interrupted`. Workers started before 3.30.1 never recorded one, because the
  column did not exist then -- so after an upgrade a perfectly live scan was
  declared dead. Its row stopped showing as running, `liveScans()` could no
  longer see it, and `stopAllScans()` found nothing to stop.

  Meanwhile `isCancelled()` accepted only `cancelling` and `cancelled` as a
  reason to stop, so a worker whose job had just been marked `interrupted` read
  that as "carry on" -- and carried on scanning, forking a `clamscan` per batch,
  with no row anywhere accounting for it.

  Jobs with no recorded pid are now matched against the processes actually
  running (by `--job-id=` in the command line) and the live worker is adopted
  rather than declared dead. `isCancelled()` now treats any status that is not
  `running` or `pending` as a stop -- including a row that has been deleted
  outright.

- `Scanner::scanWorkerPids()` finds scan workers in `/proc` rather than trusting
  the database about what is executing, and `stopAllScans()` kills the ones no
  row accounts for. `sentinel scan-reap` and `scan-stop-all` now report what is
  actually running rather than what the table believes.

  Only `clamscan` processes parented by our own workers are ever killed. cPanel
  runs its own `clamscan` for mail, and nothing here matches on process name.

## [3.30.5] - 2026-09-28

### Changed
- **One scanner process. `scan_max_concurrent` now defaults to 1**, reverting
  the 2 that shipped in 3.30.4.

  The reasoning that makes 1 the right number rather than a cautious one: each
  `clamscan` loads the entire ClamAV signature database into its own memory --
  650MB to 1.3GB per process on the reporting server. A second concurrent scan
  therefore buys a second copy of that database and two processes queued on the
  same disks. It does not halve the runtime, and it is the mechanism by which a
  server ends up with six of them and no CPU left.

  The value remains a setting, still clamped to 1-4, so an operator who wants
  more can have it deliberately.

### Fixed
- **An upgrade from 3.30.4 would silently have kept the old limit of 2.** The
  settings seed is `INSERT OR IGNORE`, which by design cannot change a row that
  already exists -- so changing the shipped default alone would have left every
  3.30.4 install running two scanners. There is now an explicit migration that
  resets the stored value.

  It is marked so it runs exactly once: an operator who later sets this to 2 on
  purpose keeps that choice rather than having every subsequent upgrade quietly
  overrule them.

## [3.30.4] - 2026-09-28

### Fixed
- **Upgrading did not stop the scans that were already running.** 3.30.3 added
  the guard that prevents new scans from stacking, but nothing dealt with the
  ones already on the server. Those workers are detached, so nothing else stops
  them: they keep running the *old* code against a database the installer has
  just migrated, and they keep their `clamscan` processes. Installing now stops
  every running scan as its own step, before the new scheduler can start any,
  and clears stale slot locks.
- **`Scanner::reapOrphanClamscans()` was never going to help here.** It
  deliberately skips any process group whose worker is still alive, because it
  is an *orphan* reaper -- so on a server with several live scans it correctly
  reported them and killed nothing. That is right for a reaper and wrong as a
  cleanup tool, which is what was missing.
- **`stopScan()` stops one job.** With several scans stacked up, stopping them
  meant finding every job id first. Added `Scanner::stopAllScans()`, the
  `scanner/stop-all` route, and `sentinel scan-stop-all`.

### Changed
- **The concurrency limit is now 2 by default, and configurable, rather than
  a hard 1.** 3.30.3 enforced a single scan; that was a choice made without
  being asked for. `scan_max_concurrent` defaults to 2 and is clamped to 1-4 --
  clamped because each `clamscan` loads the entire ClamAV signature database
  into its own memory (650MB-1.3GB observed), so raising it multiplies memory
  and disk contention rather than dividing the work.
- The worker's lock is now one file per permitted slot rather than a single
  exclusive lock, so the cap is enforced at the filesystem no matter what
  started the scan.
- `scanner/running` reports the live scans and the cap, not just the newest job.

## [3.30.3] - 2026-09-28

### Fixed
- **Nothing limited how many scans ran at once.** Reported from a live server:
  six `clamscan` processes together, each holding 650MB-1.3GB of RSS and taking
  roughly half the CPU.

  `Scanner::startScan()` inserted a job and spawned a detached worker with no
  check for one already in progress, and every route into it -- the UI button,
  the CLI, the scheduler -- did exactly that. Concurrency is not a tuning
  question for this program: every `clamscan` process loads the entire ClamAV
  signature database into its own memory, so six scans meant six copies of the
  same database and six processes competing for the same disks. One scan that
  finishes sooner is strictly better.

  There is now a single-flight guard in `startScan()`, and an exclusive
  `flock()` in the worker that covers what the guard cannot see: a cron entry
  firing during a manual scan, duplicate cron entries left by an upgrade, or
  the script run by hand. A worker that loses the race records `skipped` and
  exits 0, because declining to stack a second scan is the correct outcome and
  not something to page anybody about.

- **The scheduler started one scan per configured path, in parallel.** It
  called `startScan()` in a loop, and each call spawns a detached worker
  immediately -- so three scan paths meant three scans and three `clamscan`
  processes every scheduled run, by design. It now starts one job covering
  every path, and the worker walks them in turn, honouring a stop request
  between paths as well as between batches.

- **A killed worker left its job at `running` for ever**, since a process that
  is killed never reaches the code that sets a final status. Enough of those
  and the database claims several scans are in progress when none are. Stale
  jobs are now reaped and recorded as `interrupted` -- never as `done`, which
  would report an abandoned scan as a completed one.

- **A single `clamscan` invocation had no time limit.** One was found holding
  13 minutes of CPU and 1.3GB of RSS on one file, blocking its worker for all
  of it. Each batch is now bounded by `timeout(1)` (`scan_batch_timeout`,
  600s); threats reported before the cut-off are kept, and only the rest of
  that batch is lost.

- New `scanner/reap` route and `sentinel scan-reap` command to clear dead jobs
  and kill `clamscan` processes their workers left behind. Orphans are matched
  by process group against a dead worker, never by process name: cPanel runs
  its own `clamscan` for mail, and a name-based reaper would kill that too.

### Security
- **Stopping a scan could have signalled the web server.** `posix_setsid()`
  fails when the process is already a group leader, and 3.30.1 fell back to
  whatever `posix_getpgid(0)` returned -- the process group of whatever
  launched the worker, which is cpsrvd or php-fpm. `stopScan()` signals that
  group, so stopping a scan would have sent `SIGTERM` to every process in it.
  The group is now recorded only when the worker genuinely leads it; otherwise
  nothing is stored and only the worker pid is signalled.

## [3.30.2] - 2026-09-23

### Fixed
- **The dashboard's Real-Time Monitor widget did the opposite of its label.**
  It was populated only by `toggleMonitor()`, so on a fresh dashboard it kept
  whatever the markup shipped with -- a green "Active" badge -- while the
  module-level `monitorRunning` stayed `false`. The button reads "Stop" in the
  HTML, so the first click called **start**. Reported as "I cannot turn it
  off"; it was turning it on.

  The dashboard now loads the monitor status when it refreshes, the widget
  ships as "Checking…" with the button disabled rather than asserting a state
  it has not read, and `toggleMonitor()` refuses to act before the first status
  load rather than acting on a guess.
- **The Scanner page never read the auto-quarantine setting.** The
  "auto-quarantine off" line was hard-coded in the markup and corrected only by
  `loadSettings()`, which runs on the Settings page. Opening the Scanner page
  directly showed the default whatever the toggle was set to, so the toggle
  looked like it did nothing. The setting itself was always honoured by the
  scanner; only the display was wrong. The page now reads it on load, and says
  "state unknown" if the read fails instead of asserting "off".
- **The firewall page could hang the whole dashboard.** `iptables -L` takes the
  xtables lock, and on a CSF server lfd rewrites rules continuously, so that
  call can sit waiting for a lock another process holds. cpsrvd serialises
  requests, so one stuck call stops every page responding -- not just the
  firewall one.

  Every shell command on that path is now bounded twice over: `-w 2` gives
  iptables a limited wait for the lock instead of an unlimited one, and
  `timeout(1)` bounds the command in case the binary ignores `-w`. The iptables
  count and the CSF status are cached for a minute, since neither changes
  between page refreshes and each costs a fork. The cheap database counts are
  read before anything forks, and a failing call can no longer reject the whole
  page load.
- A count that could not be taken was reported as `0` rules and the status line
  printed "iptables active" regardless -- both of which read as a working
  firewall with nothing in it. An unavailable count now says so.
- The Real-Time Monitor **page** badge showed a green "● Running" for a monitor
  that was up but scanning nothing, and for one deliberately paused for a
  backup. Both now have their own state, as they already did on the dashboard.

## [3.30.1] - 2026-09-23

### Fixed
- **The scanner's Stop button did not stop anything.** It cleared the progress
  poller, hid the progress card and announced "Scan stopped" — without telling
  the server. The scan carried on at full speed with clamscan running flat out.
  The button did not fail to stop something; it reported a stop that had never
  happened.

  Two things are worth separating here. The real-time monitor's Stop button
  stops the monitor daemon, which never runs clamscan — it uses its own pattern
  engine. clamscan belongs to a **scan**, and there was no way to stop a scan
  at all: once started it ran to completion whatever the operator did.

  Stopping now happens on both sides, because either alone is unreliable. The
  job is marked `cancelling`, which the batch loop checks between batches and
  exits cleanly with its partial results recorded; and the worker's process
  **group** is signalled, which reaches the clamscan it is currently blocked
  on. Signalling the worker alone would leave that clamscan to finish its
  batch, which on a large file takes a while — the reported symptom.

  The worker now detaches into its own session (`posix_setsid`) and records its
  pid and process group on the job row, so there is something to signal. A
  scan stopped part-way is recorded as `cancelled`, never as `done`: writing
  `done` over a partial scan tells the operator the tree was examined when most
  of it was not. Any clamscan still present after the signal is counted and
  reported rather than glossed over.

- **A failed systemd unit could not be cleared from the dashboard.**
  `systemctl stop` on a failed unit succeeds and leaves the state exactly where
  it was, so the service card showed "failed" indefinitely — and once systemd's
  start rate limit is reached it refuses to start the unit again until it is
  reset. Stopping now runs `systemctl reset-failed` when the unit is in that
  state, which is what leaves the service in a condition Start can act on.
- The `reset-failed` check read `$detail['state']`, a key `serviceDetail()`
  does not return; it returns `active`. The check would never have fired.
- The PID fallback in the monitor's stop path signalled only the process, not
  its group.

### Added
- `scanner/stop` and `scanner/running` routes, and `Scanner::stopScan()`,
  `runningJob()` and `isCancelled()`.

## [3.30.0] - 2026-09-23

### Added
- **Real-time monitoring now stands down while a backup or bulk transfer is
  running, and resumes when it finishes.** JetBackup walks every account on the
  server and rsync streams the result off-box; a real-time scanner trying to
  keep up is competing with the backup for the same disks at the moment the
  server can least afford it.

  While one is detected the monitor keeps reading inotify events -- so the
  kernel queue does not overflow, which is not a state it recovers from
  cleanly -- and discards them instead of scanning. The polling fallback skips
  its filesystem walk entirely, and deliberately does **not** refresh its
  baseline while paused: doing so would adopt everything the backup window
  changed as the new normal, so a file planted during the pause would never be
  reported. The first pass after resuming compares against the state from
  before the backup.

  Detection reads `/proc` directly rather than forking `pgrep` every twenty
  seconds, matches on process name with a JetBackup command-line fallback, and
  cannot match the monitor itself. Both the inotify and polling loops consult
  it, so the behaviour does not depend on whether `inotify_simple` happens to
  be installed.

- **Settings for it**, in the Real-Time Monitor card that saves them: an
  on/off toggle (on by default), the process names to watch for
  (`jetbackup,rsync` by default), how long to wait after they disappear before
  resuming, and a maximum suspension.

### Security
- **The pause is capped, because it is a trigger anyone on the box can pull.**
  Matching on a process name means a process merely *named* `rsync` is enough
  to suspend scanning, so someone who can start a process could otherwise
  suppress monitoring indefinitely. Past `rt_backup_max_suspend_secs` -- four
  hours by default -- the monitor resumes regardless and raises a security
  event, and a wildcard in the process list is rejected rather than matching
  everything. Suspending and resuming are both recorded as events, with the
  length of the gap, so an unusual pause is visible rather than silent.
- **A pause is reported as its own state, not as "Active".** The daemon is
  running while suspended, so a check for "running" alone rendered a green
  badge over a monitor that is deliberately not scanning -- claiming protection
  that is paused. The badge now reads "Paused", names what is running, and the
  card states plainly that changes made during the window are not scanned in
  real time and that the next scheduled scan covers them.

### Fixed
- The first `poll()` of the detector waited out a full check interval before
  looking at anything. Starting the daemon in the middle of a nightly backup
  therefore meant scanning hard for the first twenty seconds -- precisely the
  case this feature exists to avoid.

## [3.29.0] - 2026-09-23

### Added
- **Sentinel Gate now appears in the Security section of cPanel for every
  user**, not only in WHM, and the page behind it is a real one.

  Two things stood in the way. The menu entry was gated on a cPanel feature
  that was only ever enabled in `/var/cpanel/features/default`, so every account
  on a reseller's own feature list -- which is most accounts on a reseller box
  -- had the entry hidden. And the page behind it was a redirect to the WHM
  dashboard, which authenticates against WHM, so any user who did reach it
  landed on a login they could never pass. The entry is no longer feature-gated,
  and the flag is written to every feature list rather than only `default` for
  operators who want to add the gate back.

- **A per-user security page.** It shows that account's detected threats, its
  WordPress/Joomla/Drupal installations with versions and whether an update is
  available, and any changed files -- with paths relative to the account's home.

  It reads exactly one file: `~/.sentinel-gate/report.json`, written by the
  privileged side after each scan. It does not talk to the API or the database,
  and it must not: the database directory is `0700 root` and the data is
  server-wide, so reaching it from a page every hosting customer can load would
  require either a setuid helper or loosening those permissions, and both would
  hand every customer on the box a route to the whole server's security data.
  Reading a file in the caller's own home makes cross-account disclosure
  impossible by construction rather than by a filter someone has to maintain.

- **`UserReport`**, which generates those files as root. Every write here is
  root writing into a directory a hostile user can rearrange, so it refuses to
  follow a symlinked home or report directory, verifies the home is owned by
  the account it names, creates the directory without creating parents, and
  renames the report into place rather than opening whatever is already there.
  It is scheduled hourly, generated during install so the plugin is not empty on
  day one, and rebuildable with `sentinel user-reports`.

### Fixed
- A table a module has not created yet -- `cms_installs` before CMS Guard has
  ever run -- raised a PDOException that aborted report generation. As the
  hourly task, for every account on the server. A module that has not run yet
  means nothing to report, not that reporting is broken.
- `scripts/preflight.py` walked only `backend/` and `scripts/`, so the new
  `cpanel/` page -- the file with the widest audience in the product -- had
  neither the empty-file nor the parse gate applied to it. That is the same
  blind spot that shipped a zero-byte `config.php` in 3.19.2.
- The release archive now carries `cpanel/`, and `tests/test_packaging.php`
  fails the build if the user page is missing: without it the installer has
  nothing to copy and the menu entry opens a blank page for every customer.

## [3.28.0] - 2026-09-23

Six reported faults and four requested features, from one production session.

### Fixed
- **The Log Analyzer showed a blank window.** The sidebar has carried a
  `data-page="logs"` entry since the navigation was written, but no matching
  page section ever existed and `showPage()` had no case for it, so clicking it
  hid whatever was open and rendered nothing. It had never been built. There is
  now a Log Analyzer page with per-day selection, level filtering, search and
  download, backed by two new routes. A test asserts that every sidebar entry
  has a page and every page is reachable from the sidebar, so a nav item
  pointing at nothing cannot ship again.
- **Scanner settings had no save control.** The schedule, run time, day and
  scan type could all be changed, and the only save button sat in a different
  card further up the page. The Scanner card now has its own, which re-reads
  the settings afterwards and states when the next scan will run.
- **IP reputation never checked the server's own addresses.** The scheduled job
  re-checks addresses that have *attacked* the server -- a different question --
  and the UI only pre-filled the first server IP into a manual lookup box. A
  server IP landing on a blocklist, which is what quietly breaks outbound mail,
  was checked by nothing at all. Every address the host sends from is now listed
  with its own verdict, checkable on demand and swept by the daily job, which
  raises a security event when one is listed.
- **File integrity monitoring detected changes and then reported none.**
  Detection was correct the whole time; the return values were not.
  `createBaseline()` never returned the `hashed` count the UI displayed, so
  every baseline said "0 files hashed", and `runCheck()` returned *arrays* of
  affected files under keys the UI added together as if they were numbers --
  and the scheduler logged a `changed` key that did not exist, so a scheduled
  check reported "0 change(s)" however much tampering it found. Both now return
  scalar counts alongside the detail. `tests/test_integrity.php` baselines a
  real tree, edits, adds and deletes files, and asserts each is reported.
- **CMS Guard could not justify its own verdict.** The minimum versions were
  hard-coded -- WordPress 6.4, a 2023 release -- so sites well behind current
  were reported as up to date, and the table showed a version and a bare "!"
  with no indication of what it was compared against. Thresholds are now
  settings with current defaults, each row carries the version it was judged by
  and a risk level, and the list is ordered worst-first.
- **The firewall page was slow for three avoidable reasons.** `iptables -L
  INPUT` ran without `-n`, so it resolved every address in the ruleset back to
  a hostname one DNS lookup at a time; `csf -l` was executed and its output
  discarded without ever being read; and `csf --version` was forked on every
  call. The first is the one that turns a page load into tens of seconds on a
  server with a few hundred blocks.

### Added
- **Bulk resolve for security events**, with a select-all checkbox and a bar
  that stays visible with its buttons disabled until rows are ticked. Resolving
  a single event previously returned success unconditionally, including for an
  id that matched no row; it now reports what actually changed. Resolving is
  also admin-gated, which it was not.
- **The quarantine location is visible and editable in Settings**, with a
  read/write test that actually writes and reads back rather than trusting
  `is_writable()`, and a move that relocates existing files. Quarantined files
  are evidence and are moved, never deleted. The settings page no longer names
  the old root-partition path as fact.
- **A rootkit scan schedule**, which the scheduler has honoured since it was
  written -- nothing in the UI could set it, so it ran on its weekly default.
  The intervals offered are only those `isDue()` implements: an option outside
  that set saves cleanly and then never fires.
- **Confirmation that cPanel users and resellers follow the server version.**
  The WHM UI copy is refreshed from the installed frontend on every
  registration, an update re-runs registration, and the cPanel user entry point
  redirects to the live install rather than holding its own copy. Asserted by
  test rather than assumed.

### Security
- Security event fields -- type, source IP and target -- were interpolated into
  the events table unescaped. They come from the requests of whoever attacked
  the server, so this rendered attacker-controlled markup into the page of the
  operator reviewing that attack. The same applied to CMS install paths, which
  a hosting customer chooses. Both are escaped.
- The events table declared seven columns and rendered six: the Description
  cell was missing entirely, so every cell after it was shifted one column left
  and the Status column rendered empty.

## [3.27.5] - 2026-09-23

Fixes for five faults seen in one production install run, none of which
anything in the pipeline had an opinion about.

### Fixed
- **The firewall engine was initialised with php-cgi**, which rejects `-r`
  outright, so the installer reported its firewall backend as a php-cgi usage
  screen and then warned that initialisation had failed. `php` and
  `/usr/bin/php` are not interchangeable on a cPanel box: the latter is
  routinely a symlink to php-cgi, and the former is often the EasyApache Perl
  wrapper. The installer now resolves one interpreter at startup by asking each
  candidate what SAPI it is and taking the first that answers `cli`, and every
  PHP call -- including the cron entries and the boot-time firewall restore
  unit, which bake in an absolute path -- goes through it.
- **`install.sh: line 622: : No such file or directory`, twice.** `MANIFEST`
  was defined further down the script than the firewall section that appends to
  it, so those two redirects ran with an empty filename. The definition block
  also opens the file with `>`, so even had they worked the keys would have been
  truncated away and the uninstaller would never have known about the firewall
  service it was meant to remove. `MANIFEST` is now defined at the top, outside
  the `--register-only` guard, since the cPanel registration section appends to
  it in both modes.
- **ClamAV signatures downloaded successfully and were then reported missing.**
  The search list held distro paths only; cPanel keeps its database under
  `3rdparty/share/clamav`. The installer now asks `clamconf` where the database
  lives and derives a path from the `clamscan` actually in use before falling
  back to a fixed list.
- **`install_plugin` failed for both cPanel themes** with `lacks the required
  parameter "icon"`, leaving the plugin to appear only through the legacy
  dynamicui fallback. The icon is now copied in beside `install.json` and
  declared in it, and in the dynamicui conf.
- **The post-install self-test failed a working installation.** It demanded a
  cPanel Perl shebang on the WHM CGI and ran `perl -cw` over it -- left over
  from when that CGI was Perl. It is a `/bin/sh` dispatcher, and the
  installer's own API check returned JSON in the very same run. The test now
  takes the interpreter from the shebang, checks it exists, and syntax-checks
  with it. Two further false alarms in the same run: the AppConfig check looked
  for `acls=all` while the installer deliberately writes `acls=any` and called
  the field missing, and `pgrep -x cpsrvd` never matches because cpsrvd
  rewrites its process title, so it warned that cpsrvd was down on a server
  actively serving WHM.

### Added
- `tests/test_install_wiring.php`: asserts the interpreter resolution, that no
  call bypasses it, the manifest ordering, the ClamAV search paths, the plugin
  icon, and that the self-test no longer contains the three stale assertions.

## [3.27.4] - 2026-09-23

### Fixed
- **The release package carried build leftovers.** v3.27.3 shipped
  `backend/daemon/__pycache__/monitor.cpython-310.pyc` and `-312.pyc` --
  bytecode compiled on the maintainer's machine for interpreters no target
  server runs, since cPanel hosts are on Python 3.6. Nothing broke, because
  Python only loads a `.pyc` matching its own version, but the staging step
  should copy the source tree rather than whatever happens to be sitting in it.
  `__pycache__`, `*.pyc`, `*.pyo` and `.DS_Store` are now pruned, and
  `tests/test_packaging.php` fails the build if any reappear.
- **The release could not be built on the maintainer's machine at all.**
  `make-release.sh` called `zip`, which Git Bash on Windows does not ship, so
  publishing stopped at `zip: command not found`. It now falls back to Python's
  `zipfile`, setting the mode bits explicitly so the packaged shell scripts stay
  executable (zipfile would otherwise write them 0600).

## [3.27.3] - 2026-09-23

### Fixed
- **A routine update aborted and rolled itself back**, printing
  `Unsuccessful stat on filename containing newline at
  /var/cpanel/ea4/ea_php_cli.pm line 87`.

  On cPanel the `php` on PATH is not PHP. It is a Perl wrapper that selects an
  EasyApache interpreter, and when the argument it is given contains a newline
  it tries to stat that argument as a filename and dies -- before any PHP runs
  at all. The scripts passed several multi-line `php -r "..."` payloads, so the
  wrapper exited non-zero, `set -euo pipefail` turned that into an abort, and
  the error trap restored the previous version. A working update was discarded
  over how the script that applied it was formatted.

  All ten payloads across `install.sh`, `update.sh`, `test.sh` and
  `uninstall.sh` are now single-line, which the wrapper accepts. Two `//`
  comments inside one of them became `/* ... */` so they could share a line.
  Nothing else about them changed.
- **Database migrations no longer run from a `-r` payload at all**, and can no
  longer fail the update. They run from a temporary file using a verified CLI
  interpreter, and a failure is now a warning: `Database::get()` applies
  migrations on first use anyway, so throwing away a good code update over a
  hiccup here was the worse outcome.
- **The update printed a wall of 404s before succeeding.** The download chain
  tried `builds/` and `v<version>/` ahead of `dist/`, which is the path that
  actually exists, and asked every channel for all three. It now tries `dist/`
  first and gives up on a host after two failures -- a host that is down does
  not come back for the next URL.

### Added
- `tests/test_shell_php.php`: asserts no shipped script contains a multi-line
  `php -r`, and parses every payload with `php -l` so a collapsed line cannot
  hide a `//` comment that swallows the rest of it. The shell scripts are the
  one part of the product nothing else exercises -- they run as root on the
  customer's server, where a mistake is found by the customer.

## [3.27.2] - 2026-09-23

### Fixed
- **The bulk Quarantine/Delete buttons were missing from the malware scanner.**
  They shipped in 3.26.0, but into the wrong table: the patch anchored on the
  first `<thead>` in the file, which belongs to the dashboard's events table.
  They were also a `<div>` placed directly inside `<table>`, which browsers
  hoist out of the table or discard. The buttons existed in the source and were
  absent from the page they were asked for.

  They now sit above the threats table, outside the table element.
- **The bar was hidden until something was selected**, so anyone looking for a
  way to act on several files saw nothing and reasonably concluded it had not
  been built. The bar is always visible and the buttons enable once rows are
  ticked.
- The empty-state row still spanned 8 columns after the checkbox and View
  columns were added, so "no threats detected" rendered short of the table.

### Notes
- The test that should have caught this asserted only that `threat-bulk-bar`
  existed *somewhere* in the markup - true of a bar in the wrong table, in
  invalid HTML. It now asserts where it sits, that it is not nested inside a
  table, that the buttons are present and enabled by selection, and that the
  empty-state colspan matches the real column count.

## [3.27.1] - 2026-09-23

### Fixed
- **Updating was impossible on the server that most needed the update.**
  `update.sh` copied `${INSTALL_DIR}/quarantine` and `logs` into
  `/var/backups/sentinel-gate` on every run - duplicating, on the same root
  partition, the very directory that had filled it. The update replaces only
  `backend/`, `frontend/` and `whm/`, so neither was ever at risk and neither
  needed copying. The backup now holds the database, `mode.php` and custom
  signatures: the things an update can actually destroy.
- **Nothing ever pruned those backups**, so every update since installation was
  still on disk. The most recent three are kept (`SG_KEEP_BACKUPS` to change it).
- **The update now checks for free space before touching anything**, and refuses
  with the sizes of quarantine and backups plus the commands that free them,
  rather than failing part-way through.

## [3.27.0] - 2026-09-22

Quarantine filled a live server's root partition. Three separate faults, any one
of which was enough on its own.

### Fixed
- **Quarantine defaulted to a directory on the root filesystem.**
  `QUARANTINE_DIR` was `SG_ROOT . '/quarantine'`, i.e.
  `/usr/local/sentinel-gate/quarantine`. Quarantine *moves* infected files
  there, so on a hosting server - where customer data is a separate and far
  larger volume - a busy scan fills `/` and takes the machine down. A security
  tool must not be the cause of the outage.

  It now defaults to `/home/.sentinel-gate/quarantine`, which is where the files
  being quarantined already live: there is space for them, and the move stays on
  one filesystem, which is also faster. `quarantine_dir` still overrides it.
- **Nothing ever removed anything.** Quarantine grew without limit, so a server
  scanning nightly keeps every infected file it has ever seen until the disk is
  gone. Files older than `quarantine_retention_days` (30 by default, 0 to keep
  everything) are pruned daily, along with per-scan logs, which were also one
  file per scan and never cleaned up.
- **Nothing checked free space before writing.** Quarantining now refuses if the
  move would take the target volume below 5% free, and says so. Leaving the file
  in place is recoverable; a full disk is not.

### Added
- Existing installs are **migrated on update**: if quarantine sits on a
  different filesystem to `/home`, its contents are *moved* there and the
  setting updated. Files are never deleted - they are evidence, and one may be a
  customer's only copy of something. Anything that cannot be moved is left where
  it is and reported.
- `sentinel quarantine status | prune [days] | move <dir>` - see where it lives
  and how much it holds, prune it, or relocate it to another volume without
  editing the database by hand.

## [3.26.0] - 2026-09-22

### Fixed
- **Quarantine and delete failed with no explanation.** `quarantine()` used
  `rename()`, which cannot cross a filesystem boundary - and on a hosting server
  `/home` is routinely a separate volume from `/usr/local`, so it failed with
  EXDEV on exactly the files it exists to handle. It now falls back to
  copy-then-unlink, verifying the copy before removing the original: losing a
  customer's file while trying to protect it is worse than leaving the malware
  in place.

  Both routes also returned `['success' => bool]` and nothing else, so the
  reason never reached the user. They return the reason now - cross-device move,
  unwritable directory, or a file marked immutable with `chattr +i`, which looks
  like a permissions problem and is not.
- **Delete marked a threat removed even when the file was still there.**
  `@unlink()` failing was ignored and the row was updated regardless, so the
  dashboard could report malware deleted while it sat untouched on disk. The row
  is only updated after the unlink is checked.
- **The threats table rendered file paths unescaped.** A file name is
  attacker-controlled; interpolating it into `innerHTML` made the table an XSS
  sink in the dashboard of a security product. Every value in the row is escaped.
- **Refresh buttons appeared dead.** They always refetched - which is why the
  handler check passed - but nothing on screen changed, so on an idle server a
  working refresh and a dead button looked identical. They now disable, show
  progress and stamp the time data last arrived.

### Added
- **Select-all and bulk actions** in the malware scanner: tick individual rows
  or the header box, then quarantine or delete the selection. Destructive
  actions are confirmed first, each file is attempted independently, and
  failures are reported per file with their reason rather than one pass/fail
  for the batch.
- **A read-only file viewer.** Inspect what is inside an infected file without
  running it: the server reads the bytes with `file_get_contents` - never
  including or evaluating them - and the dialog inserts them with `textContent`,
  so a payload made of markup is displayed as characters. Binary files are
  described rather than dumped, and the read is capped at 256 KB.
- `scripts/check-js-syntax.py`, in preflight. There is no Node on the build
  machine, so the only JavaScript validation this project ever had was a regex
  brace counter that mis-handled template literals - it reported a different
  imbalance for correct code and could not distinguish a real error from its own
  confusion. Every front-end change until now shipped unparsed.

## [3.25.2] - 2026-08-28

### Fixed
- **The real-time monitor daemon never started.** It died on its first line with
  `ValueError: Unrecognised argument(s): force` - `logging.basicConfig(force=)`
  requires Python 3.8, and cPanel's RHEL-family hosts ship 3.6. systemd
  relaunched it in a loop, `systemctl start` returned 0 because the process HAD
  launched, and the dashboard reported "Monitor started" over a daemon that had
  already crashed. The logging setup is 3.6-compatible now.
- **A crash loop was indistinguishable from a running daemon.** `is-active`
  answers "active" while systemd is restarting a process on a loop. Status now
  reads `ActiveState` *and* `SubState`: `running` means up, `auto-restart` means
  it is being resurrected. `start()` waits for the unit to settle and returns
  failure - with the restart count and the daemon's last log lines - instead of
  reporting success over something that is crashing.

### Added
- `scripts/check-python-compat.py`, in preflight: the daemon and cron scripts
  are checked against **Python 3.6**, the oldest version the target servers ship.
  The test suite runs on the development machine's interpreter, which is far
  newer, so it proved nothing about the customer's - which is exactly how a
  3.8-only keyword argument shipped.

  Its own first version used a line-by-line regex and reported "compatible"
  about the very call that was crashing the daemon, because `basicConfig(`
  spanned five lines. It uses the AST now.

## [3.25.1] - 2026-08-28

### Fixed
- **"Threat Breakdown - Loading..." never resolved on a clean server.** Every
  chart returned early on empty data, leaving the static placeholder in place.
  So the *good* outcome - a scan finding nothing - rendered as a panel stuck
  loading. Charts now draw an explicit empty state.
- **Monitor start/stop felt laggy and unreliable.** `systemctl` takes seconds and
  the daemon needs longer still to write its PID file, but the button returned
  immediately: a second click could race the first, and the state it flipped to
  was assumed rather than observed.

  It now disables both buttons while working, shows "Starting…"/"Stopping…",
  polls the server until the reported state matches what was asked for, and says
  so plainly when a command was accepted but did not take effect - instead of a
  success toast over a monitor that is not running.

## [3.25.0] - 2026-08-28

### Changed
- **Auto-quarantine now ships disabled.** Quarantine *moves* a detected file
  into `/usr/local/sentinel-gate/quarantine`, which is on the root partition. On
  a hosting server whose customer data lives on a separate volume, an
  enthusiastic scan can fill `/` - and a security tool that takes the server
  down has done more damage than the file it moved. Detection is unchanged;
  threats are recorded either way, and acting on them is now opt-in.

- **Existing installs are not touched.** Settings are seeded with
  `INSERT OR IGNORE`, so a server where quarantine was deliberately enabled
  keeps it. Silently disabling a protective action during an update is not a
  change to make on someone's behalf without saying so - turn it off in
  Settings, or with the command in the release notes.

### Fixed
- The scanner page stated "auto-quarantine enabled" as fixed text regardless of
  the setting. It reports the live value now.
- The Settings toggle explains what enabling it costs, and that detection
  continues without it.

## [3.24.1] - 2026-08-28

### Added
- **A Save button in the Real-Time Monitor section.** The limits were committed
  only by the page-level "Save Changes" at the top of Settings, so editing a
  value here meant leaving the section to commit it, with no confirmation that
  these particular values had landed.

  It reports the outcome in place, and reads the stored values back from the
  server afterwards rather than echoing what was typed - a value outside the
  accepted range is clamped, so showing the typed number would misreport what is
  actually in force.

## [3.24.0] - 2026-08-28

### Fixed
- **A scan did nothing at all.** Under cpsrvd the API runs as `php-cgi`, so
  `PHP_BINARY` *is* `php-cgi` - and php-cgi refuses to run a script from the
  command line without `REDIRECT_STATUS`. The background worker exited on its
  first line, the job row stayed at zero, and the scan appeared to hang. This
  was introduced in 3.20.0, replacing "the bare `php` might not be on PATH" with
  "the interpreter is definitely the wrong SAPI". The worker now uses a binary
  confirmed to report `PHP_SAPI === 'cli'`, asked rather than guessed from the
  filename.
- **Failing requests were invisible.** `if (!res?.success) return;` appears
  throughout the UI: it renders nothing and logs nothing, so a failing endpoint
  looks exactly like a button that was never wired up. HTTP failures are now
  reported centrally, with the server's own explanation. 401 and 402 keep their
  existing handling.
- **Monitor start/stop said only "Action failed".** It now reports why - the
  daemon script missing, systemd refusing, the unit not installed - which is the
  part that makes it actionable.
- **The resource limits could not be edited without first selecting Custom**, and
  the fields were hidden until you did, so the section read as preset-only. The
  limits are always visible, always editable, and editing one switches the
  profile to Custom automatically, so a typed value is never discarded because
  the profile was left on a preset. Selecting a preset fills the fields with the
  numbers that preset stands for.

### Added
- `scripts/check-ui-handlers.php`, in preflight: every `onclick`/`onchange` in
  the markup must resolve to a function that exists. A handler pointing at a
  renamed or never-written function does nothing when clicked - no error, no
  request, nothing - and no other check in this project could see it.

## [3.23.1] - 2026-08-28

### Fixed
- **A licence with no renewal date displayed the customer's name as its expiry.**
  The expiry fell back to `registeredname` when `nextduedate` was absent, which
  is not a date and not something to show in that field.
- A "Free Account" licence returns `nextduedate` as `0000-00-00`. That was shown
  verbatim; it now reads "No expiry".

Both are display-only - validity has always come from the licence status, not
from these dates.

## [3.23.0] - 2026-08-28

Licensing now works against the WHMCS Licensing Addon v3.1.

### Fixed
- **Activation failed on a correctly licensed server.** `diagnose-hash` against
  the live server showed the addon signs with `md5(check_token)` - an **empty**
  secret - and its configuration stores no secret at all. Every release from
  3.21.1 treated that normal state as a misconfiguration, refused to activate,
  and directed the operator to find a value in WHMCS that does not exist.

  The client verifies against the empty secret now. An explicit
  `SG_LICENSE_SECRET` is still honoured for a licence server that does use one.

### Changed
- **The verification secret and the local-key salt are now separate values**,
  which they always should have been. They serve different purposes: one must
  match the licence server, the other only has to be stable and secret on this
  machine.

  Using one value for both was wrong in both directions, and actively harmful
  once that value turned out to be empty - anyone who knew the scheme could mint
  an "Active" local key for any server. The local salt is now 32 random bytes
  generated per installation, stored locally and never transmitted.
- Cached local keys from earlier versions no longer validate and are re-checked
  against the licence server once. No action is needed.
- The "licensing secret is not set" warning is gone from the licence panel: on
  this addon that is the correct state, so the warning would have shown on every
  properly configured server.

## [3.22.2] - 2026-08-28

### Added
- **`sentinel license diagnose-hash`** - identifies how the licence server
  actually signs its replies, by testing candidate formulas against a real
  response.

### Notes
- The WHMCS Licensing Addon v3.1 stores **no secret** in its configuration.
  Confirmed against a live install: `tbladdonmodules` holds only `version`,
  `access`, `clientverifytool`, `maxreissues` and `logprune`. The premise behind
  every licensing message since 3.21.1 - that a shared secret exists and must be
  copied across - was therefore wrong, and no amount of searching the WHMCS UI
  would ever have produced one.

  The client's verification formula, `md5(secret + check_token)`, comes from
  WHMCS's published sample client. Since this addon has no secret to configure,
  either that sample does not apply to v3.1 or the value is derived elsewhere.
  Guessing further is not worth another release, so this command determines it
  from the wire instead.

## [3.22.1] - 2026-08-28

### Added
- **`sentinel license try-secret <value>`** - tests a candidate secret against
  the live licence server without storing it. Finding the right value otherwise
  meant writing each guess into `mode.php` and re-running activation: editing
  live configuration to answer a question, and leaving the wrong value in place
  when the guess was wrong.

### Notes
- `probe` should have existed before any of the licensing fixes, not after
  seven releases of changing one variable at a time. Three genuinely different
  failures all surface as "Invalid" from the client side, and the tool that
  distinguishes them is worth more than any wording change to the messages that
  cannot.

## [3.22.0] - 2026-08-28

### Added
- **`sentinel license probe`** - sends exactly what the real licence check sends
  and shows exactly what comes back, including the raw response.

  Several genuinely different failures all surface as "Invalid", and no message
  can distinguish them from the client side alone: the addon not being installed
  at the configured URL, the key being unknown to WHMCS, and the shared secret
  not matching. probe() reports which one it is, and prints the licence status
  the server actually returned. The secret is never included in the output, so
  the result can be pasted into a support conversation as-is.

## [3.21.5] - 2026-08-28

### Fixed
- **`sentinel license secret` accepted the example text from its own
  instructions.** The documented invocation was
  `sentinel license secret 'YOUR-WHMCS-ADDON-SECRET'`, and that literal string
  was pasted - which is exactly what a copy-pasteable example invites.

  The result was worse than setting nothing: the install reported
  `secret_configured: yes` while holding a value the licence server has never
  seen, so the diagnosis shifted from "no secret" to "secret mismatch" and sent
  the operator looking for a discrepancy between two values when only one of
  them was ever real.

  The documented placeholders are refused now, with a message saying where the
  real value lives and how to generate one. Values under 8 characters are
  refused too, since a licensing salt is not three letters.

## [3.21.4] - 2026-08-28

### Fixed
- **One condition was reported two different ways.** The unconfigured-secret
  guard added in 3.21.1 was only in `activate()`. `status()` therefore still
  contacted the licence server and reported *"the response was signed with a
  different secret than this server is configured with"* - describing an unset
  secret as a mismatch, and sending the operator to compare two values when one
  of them does not exist. Confirmed on a live server reporting
  `secret_configured: false` alongside the mismatch message.

  The guard now lives in `evaluate()`, the path every licence operation goes
  through, so status, activation and refresh give the same explanation and none
  of them contacts the licence server when no reply could be verified.
- Both messages name `sentinel license secret <value>` and say the value comes
  from WHMCS, rather than naming a file to hand-edit.

## [3.21.3] - 2026-08-28

### Added
- **`sentinel license secret <value>`** - sets the WHMCS licensing addon secret
  without hand-editing PHP. 3.21.1 correctly reported that the secret was unset,
  but the only remedy offered was editing `mode.php` over SSH. That file is
  required by `config.php`, so a stray quote there is a fatal on *every* request
  - a worse outcome than the licensing problem being fixed.

  The command edits only the one line, escapes the value properly (a secret is
  an arbitrary string; quotes and backslashes are legal), verifies the result
  parses with `php -l` *before* putting it in place, and keeps a backup. The
  value is never echoed back or logged: it is the salt that makes a cached local
  key unforgeable.
- The licence panel's warning now shows that command rather than telling the
  operator to edit a file.

## [3.21.2] - 2026-08-28

### Fixed
- **The version in the sidebar never changed, however many updates were
  applied.** An install first set up on 3.18.2 kept reporting 3.18.2.

  `mode.php` is written once at install time and recorded `SG_VERSION`. It is
  deliberately not rewritten by updates - `install.sh --register-only`, the path
  `update.sh` takes, leaves it alone so the licensing secret survives. In 3.19.6
  `config.php` was reordered to load `mode.php` FIRST, to silence a redefinition
  warning, and that frozen version started winning.

  This was a regression introduced by that reordering. The sidebar was the
  visible symptom; the update checker comparing against a frozen version was the
  serious one.

  `SG_VERSION` describes the code, not the installation, so `config.php` now
  defines it before including `mode.php` and the installer no longer records it
  there. Existing installs are migrated: the frozen line is stripped from
  `mode.php`, everything else - the licensing secret above all - is left exactly
  as set, and a backup is kept.
- The migration runs on `--register-only`, so an ordinary `update.sh` applies
  it. Placing it with the other install-time work would have skipped precisely
  the installs that need it.
- The **build now stamps the sidebar version label**. It had only ever been
  updated by hand as part of a release, so it drifted whenever a release was cut
  any other way.
- `build.py` stamps the frontend before running preflight rather than after. A
  test asserting the stamp could otherwise never pass: the build that would
  apply it refused to run because the test had not passed yet.

## [3.21.1] - 2026-08-28

### Fixed
- **A correct licence key was rejected as invalid on a server whose licensing
  secret was never set.** Activation reported "License response failed
  verification", which reads as a problem with the key. It is not: the response
  hash is `md5(secret . check_token)`, exactly as the WHMCS licensing addon
  computes it, so while `SG_LICENSE_SECRET` is still its shipped placeholder no
  reply from the licence server can ever verify and every key is refused.

  `secretConfigured()` had existed since licensing was added and **nothing ever
  called it**, so an unconfigured server was indistinguishable from a bad key.
  Activation now checks before contacting the licence server and reports
  `Unconfigured` with the file and setting to fix, stating plainly that the key
  is not the problem.
- A genuine hash mismatch on a *configured* server now says the response was
  signed with a different secret than this server holds - a configuration
  mismatch between the plugin and the WHMCS addon - rather than implying the key
  is bad.
- `status()` carries `secret_configured` on every result, and the licence panel
  warns before a key is entered rather than after it has been rejected.

### Notes
- The verification maths is unchanged and now pinned by a test. If it ever
  drifts, activation fails on correctly configured servers, which is a worse
  failure than the one fixed here.

## [3.21.0] - 2026-08-27

### Added
- **Resource profiles for the real-time monitor.** Reported as putting excessive
  load on a live server. Settings now offers Light / Balanced / Thorough /
  Custom, controlling files examined per second, maximum file size, process
  priority, poll interval, inotify watch ceiling, repeat-event window and
  directory exclusions. Custom values are clamped: a rate of 0 would mean an
  unthrottled monitor, so the floor is 1.
- Limits are **re-read roughly every minute**, so calming a loaded server down no
  longer needs a daemon restart.
- Status reports the profile the daemon actually applied and the live watch
  count, rather than only what was configured.

### Fixed
- **Polling mode was the real cost.** It walked every watched path and stat()ed
  EVERY file each interval, holding a path-to-mtime map for the whole tree.
  Against /home on a shared host that is millions of syscalls per pass, for ever.
  It now filters by extension *before* stat() (a string compare instead of a
  syscall), tracks only files it would ever scan, bounds the tracked set, and
  yields between directories.
- **inotify had no watch ceiling**, and an exhausted kernel watch limit was
  swallowed with every other error - leaving the monitor covering a fraction of
  the tree while reporting itself healthy. The cap is a setting, ENOSPC is
  reported explicitly, and the capped state is visible in status.
- **Repeated events for one file were each scanned in full.** An editor save or
  a deploy produces several events per path; they are coalesced now.
- The monitor asks for **idle I/O priority**. The load here is mostly disk, and
  `nice` only covers CPU.

### Notes
- The existing CPU slider only ever set process priority and the pause between
  scans. It could not stop the monitor walking the filesystem, which is what
  actually loaded the server; it remains, and applies to scans as before.

## [3.20.0] - 2026-08-27

Module audit, items 2 to 5. Minor rather than patch: modules that were never
run now run on a schedule, and the write paths became testable.

### Fixed
- **Real-Time Monitor showed "Active" beside empty counters.** `service_active`
  was actually `isServiceEnabled()` - enabled means "starts at boot", not
  "running now". `isRunning()` also trusted only the PID file, which the daemon
  writes itself into tmpfs, so a lost file made a running monitor look stopped.
  Systemd is consulted now, and enabled/active/installed are reported
  separately. A monitor that is running but has reported no activity for an hour
  is shown as "No activity" rather than green.
- **Bot Shield, CMS Guard, rootkit and file integrity were never run by
  anything.** The cron dispatcher had exactly three tasks: scan, sigs, iprep.
  Every one of those panels reads a database table, and nothing wrote to those
  tables unless a human pressed a button, so they showed zero for ever. All four
  are scheduled now.
- **Security Events had two writers in the whole product** - a failed login and
  one firewall path - so the page was empty even on a server actively finding
  malware. Malware detections and bot blocks now raise events.
- **The scan file count never moved.** `files_scanned` was written once, when
  the job finished, and the value was `countFiles()` re-walking the directory
  afterwards - a census of files present, not a count of files examined. A scan
  stopped part-way left 0 for ever. ClamAV is now run in batches with progress
  recorded after each, and the pattern engine reports as it walks.
- **The scan worker was launched with a bare `php`.** That relies on PATH; the
  API runs under cpsrvd, which is not a login shell. It uses PHP_BINARY now.
- **`Firewall` and `IPReputation` ended the request from inside a library** -
  printing their own JSON and calling `exit()` on an invalid address. That
  bypassed the router's envelope and would have killed a cron task mid-run. They
  throw now, and the router maps bad input to 400 instead of 500.

### Added
- `tests/test_monitor.php`, `test_scheduler.php`, `test_scanner_progress.php`,
  `test_write_paths.php` - 86 new assertions. The suite is 211.
- Command runners are injectable in `RealTimeMonitor`, `FirewallEngine` and
  `WAFInstaller`. The write paths all end in `nft`, `csf` or `apachectl`, none of
  which exist on a development machine, which is precisely why they were the
  last untested part of the product. The tests assert the decisions - which
  command would be issued, what happens when Apache rejects the config, whether
  state is persisted only on success - without pretending the tools are present.
- `scripts/check-calls.php` now checks `(new Foo())->bar()` as well as static
  calls. It immediately caught `(new FileIntegrity())->checkAll()`, a method
  that does not exist, in the new scheduler code.

## [3.19.10] - 2026-08-27

Module audit, item 1 of 5: CMS Guard.

### Fixed
- **CMS Guard reported "0 websites" on a server hosting several WordPress
  sites.** Two independent bugs, either of which alone produced that number.

  Discovery only ever looked at `glob("/home/*/public_html")` - the primary
  document root of each account. On cPanel every addon domain and subdomain has
  its own document root, and WordPress is routinely installed in a subdirectory
  (`/public_html/blog`). Against a fake hosting tree the old logic finds 1 of 3
  installs; it now reads document roots from `/var/cpanel/userdata`, which is
  cPanel's own authoritative record of every domain, and searches up to three
  levels below each one. `wp-content`, `vendor`, `node_modules` and similar are
  skipped so a plugin's sample config cannot register as a phantom install.

  The panel also read `d.total` while the API returns `total_installs`, so the
  counter displayed 0 regardless of what was found. The demo fixture used
  `total`; the real shape had drifted and only the demo was ever exercised.

- **"No scan has run yet" was indistinguishable from "no CMS found".** Both
  showed 0, and the first is what every fresh install shows - which reads as a
  broken product rather than as a next step. `getStats()` now reports
  `last_scan_at` and `ever_scanned`, and the panel says which case it is.

### Added
- `tests/test_cmsguard.php` - builds a fake hosting tree (document-root install,
  subdirectory install, addon domain, CMS-free account, `/var/www/html`, and a
  document root known only to cPanel userdata) and asserts each is classified
  correctly. Includes a demo-versus-real shape check, which caught the `total`
  drift the moment it was written.

## [3.19.9] - 2026-08-27

### Fixed
- **The scan progress percentage was `Math.random()`.** A scan that had examined
  zero files displayed "51 per cent". The value was
  `Math.min(99, Math.floor(Math.random() * 5) + 50)` - a number between 50 and
  54, refreshed every two seconds, with no relationship to anything. In a
  security product this is not cosmetic: it makes a dead scan indistinguishable
  from a working one, and once one number on screen is known to be invented,
  none of them can be trusted.

  There is no honest percentage available - a scan walks the filesystem without
  counting it first, so the total is genuinely unknown until it finishes. The
  bar is now indeterminate while running, and the panel shows the real file
  count from the job row, which was always available and always truthful.
- **A stalled scan looked identical to a running one.** The scan runs detached,
  so the UI cannot observe it dying. A job whose file count has not moved for
  about 30 seconds now says so and points at `logs/scanner.log`.
- **Log Analyzer had no client code at all.** The `logs` module has existed
  server-side throughout; `api.js` simply had no method that called it, so the
  page could never load anything.

### Added
- `tests/test_ui_honesty.php` - fails the build if `Math.random()` or a demo
  fixture value reaches a rendered element outside clearly-named demo code, and
  asserts that every server module has at least one client method. That second
  check is what catches a page like Log Analyzer shipping as navigation with no
  backing calls.

## [3.19.8] — 2026-08-27

A regression suite, and a guarantee that none of it ships.

### Added
- `tests/` — 93 assertions across six files, run in preflight so no release can
  be packaged while any of them fails. Every test is pinned to a fault that
  actually reached a production server, and names it: the truncated and then
  zero-byte `config.php`; `getallheaders()` under the CGI SAPI; the WHM login
  form that should never have appeared; `Database::getSetting()`, which does not
  exist; `Logger::write()`, which is private; routing that searched for a
  literal `api` path segment; `error_reporting(0)` hiding *and* discarding
  errors.
- `tests/test_packaging.php` asserts against the **finished zip**, not the build
  script's intentions — the two have diverged before. It checks that `tests/`,
  `scripts/`, and the 36MB bundled PHP interpreter are absent, that every file
  the product needs is present, that no packaged PHP file is empty, and that the
  package declares the version its filename claims. `build.py` runs it after
  zipping and deletes the archive if it fails.

### Fixed
- **The trial marker path was machine-global and unmockable.** `installedAt()`
  read `/var/lib/sentinel-gate/installed-at` directly, so tests both depended on
  and corrupted real state — a marker left by an earlier run reported an expired
  trial on a fresh install. `License::markerPath()` honours `SG_INSTALL_MARKER`,
  which the test bootstrap points into its sandbox. The default is unchanged.

### Changed
- The test runner treats a crashed test file as a failure. Its first version
  reported "71 assertions passed" while two files had died with fatals — a
  harness that cannot fail is not a harness, and that is the same false-pass
  shape as `php -l` accepting an empty file and the call checker skipping an
  unreadable one.
- `build.py` names `tests/`, `scripts/` and `php/` as never-packaged and fails
  the build if any appears in the archive, rather than relying on them merely
  being absent from the include list.

## [3.19.7] — 2026-08-27

Nothing in this project's pipeline had ever *run* the code it shipped. Every
gate checked it statically, so a method that did not exist was invisible until
the one request that used it reached a customer. That is the actual defect
behind the blank dashboard, the failing scanner, firewall, WAF and IP
reputation — one runtime `Error` each, in code that parsed perfectly.

### Fixed
- **`Database::getSetting()` does not exist — the method is `setting()`.** It was
  called from **11 sites** across `License.php` (7), `cron/scheduler.php` (2),
  `Scanner.php` and `WAFInstaller.php`. Because `License::status()` fatals and
  every feature route consults the licence, this single typo took down the
  dashboard, scanner, firewall, WAF and IP reputation together.
- `sys_getloadavg()` is called without a guard. It is absent on some hosts (and
  on Windows), which turned the whole dashboard payload into a 500.
- API errors now return the exception message, file and line. "Internal server
  error" with the cause hidden in a log file cost several diagnosis cycles that
  one line on screen would have ended.

### Added
- `scripts/check-calls.php` — verifies every `Foo::bar()` exists on `Foo` and is
  public, using `token_get_all()` rather than regex. A regex draft of this check
  missed 7 of the 11 call sites above, because its string-stripping ate real
  code; PHP's own lexer classifies strings, comments and heredocs exactly. An
  unreadable file aborts the run rather than reporting a pass.
- `scripts/smoke.php` — executes all 25 read-only API routes through the real
  router in a throwaway install and requires JSON from each. Only
  side-effect-free routes: nothing starts a scan, writes a firewall rule or
  touches the network. This is what would have caught every fault in this
  release, and in the three before it.
- Both run in preflight, so no release can be packaged without them passing.

## [3.19.6] — 2026-08-27

The dashboard reaches the API now. These are the faults behind the panels that
loaded but stayed empty.

### Fixed
- **Every page that consults a licence went blank.** `License::log()` called
  `Logger::write()`, which is **private** — an `Error`, not a warning, so the
  leading `@` suppressed nothing. Worse, `log()` is called from the `catch` block
  in `status()`, so the fatal *replaced* whatever it was reporting. It now uses
  the public `Logger::info()`, wrapped so logging can never be the thing that
  breaks a request.
- **"Constant already defined" on every request.** `config.php` defined
  `SG_ROOT`/`SG_VERSION` and then included `mode.php`, which set them again.
  `mode.php` is now loaded first and every define in `config.php` is guarded, so
  the file is correct against any vintage of `mode.php` — which matters because
  `install.sh --register-only`, the path `update.sh` takes, does not rewrite it.
- **Scheduled tasks still died with "Undefined constant SG_DB".** Cron entries
  written before 3.19.4 load `mode.php` only, and `update.sh` does not rewrite
  cron, so fixing the installer was not enough on its own. `Database.php` now
  derives `SG_DB` from `SG_ROOT` when it is absent.
- The dashboard shows the server's actual error rather than directing the reader
  to a log file they then have to go and read.

### Added
- Preflight scans for calls to non-public methods across classes. `php -l`
  cannot see these — they are runtime `Error`s, not syntax errors — and this one
  cost a release. Verified by reintroducing the bug: the gate rejects it.

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
