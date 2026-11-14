# ServerScrub 4.36.0

[4.36.0] - 2026-11-13

### Fixed

- **One visit to the Firewall page and one click removed every country block on
  the server, and the toast was green.** This is not new in this batch: the
  code is in the v4.35.1 release commit and dates back to 3.1.2, so it has been
  live and destructive for as long as the page has existed.

  `renderGeoGrid()` read the saved list with
  `Database?.setting?.('geo_block_countries')` — a PHP class, called in the
  browser. Optional chaining does not guard an *undeclared* identifier, so it
  threw `ReferenceError: Database is not defined` on every load, the exception
  escaped `loadFirewallStages()`, and the grid rendered with every country
  unselected. Nothing in the product read that setting back; there was no
  endpoint to read it from. "Nothing is selected" and "this server blocks no
  countries" are the same picture, so **Save Geo Rules** posted `[]`,
  `setGeoBlock([])` wrote `CC_DENY = ""`, ran `csf -r`, and returned success —
  which it returned unconditionally, having checked neither the write to
  `csf.conf` nor the exit status of the reload.

  Both halves are fixed. There is a `GET firewall/geo-block` that reports the
  saved list *and*, separately, what CSF's own `CC_DENY` actually holds — never
  merged, because if they disagree then something outside this product changed
  one of them. The grid gets its selection from that; when the read fails it
  says so instead of drawing an empty grid, because an empty grid is a factual
  claim and it was false. Save refuses to write a list the page never managed
  to read, an intentional "block nothing" is confirmed by a human, and clearing
  a non-empty list is refused unless the caller says so explicitly — the
  refusal names how many countries it would have removed. The write, the
  absence of a `CC_DENY` line, a short write and a `csf -r` that will not
  reload are each reported as failures: "saved in the panel but NOT applied" is
  something an operator must be told, and `enforced: false` is now distinct
  from `success: true`.

  **If you are upgrading, check this by hand.** The wipe has been live since
  3.1.2, so the list may already be gone on a server that never looked:

      grep -n '^CC_DENY' /etc/csf/csf.conf

  An empty `CC_DENY = ""` on a server where countries were once blocked is
  this bug, not a setting. Restore the list, then save it again from the
  Firewall page and confirm the panel and `csf.conf` now agree.

- **The WAF card claimed "ModSecurity is installed and logging matches" with no
  rule files loaded, and printed rpm's error message as the version.** On a
  server whose OWASP CRS directory existed and was empty, the card rendered
  `WAF ENGINE Installed`, "ModSecurity is installed and logging matches, but
  not blocking them yet", `ModSecurity installed package
  ea-apache24-mod_security2 is not installed`, `OWASP CRS vunknown`, and
  "holds no rule files that could be read" — all at the same time.

  `crs_installed` was `crsPath() !== null`, which tests only that a directory
  exists, and `ready` was derived from it, so an empty rule set read as a
  working one and the install button disappeared. A rule engine with no rules
  inspects nothing, logs nothing and blocks nothing. The claim now follows from
  the rule files: they are counted (`crs_rule_files`), `crs-setup.conf` and
  zero-byte files do not count as rules, and the operator-facing sentence is
  composed in PHP from that count, the mode, and whether Apache actually
  includes our config — a mode of "on" with the include gone is a blocking WAF
  filtering no requests, which `status()` has reported all along and the card
  ignored. An unreadable mode says so instead of falling through to "logging
  matches", and the badge has states for "No rules loaded" and "Not in force".

  `modsecVersion()` ran `rpm -q --qf "%{VERSION}" … 2>/dev/null`. rpm prints
  `package <name> is not installed` on **stdout** and exits 1, so the wrong
  stream was redirected and the exit code was never read. It uses `exec()`,
  checks the status, requires the output to look like a version, and returns
  null otherwise — the panel shows "installed, version unknown", which is true.

  This held the release because it is a protection claim the product had not
  verified, which is the shape of the defect that took 132 accounts down for
  two minutes on 7 November: `setMode()` reporting success for a config Apache
  had rejected. That server has one line of defence and no second scanner, and
  April's ransomware went unnoticed for six months partly because nothing
  contradicted the impression that things were fine.

- **`quarantine restore --signature='*' --apply` restored a webshell to a live
  docroot and exited 0.** `selector()` refused a restore with *no* scope but
  never checked that the scope was narrow, so `--signature='*'` became
  `threat_name LIKE '%'` — every quarantined row, every job, every account,
  every signature — and `--ext=md` alone was the same hole by another route: on
  job 12457 that is 154,252 files, which are the 30 April ransom notes.

  A signature wildcard now needs at least eight characters before the `*`, the
  same floor `04aefc1` applies to a suppression prefix — and that one only
  switches detection off, while this one writes attacker code back onto a
  customer's disk. An extension may *narrow* a restore and can no longer
  *define* one: `--job=N --ext=tar,gz,zip`, the documented way to hand back the
  72 archives from that job, is unaffected. The floor is in `selector()`, which
  is where every caller gets its WHERE clause, so the CLI and the API are held
  to it equally. An operator reaching for restore is by definition mid-incident
  and must not be one wildcard away from handing the attacker's files back.

- **The bound on destructive action at scale had no operator-visible lever, and
  the alarm handed over the one command that must not be run.**
  `scan_mass_signature_max` existed only as a settings row — no command, no
  field, no help text. Past the bound a real mass event leaves its findings
  flagged and in place by design, and the ways on from there are suppressing
  the signature (wrong: it hides a live compromise), a per-file verdict on
  153,800 files, or raising the bound. A conservative default with no visible
  lever is a dead end in the incident it exists for.

  `serverscrub scan mass-bound [N]` shows and sets it, is listed in `--help`,
  records the change as a high-severity event, and prints the last trip with
  its evidence and the next step for that verdict —`lastTrip()` was being
  written and read by nothing outside the test suite.

  And the alarm no longer pre-composes `signatures suppress add <signature>`
  for a detection the product has just said it cannot judge. That text was
  shown for the `undetermined` and mass-identical cases as well as the noisy
  one: a ready-to-paste instruction for switching off detection of a live
  root-level ransomware run, at 03:00, to somebody who has been woken up. It is
  written out for `varied-content` only, where every matched file differs; a
  mass-identical verdict says *do not* suppress and names the bound instead,
  and an undetermined one asks for a file to be read before either command.

- **The panel's "already excluded automatically" list omitted the four prunes
  that matter.** `node_modules`, any directory named `cache` or `.cache`, and
  the bind-mounted trees (`virtfs`, `.snapshot`, `.zfs`, `.cagefs`) are pruned
  by name at every depth, in both walkers, for every scan type — and none of
  them were disclosed, so the panel showed a server as covered while four
  categories of directory were never opened. A scan that skipped directories
  must not report clean coverage.

  `.cache` is the one that cost something: the hidden PHP droppers on this
  server lived in `/home/officialwebspace/.cache/`, re-executed every minute
  from a user crontab, and were invisible to a *full* scan for that reason.
  (`.cpanel/caches/` was reachable only because `caches` is not `cache`.)
  Removing the prune needs per-account depth and file-count bounds that do not
  exist yet — an unpruned walk of npm and composer caches across 132 accounts,
  with `/home/virtfs` multiplying it by 118, is the scan that ran for 59 hours
  — so for now the blind spot is at least stated, in the panel, where the
  operator decides what to scan.

- **The product quarantined 154,323 customer files from one signature and
  nothing stopped it.** Scan job 12457 ran for 59 hours doing it, across at
  least twelve unrelated accounts, and raised no alarm. Whatever the signature
  was right or wrong about, moving that many files out of customers' accounts
  unattended is not a thing a scanner may decide by itself.

  So past a bound — 500 files from one signature in one scan, as a setting —
  a finding is **flagged and left in place**: nothing further is quarantined,
  disabled or deleted for that signature. The finding is still recorded and
  still shown, with the reason written on the row, and a **critical** security
  event carries the facts that make the case readable at a glance: how many
  accounts, which extensions, how many distinct files, and the commands that
  undo what has already been taken and stop it recurring.

  **The scan is not stopped, and that is a correction to this patch rather
  than a description of it.** The bound as first written also halted the run,
  on the assumption that a signature matching implausibly many files must be
  wrong about them. That assumption is false, and this server is the
  counter-example. The 154,323-file detection on 10 November was **correct** —
  genuine qTox ransom notes, verified by reading the files and matching the
  attacker's TOX ID — left by a root-level ransomware run on 30 April that
  wrote a note into nearly every directory of nearly every account and renamed
  every database-shaped file to `*.sorry`. It never touched `/var/lib/mysql`
  and never touched site content, so all 118 sites kept serving and nobody
  noticed for six and a half months. A 500-file halt would have ended that
  scan at its 500th ransom note and left roughly 153,800 real ransomware files
  on 132 live accounts, while showing the operator a message that read like a
  false-positive warning. A bound that stops detection fails safe in the wrong
  direction: it fails toward leaving malware in place. Nothing in the bound
  stops, halts or shortens a scan now, and both the test suite and the class
  assert the absence by name.

  Count alone cannot tell the two cases apart, and neither can extensions or
  account spread: both events were ~154,000 matches of one signature, almost
  all `.md`, server-wide — `README.md` is the name of a changelog in
  `node_modules` and the name the attacker gave the note. What separates them
  is how many **distinct files** those matches are. A rule hunting hex strings
  through changelogs full of git SHAs matches files that all differ; ransom
  notes are the same few files repeated across thousands of paths. The product
  now weighs that, from the content hash recorded at detection — one bounded
  query of at most 2,000 rows per signature per job, no file re-read — and
  says which of the three answers it has: a mass event, a noisy signature, or
  that it cannot tell. Where it cannot tell it says so, and it names the next
  step for both readings rather than steering toward one. The verdict changes
  what the operator is told; it does not restart destructive action.

  An absolute count rather than a share: share-of-files-scanned is unknowable
  at the moment it matters, since the walk may be 1% done; share-of-detections
  is 100% on a three-file scan and cannot distinguish the case it is for; and
  per-account spread, which is strong evidence, is also what a reseller's mass
  defacement looks like — so it is reported in the alarm and not used to
  decide. The bound is per signature, so the one finding in that run which
  might have been real is still acted on. A long hex string, for the record, is
  not evidence of a false positive: ransomware contact IDs, wallet addresses
  and campaign identifiers are all long hex strings.

- **A scan's own threat count was wrong by five-fold.** Job 12457 recorded
  `threats_found = 32,003` while the threats table held 154,323 rows for it:
  32,003 was the first account's share. A server-wide sweep calls the scan once
  per account web root — about 120 of them — and both progress counters were
  local to one call, so each path overwrote the previous path's totals, and
  `files_scanned` went *down* whenever a smaller account started. The counters
  are cumulative across paths now, and the figure a finished job records is
  counted from the rows rather than from whatever the worker held in memory.
  The one number an operator would have looked at was understating the incident
  while it happened.

- **Customer scan requests had been silently refused for two and a half days,
  on every account.** A customer clicked "Scan my account", the request landed
  in their home, the page said "Queued", and nothing ever happened.

  The pickup takes an `flock` on `/tmp/serverscrub/user-scans.lock` and keeps
  the handle open, because closing it drops the lock. It then spawns the scan
  worker as a detached child — and **the child inherited the open descriptor,
  and with it the lock**. The pickup exits; the lock lives as long as the scan.
  Established on the server with `fuser`, not inferred:

  ```
  $ fuser -v /tmp/serverscrub/user-scans.lock
  root  2223916  F....  php          <- the pickup, long gone
  root  3824534  F....  sh
  root  3824535  F....  timeout
  root  3824536  F....  clamscan     <- holding a lock it knows nothing about
  ```

  The nightly sweep had started on Sunday at 02:00 and was still running two
  days and eleven hours later, so the lock's lifetime had become the *scan's*
  lifetime instead of the pickup's, and every customer request on a 132-account
  server was refused from Sunday onwards.

  The descriptors are now closed in the child by the shell that spawns it, so
  nothing the worker runs — the worker, `sh`, `timeout`, `clamscan` — can hold
  a lock it never asked for. The pickup also releases the lock where the pickup
  ends, rather than relying on its own process exiting, and records which PID
  holds it so a refusal can say something useful. The container demonstrates
  both halves: a child spawned the new way does not hold the file and the next
  pickup can take the lock while that child is still running; the same child
  spawned the old way does inherit it.

- **The same bug suppressed the only evidence of itself.** A refused pickup
  returned with no log line, exit 0, and without updating the timestamp that
  shows when requests were last looked at — so the one clue pointed at
  "nothing is running" while the service was running fine every five seconds
  and refusing every time. Finding it meant converting a Unix timestamp by
  hand on the server.

  There are two timestamps now, because they answer different questions: an
  *attempt* is recorded before the lock is taken, on every tick, and a *run*
  only when the pickup actually got the lock. A fresh attempt beside a stale
  run is the signature of this fault, and both are printed by
  `serverscrub-scheduler --status`, which is the command an operator already
  runs to ask whether anything is happening. A refusal is logged on the first
  occurrence and then at most once every ten minutes — the pickup runs every
  five seconds, so a line per refusal is 17,280 a day — with how many
  customers are waiting, and a diagnosis that names the holder: *"the pickup
  that took this lock was PID 2223916, which no longer exists, so the lock is
  held by a descriptor it leaked to a child"*, plus the live processes holding
  the file. That sentence is what an afternoon with `fuser` produced.

- **The customer's page said "Queued" indefinitely.** A request that nothing
  has acted on for five minutes now reads "Not started" in amber rather than
  "Queued" in green, says it has not started, and says why when the privileged
  side knows — and that it is the host's side, not theirs, because a stuck
  lock is not something a customer can do anything about. The decision comes
  from the age of the request file in their own home, which is the one signal
  on that page that does not depend on the hourly report, the database, or the
  pickup working at all.

- **The topbar said "Protected" on every page, and nothing ever set it.** The
  status pill was static markup — a green dot and the word Protected, from the
  moment the page loaded until it was closed. Rendered in a browser, it said
  Protected above the scanner card's own grey "Not yet scanned" on a server
  that had never been scanned, and it said Protected, in green, directly above
  the card's own "API unreachable" while the API was answering 500.

  It is the same defect as `MODE = 'On'`, `action = 'block'` on 148,551 events,
  `Coverage 98.7%` and "944 Java Attack / Disabled", and it outlived all four
  because it lived in the HTML rather than in the JavaScript, where no amount
  of reading the code would surface it. A badge that cannot be wrong because it
  never changes is not a status.

  It is driven from the same two figures as the scanner card — the open-threat
  count, and whether any scan has ever finished — by the same code, so the two
  cannot disagree. Five states: the API not answering, the count unreadable,
  nothing scanned yet, threats open with the count, and "No open threats" —
  which is the only green one, the only one that pulses, and reachable only
  after a scan that actually ran. The markup now ships grey and says
  "Checking…", which is also what stays on screen if the script never runs.

- **A licence key dated in the future never expired.** The age of a cached key
  is `(now − checkdate)`, which goes negative for a future date and stays under
  the key lifetime for ever: the key read as freshly verified, never degraded,
  and the product silently stopped re-verifying it. Not reachable by an
  outsider — forging a key needs the salt, which is 32 random bytes in a 0700
  root-owned database — and it fails open, so no customer loses protection; a
  clock set ahead, or corrected backwards after a key was issued, gets there
  without trying. The age is clamped at zero, so such a key counts as checked
  now and expires on schedule once the clock is right.

- **The dashboard contradicted itself on one card.** At the same moment, in
  the same panel, after a scan that had found a threat:

  ```
  ⚠️ 1 Active Threat
  Last scan: 12s ago · 0 new threats
  1,339 Scanned   1,339 Clean   0 Quarantined   0 Deleted
  Coverage 98.7%
  ```

  with the threat listed immediately below. Four of those figures did not come
  from the data: the count beside "Last scan" was a hardcoded zero while
  `threats_found` was being read correctly at four other places in the same
  file; "Clean" was the last scan's file count minus two *all-time* threat
  counts, so a file that is open as a threat right now counted as clean;
  "Deleted" was a literal zero; and the coverage percentage was a constant
  chosen by `total > 0`.

  The two headline numbers do measure different things — "Active Threats" is
  what is open now across every scan, `threats_found` is what the last scan
  found — so each now says which it is: *"Last scan: 12s ago · 1 found by that
  scan"*. `Scanner::getStats()` returns the last scan's own figures (examined,
  found, clean, quarantined, deleted, still open) and the all-time deleted
  count that `app.js` read and the server never sent. Coverage shows nothing,
  because the product counts the files it examined and not how many exist to
  examine.

  And `sc?.active || 0` painted undefined, a failed fetch and a genuine zero
  the same green. A card that could not read the threat count now says
  "Unknown" in grey: nothing must look like success.

  The same applies one step earlier. A freshly installed server showed a green
  "✅ Protected" directly above its own "Last scan: never", because the
  zero-threats branch never asked whether a scan had happened — so "never
  looked" and "looked and found nothing" rendered identically, and that is the
  first thing a new customer sees. Zero open threats across zero scans is not a
  clean bill of health: it reads "Not yet scanned" until a scan has actually
  run, and green is only reachable after one.

  Also in that area: the duplicate-rule-id explanation was spliced into the
  middle of the rollback sentence, producing `…defines an id twice., so it was
  rolled back:`. It follows Apache's own words now, which is also where it
  belongs in the reading order.

- **A database that could not be opened answered every API route with a PHP
  stack trace.** The first query runs inside the authentication check, before
  the handler that produces the JSON envelope, so the client — which expects
  JSON — showed its generic "Server error, please try again", and the response
  body disclosed absolute paths and the internal call graph. The database
  directory is 0700 and root-owned by design, so a panel running as anything
  but root hit exactly this on every request.

  `Database::ready()` is now asked before anything touches the database, and a
  failure is one sentence, HTTP 503, with the path and the reason in the log
  rather than in the response. `auth/status` is deliberately exempt — it reads
  only constants and it is what the panel polls to find out whether the API is
  alive — and it reports `db_available: false`, because "online" on its own
  would be half the truth. `serverscrub-scheduler --status`, which is the
  command an operator runs when something is already wrong, said the same
  uncaught exception; it now names the file and the likely cause.

- **A second ModSecurity ruleset on the server is now named when it collides
  with ours.** Apache answers a duplicate rule id with the file it was
  *reading* — which is our tree, and ours is clean — so the operator was sent
  to look in the wrong place. cPanel ships a vendor ruleset, so this is a
  configuration to expect. The rejection message now names the other ruleset
  and the id, or says plainly that it could not identify it and where it
  looked. The rollback already made this safe; this is about making it
  diagnosable.

- **`waf exclude add` on a server where the WAF has never been armed said
  "Invalid mode".** The CLI passed `currentMode()` — which is the literal
  `unknown` before the first `waf mode` — straight back into `setMode()`, so
  the operator was told their own command was invalid, advised to resolve
  something that was not broken, and given a non-zero exit for an action that
  had worked. The exclusion was saved all along and takes effect the first time
  the mode is set, which is the opposite of what the message said. It now says
  that, names the command that arms the WAF, and exits zero.

- **A licence the server rejects cost a round trip on every single request.**
  The back-off window was only recorded when the licence server could not be
  reached. A server that answers "Invalid" is not a failure — but nothing is
  cached for a key that is not active, so the check was repeated on every page
  load: measured at 1,456 ms for the first call and ~500 ms for each one after.
  A definitive negative answer is now backed off too. The refresh button, the
  scheduler and `license activate` clear or bypass the window, so an operator
  who has just fixed their licence still sees it immediately.

  The cached-key branches either side of that — a stale key inside the 10-day
  grace window, and one past it — had been established by reading the code
  rather than by running it, because every key the signer produces is dated
  today and the date is bound into both of its hashes, so no test could age one
  without forging a signature. The signer takes an optional date now (nothing
  in production passes one), and the grace window, the degraded state and the
  gate past grace are each exercised.

- **`install.sh`'s self-test reported eight failures and exited 1 on a
  successful `--mode standalone` install.** The WHM plugin checks were gated on
  `/usr/local/cpanel` existing rather than on the mode the operator chose, so a
  deliberate standalone install on a cPanel server was told to re-upload the
  zip and re-run the installer — for a plugin it had been asked not to install.
  The exit code is load-bearing: it killed the test container's panel before the
  server started, and any provisioning script that trusts it reads a correct
  install as a failed one. Gated on the mode, reported as "not applicable", and
  a real failure still exits non-zero.

- **An incremental log reader could decide a log had not grown when it had.**
  PHP's stat cache is process-wide and an append does not invalidate it, so a
  cached `filesize()` compared equal to the stored offset and the whole read was
  skipped. Harmless from cron, where every run is a fresh process; wrong in the
  daemon and in anything long-running. Fixed in the brute-force collector and
  in the WAF audit-log ingester, which has the same shape.

- The rollback's byte-count check was built on a claim that is not true:
  `file_put_contents()` answers a partial write with `false` and a suppressed
  warning, not with a short count — that is `fwrite()`'s behaviour. So the
  restore writes through a small helper built on `fwrite()`, and a full
  filesystem now produces *"only 500 of its 1,080 bytes were written"* instead
  of "it could not be written": the first tells an operator the file on disk is
  truncated and the filesystem is full.

- Smaller, all of them found by testing something else:
  - The OWASP CRS version was read as `unknown` from any tree the product did
    not install itself — including cPanel's vendor tree — because the pattern
    expected `OWASP_CRS` before `ver`, and the real file writes
    `ver:'OWASP_CRS/4.7.0'`. The panel rendered that as `vunknown`.
  - An authentication refusal set HTTP 401 but did not carry the code in the
    JSON envelope, so anything reading the envelope rather than the response —
    a cron caller, a shell script, a sweep — could not tell a refusal from a
    success. The licence gate always included its 402.
  - `WAFInstaller::setCrsPath()` and `Scanner::setCpanelUsersDir()` exist for
    the same reason `setConfDir()` does: without them, the code that reads the
    CRS rule files and the code that lists accounts could only be tested on a
    machine that looks nothing like a cPanel server, and the bounding of a
    "quick" scan — the thing standing between a customer and a scan that walks
    all 132 home directories — was verified only where it does not matter.

- **The rollback added above could fail and still be reported as a rollback.**
  Shakaal reproduced it: the config path was replaced with a directory during
  the `apachectl -t` window, `restoreConfig()` wrote nothing, the Apache
  include stayed in place pointing at the rejected config, `currentMode()`
  reported the rejected mode — and `setMode()` returned

  ```
  "error": "Apache rejected the change, so it was rolled back: ...",
  "rolled_back": true
  ```

  That is the 7 Nov outage state, reached through the fix for the 7 Nov
  outage. The earlier version left the rejected file behind *by choice*; this
  one left it behind *by accident* and told the operator to stop looking.

  `restoreConfig()` discarded the result of both of its writes:
  `@file_put_contents` and `@unlink`. It now returns a per-path result, and
  each path is checked three ways rather than assumed: the byte count against
  `strlen()` (a full filesystem returns a **short count**, not `false`, so
  `=== false` would accept a truncated ModSecurity config as a restored one),
  a read-back comparison against the snapshot, and for a file that did not
  exist before, `file_exists()` after the unlink. `rolled_back` is read off
  that result and is never a literal `true` anywhere in the product.

  When the rollback itself fails the product no longer claims one. It says
  what happened, names the file, and — because a config Apache has already
  refused is an outage waiting for the next restart — removes our config and
  its Apache include instead, so Apache will still start with no WAF rather
  than refuse to start at all. If even that fails the message is explicit:
  *move that file aside by hand, now, before anything restarts Apache.*

  The old message also blamed a pre-existing fault for a file the call had
  just left behind (*"Apache may already have been unable to restart before
  this change"*). That sentence is now only printed when the restore is
  confirmed, which is the only case in which it can be true.

- **"Apache rejected the change" was printed on servers where Apache was
  never asked.** With no `apachectl` on the host, `validateApache()` returned
  "could not check" and `setMode()` rendered it as a rejection — sending the
  operator to look for a syntax error that no program had ever reported, and
  rolling back a config that was fine.

  "Could not check" and "checked and rejected" are different facts and are now
  reported as different facts: the result carries `ran` as well as `ok`, and
  with no checker the mode is **not changed and nothing is written** at all.
  Writing an unvalidated ModSecurity config to a server that cannot be asked
  about it is exactly how 7 Nov stayed invisible for ten hours.

  The candidate loop also could not get past its first entry: it returned on
  the first binary that produced any output, and `sh()` folds stderr into
  stdout, so an absent binary's *"No such file or directory"* counted as a
  verdict. On any Debian or Ubuntu host — which `includePath()` claims to
  support — `/usr/sbin/apachectl` does not exist, `apache2ctl` was never
  reached, and a WAF mode could therefore never be set. Every candidate is now
  tried, and one that cannot be executed is skipped rather than believed.

- **One API call could write a rule Apache cannot parse into a live config and
  then restart Apache.** `WAF::addCustomRule()` appended to a file registered
  with cPanel's `modsec2.user.conf`, ran `service httpd graceful`, and
  returned `['success' => true]` unconditionally — no syntax check anywhere,
  and the return of neither the write nor the restart examined. The API
  defaulted the rule id to `uniqid('SG')`, so the ordinary call wrote
  `id:SG6910abc12def3`; ModSecurity ids are numeric, so that is a syntax error.
  This was the 7 Nov outage in a code path the rollback fix never touched.

  The id must now be digits and inside the band reserved for custom rules, the
  pattern must be something that can be rendered into a quoted directive at
  all (a quote is refused, not escaped), `block` and `log` both do what they
  say instead of everything being `deny`, the file is snapshotted before it is
  touched, `apachectl -t` runs **before** any reload, a rejection is rolled
  back through the same verified restore, and the result reports whether
  Apache actually re-read the file — a rule on disk that Apache has not loaded
  is filtering nothing.

- **The two features that generate ModSecurity rules could pick the same id,
  which stops Apache starting.** `WAFExclusions` generates ids from 15,000 and
  documented everything below as available to `WAF::addCustomRule()`, which
  validated nothing: a custom rule at `id:15001` was accepted, and Shakaal
  reproduced the production error from it — *"Found another rule with the same
  id (id:15001)"*, Apache refusing the entire configuration.

  The bands are now disjoint and enforced at both ends: 15,000–19,999 for
  generated exclusions, 20,000–29,999 for custom rules, nothing generated
  below 15,000 where an operator's hand-written rules live. A custom rule is
  also checked against the ids the exclusion generator has actually emitted and
  against the configs we have already written, so the check still holds if a
  band is widened later.

- **The OWASP CRS tree on the production server was corrupt, and the installer
  reported it as fine.** Two definitions of rule 913100 existed in one
  extracted tree, so Apache refused the whole configuration and the WAF had
  not loaded once since 6 Oct while the panel showed it armed. A clean
  re-extraction of the identical 4.7.0 tarball parsed, which is what proves
  the tree was the fault and not the ruleset.

  `installCrs()` ran `tar -xzf` into the live directory and assumed it had
  worked. tar **merges**: a rule file renamed between CRS versions stays
  behind next to its replacement, and a half-finished download replaces a
  working ruleset with a broken one. It now extracts into a fresh staging
  directory, refuses a tree that defines any id twice (named, with the files),
  swaps the tree into place with the previous one kept aside until the new one
  is known good, and validates with `apachectl -t` when our config already
  points at it. A CRS tree that is *already present* is read rather than
  trusted, which is the check that would have caught the production state on
  any day in the preceding month.

- **The product did not parse on PHP 7.4, which `install.sh` accepts.** Thirty
  `match()` expressions — PHP 8.0 — across `backend/api/index.php` (27, the
  whole route table), `Firewall.php` and `RootkitScanner.php`, plus 48 calls
  to `str_contains()`, `str_starts_with()` and `str_ends_with()`, which parse
  at 7.4 and fatal at run time with *Call to undefined function*. On a 7.4 host
  the installer's own gate passed and then every API route was a fatal: 70 test
  files, every one with the same parse error.

  The floor stays where `install.sh` says it is — a server the installer
  accepts must run the product. The `match()` expressions are `switch`
  statements and the three string functions are `strpos()`/`substr()` forms.
  Behaviour is unchanged: every subject is a string, and the arms, their order
  and their expressions are the same.

  `scripts/preflight.py` cannot catch this class. It lints with whatever
  interpreter it finds — 8.5 on the development machine — so "all 55 PHP files
  parse" was true and irrelevant. Linting at the declared floor is Shakaal's
  to close, in the container.

- Smaller things in the same paths:
  - `install.sh` registered `custom_rules.conf` with `Include`, not
    `IncludeOptional`. If that file is ever removed — a partial uninstall, an
    operator tidying up — **Apache will not start**. Every other include the
    product writes is optional for exactly this reason.
  - `WAFInstaller::status()` now reports `include_present` and which validator
    the host has. Our config is only read by Apache if the include that points
    at it exists, and `install()`'s failure path removes the include and leaves
    the config — so the panel could report a blocking WAF that Apache was not
    loading at all.
  - `reloadApache()` returned void, so every caller assumed it had worked. It
    reports whether anything actually reloaded.
  - The CRS version read out of `crs-setup.conf` came back as `.4.7.0`: the
    pattern captured the separator from `ver.4.7.0` as part of the number.

- **A WAF mode change Apache refused left the rejected config on disk, and
  the next Apache restart took every site on the server down.**

  `setMode()` wrote the config, ran `apachectl -t`, and on failure returned
  the error — leaving the rejected file exactly where Apache reads it. Nothing
  looks wrong when that happens: Apache keeps serving the config it parsed at
  its last start, and the operator reads the error as "the mode did not
  change".

  On the production server the file was written at 00:02, the failure was
  reported at 05:02, and at 10:18 the first restart found it:

  ```
  AH00526: Syntax error on line 56 of .../REQUEST-913-SCANNER-DETECTION.conf
  ModSecurity: Found another rule with the same id
  httpd.service: Control process exited, code=exited status=1
  [RESTART FAILURE] httpd.conf rebuild exited 25 during forced restart
  ```

  cPanel retried three times, rebuilt `httpd.conf`, and gave up. nginx
  returned 502 for all 132 accounts until the include was moved aside by hand.

  Both files are now snapshotted before the write and restored on any
  failure, byte for byte — and restored to *absent* when there was nothing
  there before, because an empty config and no config are different things to
  Apache. The restored config is then validated too: if it was already
  unparseable, the operator is told while they are still looking at a
  terminal, instead of at the next reboot.

- **The WAF could not be armed at all on any server upgraded from Sentinel
  Gate.** `serverscrub waf mode on` failed every time with

  ```
  AH00526: Found another rule with the same id
  ```

  The rename left `/etc/sentinel-gate/waf/` in place, holding a complete
  second copy of the OWASP CRS, along with the Apache include that loads it.
  Both copies define `id:913100`, so Apache rejected the config. The failure
  was reported and `apachectl -t` ran before any reload, so nothing was ever
  broken — but the panel showed the WAF as installed with a mode, and the
  engine had never once been armed.

  The installer's migration step renamed one include called
  `sentinel-waf.conf` and matched on that filename. The real include had a
  different name, so it and the directory both survived.

  The cleanup now finds a stale include by the path it *references* rather
  than by its name, and runs on every install rather than only when
  `/usr/local/sentinel-gate` still exists — inside that condition it could
  never run again on a server that had already migrated, which is every server
  with the fault. A file is removed only when every non-comment line in it
  refers to the old path; cPanel's own `modsec2.user.conf` mentions the old
  name too, and deleting that would take ModSecurity's whole configuration
  with it. The old vendor directory under `modsec_vendor_configs/` is
  deliberately left alone for the same reason: cPanel loads it with `Include`,
  not `IncludeOptional`, so removing it stops Apache starting.

### Added

- **`serverscrub quarantine restore` — there was no supported way to put a
  quarantined file back.** On 10 Nov one third-party ClamAV signature
  quarantined 154,323 customer files in a single scan, across at least twelve
  unrelated accounts, 154,252 of them named `README.md`.

  That was first read here as a false positive, on the grounds that the
  signature matches long hex strings and a changelog full of git SHAs looks
  like one. **It was not a false positive.** Every one of those files was a
  ransom note, and the long hex string was the attacker's qTox TOX ID —
  `3D7889AE…` — which is exactly what the signature
  `linux.ransom.sessionscribe.qtox.toxid` is written to find. The detection was
  correct, and the scan was the only reason anyone found out: a root-level
  ransomware run on 2026-04-30 had dropped a note into nearly every directory
  of nearly every account on the server and gone unnoticed for six months,
  because it encrypted only `.sql`, `.db` and `.sqlite` files, never touched
  `/var/lib/mysql`, and left every site serving normally.

  **A long hex string is not evidence of a false positive.** Ransomware
  contact IDs, wallet addresses and campaign identifiers are long hex strings,
  and a signature that matches them matching many files is what a mass event
  looks like from the inside. Restore exists for the case where a detection is
  genuinely wrong, which does happen — not as the remedy for a scan finding a
  lot of malware. The scoping and the dry-run default below matter more under
  that reading, not less: an operator reaching for this during an incident is
  one unscoped `--apply` away from putting 154,252 attacker files back.

  The CLI
  had status, sweep, prune and move; the one restore function took a single id,
  was reachable only from an API route, guessed the quarantine directory from a
  date instead of reading the path it had recorded, verified nothing, restored
  no ownership, and returned a bare boolean.

  Restore is scoped — by job, signature (exact or one trailing `*`), account,
  extension, absolute path, or a list of finding ids — and an unscoped restore
  is refused, because "everything" would put real detections back alongside the
  false ones. It is a **dry run by default**: `--apply` is the only thing that
  moves a file, and the dry run prints the signatures, accounts and extensions
  the scope covers so it can be checked before anything happens.

  Everything else follows from the file being a customer's: the quarantined
  copy is hashed against the hash recorded when it was taken and a mismatch is
  a failure rather than a skip; a file that exists at the original path again
  is never overwritten and is reported separately, because the customer may
  have replaced it; ownership and mode come from the record where there is one
  and from the directory the file is going back into where there is not, with
  the report saying which, since root writing a customer's file back as
  root:root breaks the site a different way; the work is paged by id in batches
  so 154,323 files is not one transaction and an interrupted run re-runs
  without doing anything twice; and the report is restored, skipped-with-reason
  and failed-with-reason with examples, never a bare count. The legacy
  quarantine directories are searched too — `quarantine status` reports
  `/home/.sentinel-gate/quarantine`, and a file quarantined before the rename
  is not under the current path — and the CLI prints where it looked when it
  says a copy is missing.

  Owner, group and mode are now recorded **at quarantine time**, so a future
  restore is exact rather than inferred.

- **A way to switch off one signature by name**, instead of switching off
  ClamAV. `serverscrub signatures suppress add|list|rm`, and a card on the
  Scanner page. A suppression names a signature exactly, or a family with one
  trailing `*` (a prefix under eight characters is refused — `{HEX}*` would
  disable a whole class of rules from six characters).

  It lives in the product's own database, not in a signature file: freshclam
  replaces the whole database and a third-party feed rewrites its own
  directory, so a suppression written there would expire at the next update,
  silently. The check sits where detections are recorded, which every source
  passes through.

  And it is never invisible. Every match is counted and the last one
  timestamped, the panel lists each suppression with how many files it has
  hidden since and who added it and why, and both suppressing and restoring a
  signature are security events. A hole in the defence that nobody can see is
  indistinguishable from a scanner that has stopped working.

- **WAF rule exclusions**, so the engine can be armed without breaking a
  customer's site. Triage could already say a rule looked like it was
  matching a site's own application rather than an attack, and there was
  nothing to do about it. The choice was to leave all 132 accounts in
  DetectionOnly, or arm the engine and find out which sites broke.

  Rule 420047 is the live example: "Bad user-agent (Mozilla/5.0)", 617 hits
  across 150 sites, firing on `/livewire/update`, `/` and `/wp-login.php` — a
  Laravel Livewire endpoint and two ordinary pages, not probes. Arming the
  engine with that rule active would have broken real application traffic on
  150 accounts.

  An exclusion names one rule and may be narrowed to one domain and one URI
  prefix, so switching off a rule for one shop no longer leaves the other 131
  accounts unprotected against what it catches.

  ```
  serverscrub waf exclude add 420047 --domain=shop.example --uri=/shop/checkout \
      --reason="real checkout traffic"
  serverscrub waf exclude list
  serverscrub waf exclude show      # the directives, before they are written
  serverscrub waf exclude rm 3
  ```

  Exclusions are held in the database and re-rendered into the Apache config
  every time it is written. Kept in the config file they would have been erased
  by the next `waf mode on`, silently, at the moment they mattered most. A
  render failure now aborts the mode change rather than writing a config
  missing an exclusion.

- `waf triage` prints the exact `waf exclude add` command for each rule it
  judges a false-positive risk, with the domain and path it actually fired on.
  Retyping a rule id by hand is how the wrong rule gets disabled, or the right
  rule gets disabled everywhere.

### Known limitations in this release

Shakaal passed this build with caveats. They are recorded here because they
describe what the product does **not** do, and an operator deciding what to
rely on needs them.

- **`cache` and `.cache` are still invisible to every scan type, at every
  depth, including a full scan.** Now disclosed in the panel's exclusions
  list, not closed. Malware ran from `.cache` on a production server. See the
  entry above for why removing the prune needs bounds that do not exist yet.
- **The mass-detection work has no WHM card yet.** The CLI lever
  (`serverscrub scan mass-bound`) and the recorded trip evidence stand in for
  it.
- **The geo-block fix was verified against a stub `csf`, not a real CSF
  install.** The failed-write branch of the save could not be executed in test
  at all; that one assertion is structural and labelled as such in the test
  suite.
- **Untested in this cycle:** cpsrvd/AppConfig/LiveAPI, real ModSecurity, real
  Exim, real ClamAV, scale (8 accounts, not 132), and a real 204 MB
  quarantine.
- **Two known minor defects ship.** The restore refusal message says a
  wildcard "cannot define" a scope when an 8-or-more character one does, and
  `MailQueue.php:463` renders an exim failure as "0 messages queued". Both are
  queued for next cycle.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
