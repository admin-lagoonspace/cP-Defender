# Test run — 2026-11-09 (commits dated 2026-11-07)

**Build:** HEAD = `7f397eb` on `main`, 4 unpushed commits. `VERSION` = 4.35.1.
Under test: `9dc209a` (WAF rule exclusions), `f1844fb` (install.sh removes the
leftover Sentinel Gate WAF config), `7f397eb` (setMode rollback — the outage fix).

**Environment:**
- Container: AlmaLinux 8.10, PHP **7.4.33** and PHP **8.2**, sqlite **3.26.0**
  (CLI and PDO), Python **3.6.8**. Docker 29.9.3, WSL2 backend.
- Host: Windows 11, project-local PHP 8.5.10 and Python (degraded fallback only).

**Verdict: FAIL — 4 blockers.** Do not release.

> **Superseded 2026-11-09.** Commit `9c5917e` addresses findings 1, 2, 3, 5 and
> 7. Retested in `docs/findings/2026-11-09-retest-9c5917e.md`, including against
> real Apache 2.4.37 and real ModSecurity 2.9.6, which this run could not do.
> All four blockers are fixed. Findings 6, 8, 9, 10, 12, 13 and 15 remain OPEN —
> see the status table in that file.

**Status: fixed-pending-retest (Wasooli, 2026-11-09).** The verdict above
stands until Shakaal re-tests; what was changed is at the end of this file.

---

## Not tested

This run exercised Linux, PHP 7.4 and 8.2, sqlite 3.26.0, and the Python 3.6
daemon. It did **not** exercise:

- **cpsrvd, WHM AppConfig, LiveAPI, the CGI wrappers.** The container installs
  with `--mode standalone`. cPanel-mode integration is proven only by
  installing on a cPanel box.
- **Real ModSecurity under Apache.** There is no httpd and no mod_security2 on
  this machine. `WAFExclusions::render()` output was reviewed **by eye** against
  the ModSecurity 2.9 reference and checked by a duplicate-id scanner I wrote
  (`docker/apachectl-stub.sh`). **No ModSecurity has ever parsed this output.**
  Finding 4 is a code review, not a test result — do not read it as one.
- **Real Exim.** `exim -bp` is a stub; queue parsing and the 72-hour prune
  decision are tested, delivery is not.
- **ClamAV.** Stubbed, flagging only EICAR.
- **Scale.** 8 seeded accounts and 1,639 files, not 132 accounts. Nothing here
  says anything about how the product behaves at the real size.
- **A real signature match.** The clamscan stub flags the EICAR string and
  nothing else, and the `main.cld` / `daily.cld` files that make the product
  take the ClamAV branch at all are **empty placeholders I created**. The
  detection, quarantine and verdict-gate paths are genuinely exercised; the
  antivirus is not.
- **The dependency-install branch of `install.sh`.** `ipset` is now baked into
  the image, so the bootstrap takes the "All runtime dependencies already
  present" path. The `dnf install` branch does not run here.
- **MySQL.** There is no MySQL client or PDO driver in the container, so the WP
  database sweep discovers installs (11, correctly) and then fails to read
  every one of them. Discovery and the error reporting around it are tested;
  the actual database inspection is not.
- **`apachectl` is mine, not Apache's.** `docker/apachectl-stub.sh` checks one
  thing — duplicate `SecRule` ids across our includes — and returns "Syntax OK"
  for everything else. Every `setMode()` result in this report rests on it.
- **Any mode change on a host without `/usr/sbin/apachectl`.** Finding 5 says
  this cannot work; I did not install a Debian container to prove it.
- **PHP 7.4 beyond the parse gate.** See finding 2: the product does not parse
  at 7.4, so *nothing* below the parse stage has ever run there. The 8.2 figures
  below are the only Linux coverage that exists.
- **`scan_types` on a cPanel-shaped host.** 7 assertions invert when
  `/var/cpanel/users` is populated (finding 9), so quick-vs-full scan bounding
  is unverified in the only environment where it matters.

---

## Findings

### 1. `restoreConfig()` cannot tell whether the rollback happened, and `setMode()` claims it did — blocker

**What happens:** `restoreConfig()` is the whole of the outage fix, and it
discards the result of both of its writes:

```php
foreach ($snap as $p => $contents) {
    if ($contents === null) { @unlink($p); continue; }
    @file_put_contents($p, $contents);
    @chmod($p, 0644);
}
```

`setMode()` then returns `'rolled_back' => true` unconditionally and an error
string that begins *"Apache rejected the change, so it was rolled back"*. When
the restore fails, the config Apache rejected is **still on disk**, the Apache
include is **still pointing at it**, `currentMode()` reports the rejected mode,
and the operator has been told in writing that it was rolled back.

That is the 7 Nov outage state, reached through the fix for the 7 Nov outage.
`7f397eb` closed the window where the rejected file is left behind *by choice*
and left open the window where it is left behind *by accident* — and the second
is worse, because the operator has a sentence telling them to stop looking.

**Reproduce — by hand, as root, on Linux, in the container.** This is the one
that counts, because the product runs as root on the server and root ignores
permission bits. The config path is replaced with a directory during the
`apachectl -t` window, which defeats `file_put_contents` for root too:

```
### attempting: waf mode on (will be rejected) ###
ERROR: Apache rejected the change, so it was rolled back: AH00526: Syntax error
on line 56 of REQUEST-913-SCANNER-DETECTION.conf
ModSecurity: Found another rule with the same id | WARNING: the restored config
does not validate either, so Apache may already have been unable to restart
before this change: ...

### WHAT IS ACTUALLY ON DISK ###
conf path is a DIRECTORY — the restore wrote nothing
drw-r--r-- 2 root root 4096 /etc/serverscrub/waf/serverscrub-waf.conf
include still present: /etc/apache2/conf.d/zz-serverscrub-waf.conf
currentMode() reports: unknown
```

The CLI says "it was rolled back". Nothing was put back; the config is gone
entirely and the Apache include still points at the path.

**Also reproduce:** `php tests/run.php waf_rollback_honesty` (test added this
run; 9 assertions fail on Windows, 7 in the container). The runner callback
fires from inside `validateApache()`, which is exactly between the write and
the restore:

```
setMode returned: {"success":false,
  "error":"Apache rejected the change, so it was rolled back: AH00526 ...
           | WARNING: the restored config does not validate either, so Apache
             may already have been unable to restart before this change: ...",
  "rolled_back":true, "restored_ok":false}

claims rolled_back                : true
conf byte-identical to pre-change : false
REJECTED MODE STILL ON DISK       : true
currentMode() now                 : on
include still present (armed)     : true
```

**Expected:** `restoreConfig()` returns success/failure per path, checks it, and
re-reads the file to confirm the bytes match the snapshot. `setMode()` sets
`rolled_back` from that result, and when the restore failed it says so in those
words — *"the rejected config could NOT be removed and is still on disk at
&lt;path&gt;; move it aside before Apache is restarted"* — because that is a
hands-on-now emergency, not a failed mode change.

Note `file_put_contents` on a full filesystem returns a **short byte count, not
`false`**, so a truncated config is written and would be reported as a
successful restore even if the return value were merely tested for `=== false`.
The check has to be a byte comparison.

Ways the restore fails on a real server, all inside the window `apachectl -t`
takes on a 132-account box: `/etc` fills up; a config-management agent
re-asserts ownership; `chattr +i`, which several hardening guides apply to
`/etc/httpd/conf.d`; the filesystem remounted read-only after an I/O error.

**Also wrong in the same block:** when the restore fails, the message blames a
pre-existing fault — *"Apache may already have been unable to restart before
this change"*. A failed restore and an already-broken config produce an
identical result shape (`restored_ok: false`), and the message points the
operator at the wrong one.

---

### 2. The product does not parse at PHP 7.4, which `install.sh` requires — blocker

**What happens:** three files use `match()`, a PHP 8.0 expression:

- `backend/api/index.php:184` — the entire API entry point
- `backend/lib/Firewall.php:338`
- `backend/lib/RootkitScanner.php:120`

`install.sh:360` is `[[ $PHP_VER -lt 7 ]] && error "PHP 7.4+ required"`, so a
7.4 host passes the gate and then has a dead product: every API route is a
fatal, the CLI cannot load, the panel is blank.

The first-ever run of the suite at 7.4 did not fail, it **crashed**: 70 test
files, every one with the same parse error.

**Reproduce:**
```
PHP_STREAM=7.4 docker compose -f docker/compose.yml run --rm test lint
```
```
════ parse check — php 7.4.33 ════
  PARSE FAIL  backend/api/index.php
              PHP Parse error: syntax error, unexpected '=>' (T_DOUBLE_ARROW) ... line 184
  PARSE FAIL  backend/lib/Firewall.php      ... line 338
  PARSE FAIL  backend/lib/RootkitScanner.php ... line 120
  3 file(s) do not parse at PHP 7.4.33.
```

**Expected:** either the three `match()` expressions become `switch`, or
`install.sh` raises its floor to 8.0 and refuses 7.4 instead of welcoming it.
This is a decision for the user, not for me — but the two statements the product
currently makes cannot both be true.

**Pre-existing, not caused by the commits under test.** `git log -S "match("`
puts the `Firewall.php` one in the initial commit. It has shipped in every
release including 4.35.1. It has never been caught because
`scripts/preflight.py` lints with whatever interpreter it finds — on the
developer's machine, PHP 8.5.10 — so its "all 55 PHP files parse" line is true
and irrelevant. **The gate that exists to catch exactly this cannot catch it.**

---

### 3. `WAF::addCustomRule()` writes an unvalidated rule into a loaded config and restarts Apache — blocker

**What happens:** `backend/lib/WAF.php:760` appends to a file Apache loads, then
gracefully restarts Apache, with no syntax check anywhere, and returns
`['success' => true]` unconditionally:

```php
$rule = sprintf('SecRule REQUEST_URI|ARGS|REQUEST_HEADERS "%s" "id:%s,phase:2,deny,..."', ...);
file_put_contents($confPath, $rule, FILE_APPEND);
exec('service httpd graceful 2>/dev/null || service apache2 graceful 2>/dev/null');
return ['success' => true];
```

Three compounding problems:

1. **The id can be non-numeric.** `backend/api/index.php:871` defaults it to
   `uniqid('SG')`, producing `id:SG6910abc12def3`. ModSecurity rule ids must be
   numeric; that line is a syntax error.
2. **The file is loaded by Apache.** `install.sh:1121-1126` appends
   `Include /etc/apache2/conf.d/modsec_vendor_configs/serverscrub/custom_rules.conf`
   to cPanel's `modsec2.user.conf`.
3. **No `apachectl -t`, ever,** and the return value of neither the write nor
   the restart is examined.

So one API call writes a config Apache cannot parse, tells the operator it
succeeded, and restarts Apache. This is the 7 Nov outage in a code path
`7f397eb` did not touch.

**Reproduce:** code review plus the call graph above; I did not fire it, because
doing so needs a real httpd to be meaningful and there is none here.
`POST waf/add-rule` with no `id` in the body is the path.

**Expected:** the same discipline `WAFInstaller::setMode()` now has — validate
before the file becomes live, roll back and verify on failure, numeric-only id
validation, and a success value derived from what actually happened. The
`$action` parameter is also accepted and then ignored; the rule is always
`deny`.

**Mitigating:** not reachable from the dashboard — `grep` finds no
`waf/add-rule` caller in `frontend/js/app.js`; the "add rule" modal there is the
firewall one. API-only, and pre-existing. I am still calling it a blocker
because the consequence is 132 accounts at 502 and the fix under test was
supposed to have removed this class from the product.

---

### 4. `WAFExclusions::render()` — reviewed by eye only, two real concerns — major

**No ModSecurity and no Apache exist on this machine or in the container.
Nothing below was executed against a parser. Do not record this as tested.**

Generated output, with four exclusions seeded:

```
    # [4] rule 913100 disabled for path /wp-admin/* — path only
    SecRule REQUEST_URI "@beginsWith /wp-admin/" \
        "id:15004,phase:1,pass,nolog,ctl:ruleRemoveById=913100"

    # [2] rule 942100 disabled for host shop.test, path /shop/checkout* — ...
    SecRule REQUEST_HEADERS:Host "@streq shop.test" \
        "id:15002,phase:1,pass,nolog,chain"
        SecRule REQUEST_URI "@beginsWith /shop/checkout" \
            "ctl:ruleRemoveById=942100"

    # [1] rule 420047 disabled for EVERY site and path — a global one
    SecRuleRemoveById 420047
```

What I believe is **correct**, against the ModSecurity 2.9 reference and the CRS
exclusion recipes:

- `SecRuleRemoveById` is emitted *after* the CRS includes in the generated file
  (`{$rules}{$excl}` in `writeConfig()`), which is required — it removes a rule
  that must already be defined.
- The chained form matches the CRS-documented host+path recipe: metadata
  (`id`, `phase`) and `chain` on the first rule, the non-disruptive `ctl` on the
  child. `ctl` is a non-disruptive action and is permitted in a chain child.
- `phase:1` is right for the `ctl`, and `REQUEST_HEADERS:Host` and `REQUEST_URI`
  are both populated in phase 1.
- The id band 15000–99999 sits inside the 1–99,999 local-use range and cannot
  collide with CRS (900,000+).
- Input validation is genuinely good: `uri_prefix` rejects `"`, `'`, `\`, CR and
  LF, so there is no directive breakout, and `reason` has newlines stripped
  before it is rendered into a comment.
- The CLI warns about apex-vs-`www` and about phase-1 target rules, which the
  docblock promises and which I confirmed at
  `backend/cli/serverscrub.php:472-485`. Credit where it is due.

Two concerns that remain:

**(a) The generated id band is shared with `WAF::addCustomRule()`, which
validates nothing.** The docblock at `WAFExclusions.php:46-51` reserves
15,000+ for itself and says below it is "for anything hand-written and for
`WAF::addCustomRule()`, where the operator picks the id" — but `addCustomRule()`
accepts any string and the API defaults to `uniqid('SG')` (finding 3). Nothing
prevents a custom rule at `id:15002`. A duplicate id is literally the 7 Nov
error, *"Found another rule with the same id"*.

**(b) `@streq` on `REQUEST_HEADERS:Host` does not match a Host carrying a
port.** `example.com:8443` is not `@streq example.com`, so the exclusion
silently does not fire and the shop the operator protected still breaks when
the engine is armed. The CLI warns about `www.`; it says nothing about ports.
`@beginsWith` on `REQUEST_URI` is also case-sensitive, so `/Shop/Checkout`
bypasses the exclusion. Both are "the exclusion appears not to work" from the
operator's side.

**Expected:** numeric-id validation and a reserved-range check in
`addCustomRule()`; a duplicate-id check across *everything* the product writes
before any config becomes live; and the port/case caveats either handled
(`@rx ^example\.com(:\d+)?$`) or stated by the CLI the way the `www` one is.

---

### 5. `validateApache()` reports "Apache rejected the change" when no Apache was asked — major

**What happens:** with no validator present, `validateApache()` correctly
returns `ok => false, output => 'Could not run an Apache syntax check'`. But
`setMode()` feeds that straight into *"Apache rejected the change, so it was
rolled back"*. Apache rejected nothing; there was no Apache. `install()` does
the same: *"Apache rejected the configuration, so it was removed"*.

Separately, **every candidate after the first is unreachable.** The loop returns
on the first binary whose output is non-empty, and `sh()` folds stderr into
`out`, so an absent binary produces `No such file or directory` — non-empty —
and the loop returns `ok => false` without trying `apache2ctl`:

```php
foreach (['/usr/sbin/apachectl', '/usr/sbin/httpd', 'apachectl', 'apache2ctl'] as $bin) {
    $r = self::sh(escapeshellarg($bin) . ' -t');
    if (trim($r['out']) !== '') { return ['ok' => $r['code'] === 0, ...]; }
}
```

On any host where `/usr/sbin/apachectl` is missing — every Debian/Ubuntu host,
and `includePath()` claims to support `debian` — a WAF mode can **never** be
set, and the operator is told Apache rejected their config.

**Reproduce:** assertions 8–12 of `tests/test_waf_rollback_honesty.php`.

**Expected:** distinguish "no validator" from "validator said no". With no
validator, refuse the change and say *"no Apache syntax checker was found, so
the change was not applied"* — do not attribute a verdict to a program that was
never run. And probe for existence before deciding, so a missing first
candidate does not end the search.

---

### 6. A database that cannot be opened returns a plain-text stack trace, not JSON — major

**What happens:** every API route, when `Database::get()` cannot open the file,
emits an uncaught `PDOException` as plain text with a full stack trace and
absolute filesystem paths, instead of the JSON envelope:

```
PHP Fatal error:  Uncaught PDOException: SQLSTATE[HY000]: General error: 14
unable to open database file in /opt/serverscrub-src/backend/lib/Database.php:851
Stack trace:
#0 /opt/serverscrub-src/backend/lib/Database.php(851): PDO->prepare()
#3 /opt/serverscrub-src/backend/lib/License.php(591): Database::setting()
```

The throw is from the licence check during bootstrap, before the handler that
produces the JSON envelope is in place — `tests/test_router.php` asserts "a
fatal still produces a JSON envelope" and that passes for a *later* fatal, so
the envelope exists and this path goes around it.

Two consequences: the client gets HTML/text where it expects JSON and shows the
generic "Server error — please try again", which is the whole class
`test_router.php` was written to prevent; and the panel discloses absolute paths
and internal structure in an HTTP response.

The database directory is `0700` root-owned by design (`install.sh:607`,
confirmed at runtime), so a panel running as anything but root hits exactly
this.

**Reproduce:** 6 assertions in `tests/test_router.php` fail in the container;
the raw output above is from running `backend/api/index.php` where the database
path is not writable.

**Expected:** the error handler installed before anything touches the database,
and a DB-open failure rendered as
`{"success":false,"error":"the database could not be opened"}` with the detail
in the log, not the response.

---

### 7. The "OWASP CRS CATEGORIES" panel is a hardcoded array — blocker

**What happens:** `WAF::getRuleCategories()` (`backend/lib/WAF.php:167-186`)
returns a literal array. The whole panel — 16 categories, exact rule counts,
and the Active/Disabled flag on each — is fabricated and reads nothing from the
installed ruleset:

```php
['id' => '913', 'name' => 'Scanner Detection', 'active' => true,  'rules' => 94],
['id' => '942', 'name' => 'SQL Injection',     'active' => true,  'rules' => 214],
['id' => '944', 'name' => 'Java Attack',       'active' => false, 'rules' => 12],
```

It renders identically on a server with CRS 4.7.0, with CRS 3.x, and with no
CRS at all. Observed in the container, where `crs_version` is unknown and the
panel still asserts "942 — SQL Injection · 214 rules · Active".

"944 — Java Attack · **Disabled**" is a specific, actionable statement about a
customer's security posture, and it is a literal `false` in PHP source. An
operator who reads it will either believe Java rules are off and go looking, or
believe the other fifteen are on and stop looking.

**Reproduce:** open the WAF panel; compare against
`backend/lib/WAF.php:167`.

**Expected:** counts and states parsed from the CRS rule files that
`WAFInstaller::crsPath()` already locates, or the panel removed. A number the
product cannot derive must not be displayed as one. This is the same defect as
`action = 'block'` on 148,551 rows and `MODE.textContent = 'On'` — both of
which were fixed. This one was missed.

**Pre-existing**, not from the commits under test.

---

### 8. The dashboard scanner card hardcodes "0 new threats" — major

**What happens:** `frontend/js/app.js:686`:

```js
scanMeta.textContent = `Last scan: ${reltime(lastJob.finished_at)} · 0 new threats`;
```

The `0` is a literal. `lastJob.threats_found` exists and is used at lines 952,
1018, 1023 and 1294. So the card reads "0 new threats" whatever the last scan
found, and when threats are open the same card says "⚠️ 12 Active Threats"
directly above "Last scan: 5m ago · 0 new threats".

**Observed live in the container**, after a full scan that found the seeded
EICAR file. The same card, at the same moment:

```
SCANNER STATUS
Threats Found
⚠️ 1 Active Threat
Last scan: 12s ago · 0 new threats
```

and immediately below it:

```
SCAN COVERAGE   Coverage 98.7%
1,339 Scanned   1,339 Clean   0 Quarantined   0 Deleted
```

1,339 scanned and 1,339 "Clean" while one threat is active and listed in the
panel beneath. Two contradictions on one card.

This is the same class as `action = 'block'` on 148,551 rows: a value presented
as fact that does not come from the data.

**Also, in the same block (lines 670-682):** `const threats = sc?.active || 0`,
then `if (threats > 0) {...} else { '✅ Protected', badge-green }`. The `else`
fires for zero, for `undefined`, and for a failed fetch alike — so a dashboard
that could not read the threat count shows a green "Protected". Nothing must not
look like success.

**Expected:** `${lastJob.threats_found ?? '—'} new threats`, and a third state
for "could not read" that is not green.

---

### 9. `install.sh` self-test reports 8 failures and exits 1 on a successful `--mode standalone` install — major

**What happens:** installing with `--mode standalone` ends in:

```
[FAIL] AppConfig MISSING: /var/cpanel/apps/serverscrub.conf — WHM plugin won't appear
[FAIL] WHM CGI dir MISSING: /usr/local/cpanel/whostmgr/docroot/cgi/serverscrub
[FAIL] Driver file MISSING: .../ConfigObj/Driver/ServerScrub.pm — re-run install.sh
[FAIL] REGISTERED: /var/cpanel/apps/serverscrub.conf missing — register_appconfig did not run
  PASS: 23   FAIL: 8   WARN: 3
  Installation verification failed — 8 test(s) failed
```

and exit code 1. The install succeeded; the installer says it failed and advises
"Re-upload the latest zip and re-run install.sh".

**Cause, precisely:** `test.sh:87` gates the WHM block on the filesystem, not on
the mode:

```bash
if [[ -d /usr/local/cpanel ]]; then
```

`INSTALL_MODE` is already read at `test.sh:39` and is used correctly at lines
191 and 214 — just not here. So the block runs whenever `/usr/local/cpanel`
exists, even when the operator explicitly asked for `--mode standalone`.

**Scope — narrower than it first looks.** On a genuine standalone host with no
cPanel the section is correctly skipped. This bites when `/usr/local/cpanel`
exists *and* the mode is standalone: a cPanel server where the operator chose
standalone deliberately, and this container (`seed-cpanel.sh` creates
`/usr/local/cpanel/logs`).

**Reproduce:** `docker compose -f docker/compose.yml run --rm test upgrade`.

**Why it is major and not cosmetic:** the non-zero exit is load-bearing for
automation. It killed the panel container outright — `do_serve` called
`do_install`, `set -e` saw exit 1, and the entrypoint died before
`exec php -S`, so `up panel` installed successfully and then exited with no
server. Anything that trusts `install.sh`'s exit code — a provisioning script,
or Gabbar's release automation — will read a correct install as a failed one.

**Expected:** `if [[ -d /usr/local/cpanel && "${INSTALL_MODE}" == "cpanel" ]]`,
or the section reported as "not applicable — standalone mode", and a zero exit
when the install worked. An installer that cries wolf trains the operator to
ignore its output, and the next line in that list will be a real one.

**Also:** `install.sh:1125` appends `Include` — not `IncludeOptional` — for
`custom_rules.conf`. If that file is ever removed (a partial uninstall, an
operator tidying up), **Apache will not start.** Every other include the product
writes is `IncludeOptional`, for exactly this reason.

---

### 10. `test_scan_types.php` inverts on a cPanel-shaped host, so quick-scan bounding is unverified — major (test defect)

**What happens:** 7 assertions pass on a machine with no `/var/cpanel` and fail
on one that has it:

```
- scan_types: an account with a web root says so — expected true, got null
- scan_types: with its document root — expected '/tmp/sg-test-.../srv/alice/public_html', got null
- scan_types: a quick scan walks the web roots — expected array(2), got array(8)
- scan_types: with no web roots a quick scan falls back to the full root — expected array(1), got array(8)
```

The test builds accounts in a sandbox scan root; the product reads
`/var/cpanel/users` and `/var/cpanel/userdata`, which is correct behaviour on a
server. So the expectations only hold on a developer's laptop.

**Reproduce:** `php tests/test_scan_types.php` passes in an unseeded container
and fails after `seed-cpanel.sh`.

**Expected:** these assertions are the ones standing between a customer and a
"quick" scan that walks all 132 home directories. They have to assert against
the seeded cPanel layout. Right now the bounding of quick-vs-full is **not
verified anywhere that resembles a server** — which is finding 9's real cost,
not the red lines themselves.

---

### 11. An excluded rule is invisible to the panel, which still reports the WAF as fully armed — major

**What happens:** `WAFExclusions` is referenced only by
`backend/cli/serverscrub.php` and `backend/lib/WAFInstaller.php`. There is no
API route (`grep` finds no `exclusions` action under the `waf` module — the
`exclusions` route at `backend/api/index.php:199` is *scan* exclusions, a
different thing) and nothing in `frontend/js/app.js`.

So after `serverscrub waf exclude add 420047`, rule 420047 is disabled for all
132 sites, and the WAF panel shows `SecRuleEngine: On` with the CRS armed and no
indication whatsoever that a rule has been switched off. The operator who did it
knows; the next operator, or the same one in three months, does not.

Shipping the feature CLI-only is a legitimate choice. Shipping it CLI-only while
the panel continues to claim complete coverage is the `MODE = 'On'` problem
again: a value presented as fact that the product knows to be qualified.

**Reproduce:** `grep -rn WAFExclusions --include=*.php .` returns three files,
none of them in `backend/api/` or `frontend/`.

**Expected:** `WAFInstaller::status()` returns the exclusion count, and the WAF
panel says "3 rules excluded" next to the mode — even as plain text with no
management UI. The count already exists; it just is not surfaced.

---

### 12. On a server where the WAF was never armed, every `waf exclude add` fails with "Invalid mode" — major

**What happens:** this is the first thing an operator will do after upgrading
to get the new feature, and on a server that has never run `waf mode` it looks
like this:

```
$ serverscrub waf exclude add 420047 --reason="..."
id:                    1
scope:                 server-wide
applied:               no
mode:                  unknown
WARNING: the exclusion is recorded but Apache was not updated: Invalid mode
Run `serverscrub waf exclude apply` once that is resolved.
```

**Cause:** `backend/cli/serverscrub.php:457` re-applies the config with

```php
$applied = WAFInstaller::setMode(WAFInstaller::currentMode());
```

`currentMode()` returns the literal `'unknown'` when
`/etc/serverscrub/waf/serverscrub-waf.conf` is absent or has no
`SecRuleEngine` line. `setMode('unknown')` misses the `$map` lookup and returns
`'Invalid mode'`. `waf exclude rm` and `waf exclude apply` share the line and
the fault.

**Why it matters:** "Invalid mode" is meaningless to an operator who never
supplied a mode — the CLI generated the value itself. And the advice is
unactionable: there is nothing to resolve, the WAF simply has not been
configured yet. The row *is* saved, so the exclusion silently takes effect the
first time the mode is set later, which the operator has just been told did not
happen.

**Reproduce:** `docker compose -f docker/compose.yml run --rm test upgrade` —
it is in the output above, on an upgraded 4.35.0 database.

**Expected:** `currentMode() === 'unknown'` detected before the call, and a
message that says the thing: *"the exclusion is saved; the WAF is not
configured on this server yet, so there is nothing to apply. Run `serverscrub
waf install` or `waf mode detectiononly` and it will be included."*

---

### 13. Licence back-off does not hold on Linux — minor

```
- firewall_speed: a failed check sets a back-off window
- firewall_speed: subsequent requests do not re-attempt the licence server (worst 536.2ms)
```

Every request re-attempts the licence server after a failure instead of
honouring the back-off window, adding ~0.5s to each. Reproducible at both PHP
streams in the container; passes on Windows.

---

### 14. The scheduler status path resolves a database inside the source tree — minor

`php tests/test_schedule_status.php` inside the read-only mount produced
`file_put_contents(/opt/serverscrub-src/logs/2026-11-09.log): Read-only file
system` and then `SQLSTATE[HY000]: General error: 14 unable to open database
file`. Some path resolves relative to the tree rather than to `SG_ROOT`. Benign
on a server where the install directory is writable; it means the suite cannot
run against a read-only source checkout, which is how this container is
deliberately mounted.

---

### 15. `VERSION` was not bumped — minor (release process)

`VERSION` is 4.35.1, which is already released (`dist/serverscrub-4.35.1.zip`,
tag exists). HEAD adds a feature — WAF rule exclusions — so by the project's own
scheme this is 4.36.0. `scripts/preflight.py` reports "version consistent:
4.35.1" because it only checks internal agreement, not that the candidate
differs from the last release. Releasing as-is would publish a second,
different 4.35.1.

---

## What passed

Verified by running it, not by reading it.

- **Both ends of the PHP range build.** `PHP_STREAM=7.4` and `PHP_STREAM=8.2`
  both produce an image on AlmaLinux 8.10. The container reports exactly the
  production shape: PHP 7.4.33 / 8.2.35, **sqlite 3.26.0 for both CLI and
  PDO**, Python 3.6.8.
- **4152 assertions pass on Windows** (`php tests/run.php`) and
  `scripts/preflight.py` is green on all 19 checks.
- **4118 of 4136 assertions pass on Linux at PHP 8.2.** Of the 18 failures, 9
  are my new `waf_rollback_honesty` file (finding 1 and 5, deliberately
  failing), 7 are `scan_types` (finding 10, a test defect), 6 are `router` and
  1 `schedule_status` (findings 6 and 14).
- **All shipped Python runs on 3.6.8**, `backend/daemon/monitor.py` included.
  `test_monitor_resources.py`, `test_monitor_backup.py` and
  `test_monitor_newdirs.py` pass on Linux — they had never run there at all.
- **The happy path of `7f397eb` works on Linux, for real.** `serverscrub waf
  mode detectiononly` writes `/etc/serverscrub/waf/serverscrub-waf.conf` with
  `SecRuleEngine DetectionOnly`, drops `IncludeOptional` into
  `/etc/apache2/conf.d/zz-serverscrub-waf.conf`, validates, and reports
  `applied: yes`. A rejected config is not applied, the reload does not run,
  the mode is not recorded, the snapshot precedes the write, and a
  never-existed file restores to absent rather than empty. Finding 1 is about
  the one write in that path whose result is not checked.
- **The upgrade path is sound.** Baseline `dist/serverscrub-4.35.0.zip`
  installed (no `waf_exclusions` table), a canary row planted, then upgraded to
  HEAD:

  ```
  integrity_check  : ok
  foreign_key_check: (empty)
  waf_exclusions   : 1          # created by the migration on an UPGRADED db
  canary survived  : 4.35.0     # no data loss
  db dir perms     : 700 root:nobody
  ```

  and `serverscrub waf exclude list` works against the upgraded database.
- **Scan bounding is exact, and the virtfs trap works.** A full scan of `/home`
  examined **1,339** files in 4s. `/home` holds 1,639 files of which 300 are
  under `/home/virtfs` — 1,639 − 300 = 1,339, so the prune is precise, not
  approximate. `SCAN_SKIP_DIRS` covers `virtfs`, `.snapshot`, `.zfs`,
  `.trash`, `.cagefs`, and the job log names the 8 web roots it chose.
- **Detection, quarantine and the verdict gate work end to end.** Once the
  container could actually invoke clamscan (see `docker/` below), the seeded
  EICAR file at `/home/acct3/public_html/wp-content/uploads/suspicious.php` was
  found, recorded as `malware`, and surfaced in the panel and the events list.
- **Concurrency holds.** A full scan, the scheduler and five concurrent CLI
  loops against one sqlite file: **zero** `SQLITE_BUSY`, no WAL file left
  behind, `PRAGMA integrity_check` = ok, `PRAGMA foreign_key_check` empty,
  `serverscrub db-check` = `ok: yes`. `Database::once()` is correctly built —
  `BEGIN IMMEDIATE`, the marker re-checked inside the lock, marker and work in
  one transaction — and `busy_timeout=10000` with `wal_autocheckpoint=1000` is
  set on every connection.
- **The database directory is 0700** after install, and the panel still serves.
  (The file itself is 0644; it sits inside a 0700 directory, so this is not
  exposure, but 0600 would cost nothing.)
- **WAF event ingestion and client-IP attribution are correct.** Reading the
  seeded audit log produced 5 events, and every one of the README's absence
  tests passes:
  - the **Action column differs per row** — four `Logged`, one `Blocked`. The
    `action = 'block'` regression is gone.
  - `20.46.43.126` → `Blocked`, direct.
  - `20.218.73.251` → from `X-Forwarded-For`, **not** `127.0.0.1`.
  - `52.242.194.83` → the rightmost entry, **not** the forged `8.8.8.8`.
  - `203.0.113.77` → via `cf-connecting-ip`.
  - `420047` on `/shop/checkout` — the triage case — is present.
- **The MODE tile is honest.** It reads `Unknown` where the engine state is
  unknown. The hardcoded `'On'` is gone.
- **"Read log now" gives real feedback.** The banner stated the log path and
  byte count, the click moved TOTAL EVENTS 0 → 5, and the banner cleared.
- **The WP sweep is honest about a sweep that read nothing.** With no MySQL
  client available, all 11 installs failed to read, and the toast was
  **`toast warning`**: *"Read 11 of 11 installs — 0 new finding(s); 50
  install(s) could not be read"*. The `errs ? 'warning' : 'success'` branch in
  `app.js:6560` works. I initially recorded this as a blocker from the API
  response alone and was wrong — the UI handles it. Two small residuals worth a
  look, neither a finding on its own: `scanned: 11` counts attempts rather than
  successes, "50 install(s)" is a per-query error count against 11 installs,
  and once the toast fades the panel shows only "0 open · Last swept <time>"
  with no trace that nothing was read.
- **`WAFExclusions` input validation.** Rule ids digits-only, hostnames
  regex-checked, URI prefixes reject quotes, backslashes and newlines, reasons
  newline-stripped, duplicates refused by a unique index. Nothing I put in
  those fields broke out of the generated directive.
- **The `waf exclude` CLI is honest about its own limits** — it warns that
  `@streq` is exact and apex and `www` are two hosts, and that a narrowed
  exclusion cannot remove a phase-1 rule.
- **`f1844fb`** — `tests/test_legacy_waf_cleanup.php` passes on Linux.
- **A genuine duplicate-id collision is caught.** Planting a custom rule at
  `id:15001`, the same id the exclusion generator produced, reproduced the
  7 Nov error exactly: `ModSecurity: Found another rule with the same id
  (id:15001)`. That is finding 4(a) demonstrated rather than argued.

## `docker/` — what needed changing

Nothing in `docker/` had ever been executed. Every item below was a real
failure, not a tidy-up.

| Fix | Why |
|---|---|
| `compose.yml`: removed `sysctls: { fs.inotify.max_user_watches }` | `fs.inotify.*` is not in a separate kernel namespace. `up panel` failed outright: `runc create failed: sysctl "fs.inotify.max_user_watches" is not in a separate kernel namespace`. The panel could never have started. |
| `compose.yml`: anonymous volumes masking `python/`, `php/` | The repo ships the **Windows** embeddable interpreters, and the mount makes them visible as `-rwxrwxrwx` inside Linux. `tests/run.php`, `tests/test_monitor.php` and `scripts/preflight.py` all pick an interpreter by `is_file()` and try repo-local `python.exe` **first**, so the container ran the Windows binary over `/usr/bin/python3`: `<3>WSL ERROR: UtilBindVsockAnyPort:317: socket failed 1`. Three Python test files "CRASHED" and the 3.6 compatibility check failed with exit 1 and an empty message. **The entire Python daemon surface was silently unexercised.** |
| `compose.yml`: anonymous volume on `logs/` | Parts of the suite write to `<repo>/logs` rather than `SG_ROOT/logs`; against the read-only mount that turned into 20 failures whose assertion text was a PHP warning. Finding 14 keeps the underlying bug visible. |
| `Dockerfile`: `COPY seed-logs.sh` | It was never copied into the image **and never called**. The ModSecurity audit log, the Exim queue stub and the mail fixtures did not exist, so the WAF-parse, audit-ingest and mail-queue-prune tests ran against nothing — and passed, because "no entries" and "nothing to parse" look the same. |
| `Dockerfile`: `php-pecl-zip` + a build-time assertion | `ZipArchive` is not in `php-common` on AlmaLinux 8. `test_packaging.php` died with `Class "ZipArchive" not found`, so the check that the release artefact is well-formed — and that `tests/` is absent from it — never ran. |
| `Dockerfile`: new `apachectl-stub.sh` at `/usr/sbin/apachectl` | With no `apachectl`, `validateApache()` returns `ok => false` and **every** `setMode()` call took the rollback branch — the whole of `7f397eb` was unreachable on Linux. The stub does one real thing: it follows our `IncludeOptional` globs and fails on a duplicate `SecRule` id, which is the actual 7 Nov fault. It does **not** parse Apache's grammar or load ModSecurity, and it says so in a 30-line header. A pass from it is not evidence Apache accepts the config. |
| `entrypoint.sh`: call `seed-logs.sh` from `do_seed` | See above. |
| `entrypoint.sh`: new `lint` command, run first by `test` | Finding 2 surfaced as 70 identical crashes. Now it is one block of three lines. |
| `entrypoint.sh`: dropped `--yes` from the `install.sh` call | `install.sh`'s argument loop ends in `*) ;;` — `--yes` was silently ignored and is not a real flag. `--mode` is what skips the prompt. Added `--admin-user/--admin-pass` so UI runs are repeatable instead of depending on a generated password. |
| `entrypoint.sh`: `do_serve` copies `docker-router.php` into `$DEST` | `install.sh` copies `backend/`, `frontend/` and `VERSION` — not `docker-router.php`. `php -S` with a router it cannot open exits immediately, so the panel never came up. |
| `entrypoint.sh`: stopped swallowing Python failures | `python3 "$t" || echo "FAILED: $t"` meant a Python failure could not change the exit status, so `docker compose run --rm test` returned **0** with failures on screen. `run.php` already runs those files; the duplicate loop is gone. |
| `Dockerfile`: `ipset` | The only runtime dependency `install.sh` was missing, and the layer above ends in `dnf clean all` — so `install.sh` re-downloaded every repository's metadata to fetch one package, and `up panel` sat on `[INFO] Installing: ipset` for over four minutes before the server existed. Consequence stated in "not tested": the dnf-install branch of the dependency bootstrap no longer runs here. |
| `entrypoint.sh`: `do_install` tolerates `install.sh`'s exit code | Finding 9. `set -e` saw the exit 1 from a *successful* standalone install and killed the entrypoint before `exec php -S`, so `up panel` installed and then exited with no server. Now the code is recorded and the install is judged on whether `$DEST/VERSION` exists. |
| `seed-cpanel.sh`: clamscan stub now understands `--file-list=` | `Scanner::scanBatch()` does not pass file paths as arguments; it writes them to a temp file and passes `--file-list=`. The stub only read positional arguments, so it received a list file it ignored, scanned nothing, printed nothing, and **every scan reported "0 threats found"** with the seeded EICAR file sitting in `/home/acct3/public_html` the whole time. A stub that silently agrees nothing is wrong is worse than no stub. |
| `seed-cpanel.sh`: placeholder `main.cld` / `daily.cld` | `runClamScan()` begins `if ($bin === null \|\| !self::clamSignaturesPresent())` and falls back to the pattern engine. With the stub binary present but no signature database, that check was false and the ClamAV branch — with quarantine and the verdict gate behind it — never executed. A full scan went from 31 files to 1,339 once this existed. |
| `apachectl-stub.sh`: dedupe the file list | My own bug, caught by running it: the two include-resolution passes both added `serverscrub-waf.conf`, so every `id:` was counted twice and `uniq -d` called the first one a collision. `waf exclude add` rolled back a perfectly good config as a result. |
| `entrypoint.sh`: new `upgrade` command | There was no way to exercise an upgrade. It installs a baseline from `dist/`, plants a canary row, upgrades to the mounted tree, then checks `PRAGMA integrity_check`, the `waf_exclusions` migration, the canary, the database directory mode, and `waf exclude list` against an upgraded database. |

---

## For Wasooli

Fix, in this order:

1. **Finding 1** — `restoreConfig()` must return a per-path result, `setMode()`
   must derive `rolled_back` from it by comparing the bytes on disk to the
   snapshot, and a failed restore must be reported as an emergency naming the
   path, not as a rollback.
2. **Finding 3** — `addCustomRule()` needs numeric-id validation, a
   reserved-range check, `apachectl -t` before the file is live, rollback on
   failure, and a return value derived from what happened. Or withdraw the
   route.
3. **Finding 2** — a decision from the user: rewrite three `match()`
   expressions, or raise `install.sh`'s floor to 8.0. Also:
   `scripts/preflight.py` must lint at the declared floor, not at whatever
   interpreter is lying around, or it will not catch the next one either.
4. **Findings 5, 6, 8, 9, 11, 12** — the false claims, and finding 7 alongside them. Each one tells the operator
   something the product does not know.
5. **Finding 4** — the id-collision check, and the port/case caveats.
6. **Findings 10–15** at your discretion; 10 is mine to fix in `tests/` if you
   would rather I did.

Re-test command set:

```bash
PHP_STREAM=7.4 docker compose -f docker/compose.yml build
PHP_STREAM=8.2 docker compose -f docker/compose.yml build
PHP_STREAM=7.4 docker compose -f docker/compose.yml run --rm test lint
PHP_STREAM=8.2 docker compose -f docker/compose.yml run --rm test
PHP_STREAM=8.2 docker compose -f docker/compose.yml run --rm test upgrade
php tests/run.php waf_rollback_honesty
```

---

## Wasooli — what was changed, 2026-11-09

**Status: fixed-pending-retest.** Back to Shakaal. Nothing below is a test
result from a real Apache or a real server; see "what I could not demonstrate".

Local: `python scripts/preflight.py` green on all 19 checks, **4275 assertions
pass** on Windows (PHP 8.5). Container, this tree:

| run | result |
|---|---|
| `PHP_STREAM=7.4 ... test lint` | **all files parse** (was 3 failures) |
| `PHP_STREAM=7.4` full suite | 13 of 4035 failed — the suite RAN at 7.4 for the first time |
| `PHP_STREAM=8.2` full suite | 10 of 4249 failed |

The 8.2 failures are findings 6 (6 x `router`), 13 (2 x `firewall_speed`), 14
(`schedule_status`), plus `bruteforce: only the appended line is read`, which I
proved pre-existing by running that one file at 8.2 against a worktree of
`7f397eb` — it fails there too. It is **not** in your report; worth a look, it
is a Linux-only read-offset failure.

7.4 adds three crashes that are newly *reachable* rather than new: two are
`ReflectionMethod`/`ReflectionProperty` needing `setAccessible(true)` before
PHP 8.1 (`test_bruteforce_ladder.php:44`, `test_firewall_rules_paging.php:133`
— test code, not product), and `test_packaging.php` still cannot find
`ZipArchive` in the 7.4 image.

### Finding 1 — a rollback that could not tell, and claimed anyway

`restoreConfig()` is public, returns `['ok' => bool, 'failed' => [path, reason]]`
and verifies every path three ways: the byte count against `strlen()` (a full
filesystem returns a **short count**, not `false`), a read-back comparison, and
`file_exists()` after the unlink for a file that did not exist before.
`rolled_back` is read off that result; `'rolled_back' => true` as a literal
appears nowhere in the product, and a test asserts that.

Added beyond the report: when the restore fails, `neutraliseConfig()` removes
the Apache include first and then the config, so a config Apache has already
refused is not left for the next restart. A server with no WAF starts; a server
with a config Apache refuses does not. If that fails too, the message names the
file and says to move it aside by hand, now. The old "Apache may already have
been unable to restart before this change" is printed only when the restore is
confirmed — the one case where it can be true.

`tests/test_waf_rollback_honesty.php` (yours) passes 15/15.
New: `tests/test_waf_restore_verified.php`, 33 assertions.

### Findings 5 and 2 — "could not check" is no longer "checked and rejected"

`validateApache()` returns `ran` as well as `ok`. Candidates are tried in full;
exit 127 or a shell "not found" on the output skips a candidate instead of
counting as a verdict, so `apache2ctl` is reachable. With no checker at all,
`setMode()` **refuses and writes nothing** — the reasoning is in the docblock:
writing an unvalidated ModSecurity config to a host that cannot be asked about
it is the 7 Nov shape, and a host with no apachectl has no Apache for the
config to configure. The pre-check is skipped when a runner is injected (a stub
runner supplies Apache's answers; the filesystem has nothing to say about that
host), and the post-write `ran === false` branch is the real safety net — which
is what the suite exercises.

### Finding 3 and 4(a) — addCustomRule, and the id bands

Numeric id, band-checked, collision-checked against
`WAFExclusions::generatedIds()` and against the configs we have already
written; the pattern is rejected rather than escaped if it holds a quote,
backslash or newline, and rejected if it is not a valid regex; `block` and
`log` both mean what they say (`$action` was accepted and ignored — everything
was `deny`); snapshot, `apachectl -t` **before** any reload, verified rollback
on failure, and `live` in the result from `reloadApache()`, which now returns a
bool.

Bands, enforced at both ends and documented in one place:

```
      < 15000   hand-written operator rules. We never generate here.
15000 - 19999   generated exclusions (WAFExclusions::ID_BASE / ID_CEIL)
20000 - 29999   custom rules (WAFExclusions::CUSTOM_ID_MIN / CUSTOM_ID_MAX)
     900000+    OWASP CRS
```

`ID_CEIL` moved from 99999 to 19999, so an installation would need 5,000
exclusions to exhaust it; past that `render()` throws, as before.
New: `tests/test_waf_custom_rule.php`, 37 assertions, including your `id:15001`
collision.

Not done: finding 4(b), the `@streq` port and `@beginsWith` case caveats. Out
of the brief, and I did not want to change matching behaviour in the same
change as the id work. It is a real "the exclusion appears not to work".

### Finding 2 — PHP 7.4

Not 3 `match()` expressions: **30**. `backend/api/index.php` has 27 — the whole
route table — because `php -l` stops at the first error, so the report saw only
line 184. All 30 are `switch` now, converted with a tokeniser script rather
than by hand, then reviewed. Every subject is a string, and every arm, its
order and its expression are unchanged; the only semantic difference is
`switch`'s loose comparison, which cannot bite on string-to-string.

Also **48 calls** to `str_contains`/`str_starts_with`/`str_ends_with` across 9
product files and 3 test files. Those parse at 7.4 and fatal at run time with
*Call to undefined function*, so no parse gate could ever catch them; they are
`strpos()`/`substr()` forms now. I did not add a polyfill: `config.php` is
Gabbar's file, and a polyfill one entry point forgets to load fatals in exactly
the place nobody looks, which is cron.

The floor stays at 7.4. Closing the gate — linting at the declared floor rather
than at whatever interpreter is on the developer's machine — is yours, in the
container.

### Finding 7 — the fabricated CRS category panel

`getRuleCategories()` reads `rules/*.conf` under `WAFInstaller::crsPath()`: ids
counted per file with comment lines stripped first, names derived from the CRS
file names, the files each number came from returned alongside it, the CRS
version read from the **same** tree, and `excluded` per category from the
exclusions the operator has recorded. Bounded: one directory level, 400 files,
4 MB per file, nothing recursive.

With no readable tree it returns `available => false` with a reason, and the
panel prints the reason. `loaded` means "our config includes this file" and is
labelled *Included* in the UI — not *Active*, which is a claim only a running
Apache could support. `Java Attack` and the invented counts are gone from the
source, asserted.
New: `tests/test_waf_categories_real.php`, 21 assertions.

### Not in your report — the corrupt CRS tree

`installCrs()` extracted with `tar -xzf` into the live directory and assumed.
tar merges, which is how one tree came to define 913100 twice and the WAF had
not loaded since 6 Oct. Now: a fresh staging directory per attempt, a
duplicate-id scan of the staged tree before it goes anywhere near Apache, an
atomic swap with the previous tree kept aside until the new one is known good,
`apachectl -t` when our config already points at the tree, and the previous
tree put back if any of it fails. `install()` also scans a tree that is
*already present* instead of printing "already present" in green.
New: `tests/test_waf_crs_tree.php`, 17 assertions. `duplicateRuleIds()` is
public so the CLI can use it later.

### Smaller, in the same paths

- `install.sh` now writes `IncludeOptional` for `custom_rules.conf` (the tail
  of your finding 9). **Existing servers keep the plain `Include`** — the
  installer skips the block when the path is already mentioned. The command to
  fix a live server went to the user, not to the server.
- `WAFInstaller::status()` gains `include_present`, `include_path` and
  `validator`. Finding 11's exclusion count is NOT surfaced — not in the brief.
- `crsVersion()` returned `.4.7.0`: the pattern captured the separator out of
  `ver.4.7.0`. Found by writing the category test.

### Tests I changed, and why — read this part

> **CORRECTION, 2026-11-09, after Shakaal's retest.** I wrote "no assertion
> changed meaning" below. That was not accurate, and Shakaal proved it rather
> than argued it. Two of the fourteen — the pair in
> `tests/test_waf_config_rollback.php` — went from an exact single-line match
> to an unordered membership test, so both fragments can now appear in
> *different branches* of `setMode()` and still satisfy it, including the case
> where the write-failure path does not roll back at all. Under his mutation M5
> (`restoreConfig()` always reports success) that file reported **zero**
> failures while `test_waf_restore_verified.php` reported seven and
> `test_waf_rollback_honesty.php` three. The protection was relocated, not
> preserved. Net coverage is better, which is why the change stands, but the
> claim was wrong and the twelve others are the only ones it applies to.
>
> What I have done about it: `test_waf_restore_verified.php` now kills all four
> of his mutations individually (M2 2 failures, M3 3, M4 1, M5 17 — measured by
> removing each check in turn), so the behavioural pin no longer depends on a
> source-text assertion at all. See N2 in the retest report.

Twelve of the fourteen located a route by its `match()`-arm text, which no
longer exists; each now looks for the equivalent `case` label:

`test_dashboard_overview.php` (`'overview'   => routeOverview` ->
`case 'overview':   $response = routeOverview`), `test_mailguard.php` (window
locator `'deliver' => $method === 'POST'` -> `case 'deliver':`),
`test_reseller_privilege.php` (`'login' =>`), `test_scan_concurrency.php`
(x2: `'reap' =>`, `'stop-all' =>`), `test_scan_log.php` (`'jobs' => (function
() use ($q) {` -> the two-line `case 'jobs':` form), `test_scan_stop.php`
(`'stop' => $method === 'POST'` -> the two-line `case 'stop':` form),
`test_scan_threat_detail.php` (`'threats' => (function`),
`test_scan_types.php` (`'accounts' =>`), `test_ui_honesty.php` (the
router-module regex — also single-quoted now, because `"\$response"` in a
double-quoted PHP string reached PCRE as an end-of-line anchor and matched
nothing, so that assertion would have passed vacuously).

Two in `test_waf_config_rollback.php` pinned the exact lines this blocker is
about: `@file_put_contents($p, $contents);` and
`if ($contents === null) { @unlink($p); continue; }` — the unchecked write and
the unchecked unlink. They are now `t_fn_body()` assertions that the write
result **is** checked and the removal **is** verified. Strictly stronger, but
those are the two edits to argue with me about.

Three test files had their own `str_contains`/`str_starts_with` calls replaced
(`assert.php`, `test_mailguard.php`, `test_wpdb_scanner.php`) so the suite can
run at 7.4 at all. No assertion text changed.

### What I could not demonstrate

- **No ModSecurity and no real Apache.** Every `validateApache()` result in my
  runs comes from an injected runner or your `apachectl-stub.sh`. Nothing I
  wrote has been parsed by ModSecurity, including the custom-rule directive and
  the band layout.
- **The short-write case is asserted on the source, not reproduced.** ENOSPC
  cannot be produced in a sandbox. The byte-count comparison and the read-back
  are structural assertions; the unwritable and path-is-a-directory cases are
  behavioural.
- **`installCrs()` has never been executed.** It downloads a 4.7.0 tarball and
  there is no network in the container. The duplicate-id scanner is tested
  against fixtures I wrote; the staging/swap/rollback sequence is asserted on
  the source only. **I have not run the scan against the real CRS 4.7.0 tree,
  so I cannot say it does not false-positive on a clean one** — and a false
  positive there refuses the install. That is the thing I most want checked.
- **The pre-write "no syntax checker" refusal** is asserted structurally only;
  the behavioural coverage goes through the post-write branch.
- **The category panel has not been rendered in a browser.** The API shape
  changed from a bare array to `{available, reason, crs_path, crs_version,
  loaded, categories[]}`. `app.js` handles both shapes, but I have not loaded
  the page.
- `backend/api/index.php` shows a ~2,900-line diff. It is not line endings (LF
  before and after, no CR in the file): it is the 27 `match` -> `switch`
  conversions, and roughly 900 of those lines differ only by the four-space
  re-indentation of continuation lines, which `git diff --ignore-all-space`
  hides.
