# Test run — 2026-11-26/27

**Build:** branch `fix/protected-only-from-finished-scan`, tested at `ee4c865`.
The commit adding this file is docs-only on top of `ee4c865`; no code changed after testing.
**Environment:** AlmaLinux 8 (docker/compose.yml), PHP 7.4.33 and 8.2.35
**Verdict:** PASS WITH CAVEATS (on `ee4c865`)

## Not tested
- Browser panel on :8777. This run did not drive the UI.
- cPanel mode (cpsrvd, WHM AppConfig, LiveAPI, CGI wrappers); the container is standalone.
- Real scans: ClamAV and Exim are stubbed. Job rows were seeded directly.
- Scale: the probe used 130 synthetic accounts (132 counting the extra ones), not the live 132-account server.

## Findings
### 1. Boundary test for exactly 8 days was clock-flaky — blocker (first pass), FIXED
**What happened:** at `44a2bcf`, `test_top_status_pill.php` seeded rows relative to its own
`$now`, while `getStats()` read `time()` a second later. On 7.4 it got 691201 vs 691200
and 864001 vs 864000. Run alone, it failed 2 of 5 runs. The first-pass verdict was FAIL.
On 8.2 a second clock flake appeared, in `test_user_scan_window.php` (39599 vs 39600). That test predates this branch.
**Fix (`ee4c865`):** `getStats(?int $now = null)`. The test passes the clock it seeds with.
`test_user_scan_window.php` passes `$now` to the existing `retryIn($user, $now)`.
`test_user_scan_lock_leak.php` reads `time()` once. The expected values (3600, 39600, 691200) are unchanged, so nothing was loosened.
**Verified:** every API and CLI caller of `Scanner::getStats()` passes no argument, so no request can set the clock.

### 2. A full scan from the CLI (`@cli`) never counted as server-wide — minor, FIXED
This made the card falsely amber after an admin scanned everything. `ee4c865` adds `@cli` under the same path rule.

### 3. A new account turns a quick sweep amber until the next nightly scan — accepted behaviour
This fails safe (amber, never a false green), so it is acceptable.

## Scope probe (real `listAccounts()`, 130 cPanel accounts, both PHP versions)
Not green:
- customer scan of its own home
- customer scan with path `/`
- customer-tagged job listing every home
- admin (`@operator`) scan of one account
- `@cli` scan of one account
- prefix path `/home/u00` (does not cover `/home/u001`)
- legacy `''` row of one home
- `/home` scan when an account lives in `/home2`

Green:
- scheduled `/home` scan
- scheduled quick scan of every home
- `/home,/home2` scan
- `@cli` scan of `/home`
- `@cli` scan of every home

No false green found.

**Cost:** about 4 ms per `getStats()` in the worst case, where 25 non-server-wide jobs force the account listing. No caching needed.

## What passed
- Full suite at `ee4c865`: 5726/5726 on PHP 7.4 and 5726/5726 on PHP 8.2, exit 0.
- The three clock-pinned tests ran 6 times each on 7.4 and 8.2 with 0 failures.
- All five `CHANGED` assertions now assert behaviour, not source text. None was weakened.
- The extra amber "No complete server scan" state and "Scan in progress" text are honest.
- "Not yet scanned" during a first scan matches spec case 6.
