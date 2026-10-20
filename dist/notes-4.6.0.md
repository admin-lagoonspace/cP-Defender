# ServerScrub 4.6.0

[4.6.0] - 2026-10-20

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

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
