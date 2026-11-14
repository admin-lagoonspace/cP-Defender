# Quick-scan blindspot, and the mass-detection bound that would have made it worse

**Asked for:** "a note" to Wasooli covering the two defects exposed by the
2026-11-13 review of the host.lws-s1.com ransomware incident.
**Status:** ready-for-wasooli
**Size:** Item 1 — Z. Item 2 — Z. (Both are fixes to shipped or about-to-ship
behaviour. Neither adds a feature; see "Sizing" at the end.)

> **RELEASE BLOCKER:** item 2 blocks commit 2e160dc from shipping as written.
> Releasing today with the bound unchanged ships a regression that leaves
> ransomware in place. Read item 2 before cutting the next release.

## The incident, in short

Between 13:11 and 13:31 on 2026-04-30 something with **root** privilege wrote a
qTox ransom note named `README.md` into effectively every directory of every
account, and renamed database-shaped files (`.sql`, `.db`, `.sqlite`, `.bak`)
to `*.sorry`. It never touched `/var/lib/mysql`, never touched site content and
never touched PHP, so all 118 sites kept serving and **nobody noticed for six
and a half months**. 58,597 notes were still live on disk when it was found;
~160,000 had been quarantined; 1,864 `.sorry` stubs. CPGuard was installed and
running throughout — `/home/pnpwebdesign/.cpguard/bforce.db.sorry` is the proof
— and reported none of it. Everything is now cleaned: 0 notes, 0 stubs, no data
lost.

Separately, hidden PHP droppers named `.<41 hex>` under
`/home/officialwebspace/`, `/home/officialwebspace/.cache/` and
`/home/themmw/`, mtime 2026-08-28 11:31, re-executed every minute from user
crontabs. Contained 2026-11-11.

---

# Item 1 — a quick scan structurally cannot see where this malware lived

**Size: Z.**

## What the user is actually trying to achieve

The nightly sweep is the operator's primary detection path — their words:
without it "we have a blindspot for finding infections." They need the nightly
scan to look where infections on this server have actually been found, not
where infections are conventionally expected. Both real infections on this host
lived entirely outside the web root, and a six-month dwell time is the measured
cost.

## What exists today

- `backend/cron/scheduler.php:183` — the scheduled task reads `scan_type`
  (`setting('scan_type', 'full')`) and `scan_paths`, and starts one job.
- `backend/lib/Scanner.php:545` — `resolveScanPaths('quick')` returns, for every
  account, **only** `$a['docroot']`.
- `backend/lib/Scanner.php:483` — `listAccounts()` sets
  `$docroot = $home . '/public_html'`.
- Confirmed in production: job 12460's `scan_path` holds 118 entries, every one
  of them a `public_html`.

Every artifact of both infections was outside `public_html`:

- notes in `$HOME`, `.cpanel/caches/config/`, `tmp/webalizer/`, `.cphorde/`,
  `.subaccounts/`, `ssl/`
- droppers in `$HOME` and `.cache/`
- the one that settles it: `/home/pnpwebdesign/.cpanel/caches/config/README.md`,
  inside a `drwx------` directory

So the nightly sweep could not have found either infection at any point in six
months. It took a full scan to find them.

**A second finding, found while reading the walkers — this one also hides the
droppers from a FULL scan.** `Scanner::SCAN_SKIP_DIRS`
(`backend/lib/Scanner.php:939`) prunes `'cache', '.cache'` by name at every
depth, and both walkers (`walkFiles()` and `getPhpFiles()`, the latter building
its prune regex from the same constant at line ~1402) honour it. The
officialwebspace droppers lived in `/home/officialwebspace/.cache/`. They were
pruned from every scan of any type. Wasooli must resolve this: `.cache` cannot
stay an unconditional prune. (`.cpanel/caches/` was not pruned — `caches` does
not equal `cache` — so the notes there were reachable by a full scan.)

## Requirements

1. A quick scan covers each account's `$HOME` itself — files directly in the
   home directory — in addition to `public_html`.
2. A quick scan covers the account's home dotdirectories, including at minimum
   the locations where artifacts were actually found: `.cpanel/`, `.cphorde/`,
   `.subaccounts/`, `.cache/`, `ssl/`, `tmp/`.
3. Coverage does not depend on directory mode. A `drwx------` directory is
   scanned (the scan runs as root); a directory that cannot be read is reported
   as unreadable, never silently skipped.
4. The exclude list for a quick scan is explicit, documented in code, and
   chosen for cost — mail spool, backups, `node_modules`/`vendor`, bind-mount
   trees — not for "malware would not be there."
5. `.cache` (and `cache`) is no longer an unconditional prune for either walker
   at any scan type; whatever replacement bound Wasooli chooses, a hidden
   hex-named file under an account's `.cache/` is reachable.
6. `serverscrub scan --type=quick` has a way to print the resolved path set and
   the exclude list without running the scan, so an operator can see what the
   nightly sweep will and will not look at.
7. The operator-facing description of "quick" in the WHM UI and CLI help
   matches what it now covers.

## Explicitly out of scope

- Changing the default `scan_type` for the schedule, or re-enabling
  `scan_schedule` (set to `off` on prod 2026-11-10 pending the user-scan lock
  fix). That is the operator's switch to throw.
- Scanning outside `/home` — no `/tmp`, `/var/tmp`, `/usr/local`, crontab
  spools, or `/etc`. The droppers were re-executed from user crontabs, and
  crontab scanning is a separate requirement that is not being asked for here.
- Any change to detection content: signatures, heuristics, ransom-note or
  `.sorry` recognition.
- Reworking `scan_max_concurrent` (see Context below).

## Failure behaviour

- An account with no `public_html`: still scanned — `$HOME` and dotdirs are the
  coverage, and 14 of 132 accounts have no site.
- An unreadable or vanished directory (account removed mid-scan): logged with
  the path, counted, scan continues, and the count appears in the job summary.
  A scan that skipped directories must not report clean coverage.
- No `/var/cpanel/users`: `listAccounts()` already falls back to home
  directories one level under the scan roots; quick scan must behave the same
  way there, and its path note must say which source it used.
- If the resolved quick path set is empty, the scan does **not** silently fall
  back to walking everything under the word "quick" — the existing note
  mechanism (`'no web roots found, scanning in full'`) is the pattern; keep it
  honest and visible.

## Resource bounds

Give numbers; do not ship "bounded."

1. Per-account file-count cap for a quick scan, with the cap and the hit
   recorded per account in the job row.
2. Per-account wall-clock cap, and a whole-sweep wall-clock cap. The prior full
   `/home` sweep ran 59 hours and another ran 15; a nightly quick sweep that
   cannot finish overnight is not a nightly sweep.
3. Maximum depth below each dotdir, so `.cpanel/caches/` is reached without
   walking an arbitrarily deep tree.
4. `virtfs`, `.snapshot`, `.zfs`, `.trash`, `.cagefs`, `.serverscrub` and
   `.sentinel-gate` stay pruned — unpruned `/home/virtfs` is multiplicative
   (118x on this host) and has already produced a scan that never completed and
   load above 35.
5. A stated target for the whole 132-account sweep, measured on prod, in the
   acceptance evidence. Not a guess in a comment.

## Acceptance criteria

1. On a fixture server with an account whose only artifact is
   `$HOME/.cpanel/caches/config/README.md` in a `0700` directory, a quick scan
   finds it. The same scan before the change does not.
2. Fixtures reproducing each real location — `$HOME`, `.cphorde/`,
   `.subaccounts/`, `ssl/`, `tmp/webalizer/`, `.cache/.<41 hex>.php` — are each
   found by a quick scan.
3. A `.<41 hex>` dropper under `$HOME/.cache/` is found by both a quick and a
   full scan (proves requirement 5).
4. `resolveScanPaths('quick')` on a 132-account fixture returns the documented
   path set, and the test asserts it on a machine shaped like a cPanel server
   via `Scanner::setCpanelUsersDir()` — not only on a laptop with no
   `/var/cpanel`.
5. An account with no `public_html` is still represented in the path set.
6. An unreadable directory produces a logged, counted skip and a non-clean
   coverage report; no exception escapes the worker.
7. `virtfs` prune is asserted still in force for quick scans.
8. Each resource bound in the section above is demonstrated firing in a test.
9. Timed sweep on prod (or a copy) completes inside the stated whole-sweep cap.

---

# Item 2 — the mass-detection bound, as written, would have left the ransomware in place

**Size: Z.** Blocks release of 2e160dc.

## What the user is actually trying to achieve

They want to stop a bad third-party signature quarantining 154,323 customer
files unattended — the 10 Nov event — **without** building a mechanism that
stops a scan from finding a real mass event. Ransomware and mass defacement are
mass-identical-file events by their nature. The bound as written cannot tell
them apart, and this incident is the counter-example.

## What exists today

- `backend/lib/MassDetection.php` — commit 2e160dc, unreleased, in
  `CHANGELOG.md [Unreleased]`.
  - `DEFAULT_MAX = 500`, per job per signature (line 72).
  - `allow()` (line 103) returns `act: false` past the bound; the caller
    (`backend/lib/Scanner.php:1678`) records `action_taken = 'flagged: mass
    detection bound (...)'`.
  - `trip()` (line 154) writes a critical event and then calls `halt()`.
  - `halt()` (line 215) sets `scan_jobs.status = 'halted'`; the comment notes
    `Scanner::isCancelled()` treats anything not `running`/`pending` as a stop,
    so **the worker leaves at the next batch boundary.** The scan ends.
- The file's own header states the reasoning: "a single signature accounting
  for an implausible number of a run's findings is evidence about the
  signature, not about the customer's files," and "WHY THE WHOLE SCAN HALTS."
- Per-signature operator suppression already exists (04aefc1): `serverscrub
  signatures suppress add|list|rm`, plus the WHM card.
- Scoped, dry-run-by-default `serverscrub quarantine restore` already exists.

## The defect

The assumption in the header — that ~150,000 matches from one signature must be
a false positive — is wrong. The 154,323-file detection in this incident was
**100% correct**: genuine ransom notes, verified by reading file contents and
matching the attacker's qTox TOX ID.

With `DEFAULT_MAX = 500` in place at the time, the scan would have halted at
the 500th note, left roughly 153,800 real ransomware files in place, and shown
the operator a message reading "which is evidence about the signature rather
than about these files. An operator has to decide" — i.e. it would have
presented a correct mass detection as a probable false positive, and stopped
looking.

A bound that stops detection fails safe in the wrong direction: it fails toward
leaving malware in place.

Points for Wasooli, without prescribing the design:

- **Halting the scan is the harmful part.** Flagging instead of quarantining is
  not harmful; it is the right conservative default for destructive action.
  These are separable and currently are not separated.
- **File-content identicality is available and cheap to sample.** 154,000
  byte-identical files is evidence **for** a real mass event, not against it. A
  bad signature matching README/CHANGELOG across `node_modules` and `vendor`
  matches files that are all *different*; ransom notes are all the *same*. The
  10 Nov false positive and the 30 Apr true positive are distinguishable on a
  sampled hash, and the existing `trip()` already does bounded sampling
  (`LIMIT 2000`) for extensions, so the shape is there.
- **The real false-positive case is already covered**, operator-driven and
  after review, by per-signature suppression (04aefc1) and scoped restore. The
  bound does not need to carry that load alone.
- Per-account spread was already reasoned about and correctly rejected as a
  trigger (file header, lines 38-41) — a reseller mass defacement looks the
  same. That reasoning stands; what does not stand is halting.

## Requirements

1. A mass detection never halts the scan. The scan completes its walk and
   records every finding.
2. Past the bound, destructive action (quarantine, disable, delete) stops for
   that signature; findings continue to be recorded and shown to the operator.
   This part of the current behaviour is correct and must survive.
3. The product distinguishes "implausibly many" from "legitimately many" using
   evidence it can actually gather, including sampled content identicality
   across matched files. The verdict is stated with its basis.
4. Where it cannot tell, it says it does not know. It must not label a mass
   detection a probable false positive, and must not label one a confirmed true
   positive, on count alone.
5. The operator-facing message distinguishes the two cases in words an operator
   can act on, and names the next step for each: suppression for a bad
   signature, a decision about scope for a real mass event.
6. The operator alarm for a mass detection remains critical-severity and
   immediate — the 10 Nov failure was 59 hours of silence, and that must not
   return.
7. `scan_mass_signature_max = 0` still disables the bound entirely, and the
   setting remains operator-visible.
8. The reasoning in the `MassDetection.php` header is corrected. Leaving the
   wrong assumption in place as documentation is itself a defect; a future
   reader would restore the halt.

## Explicitly out of scope

- Automatic bulk remediation of a confirmed mass event. Still flag and report;
  the operator decides. Mass deletion of customer files is not being asked for.
- Changing the default value of `scan_mass_signature_max` as the primary fix.
  Raising 500 to 200,000 does not fix the direction of the failure.
- Any change to `signatures suppress` or `quarantine restore`, both of which
  work and are the operator's existing tools.
- Ransom-note- or `.sorry`-specific detection rules. That is a separate
  requirement and is not in this note.

## Failure behaviour

- Content sampling cannot read a matched file (vanished, permission, now
  quarantined): that sample is inconclusive, and an inconclusive sample must
  not be scored as evidence either way. Report how many samples succeeded.
- The sampling query or hashing fails outright: fall back to requirement 4 —
  "we do not know" — stop destructive action for that signature, alarm, and
  **still do not halt the scan**.
- `threats` is counted rather than `scan_jobs.threats_found`, as now; that
  column was wrong (32,003 vs 154,323) and must not become the basis.
- Two signatures trip in one job: each is handled independently; neither stops
  the other and neither stops the scan.
- A halted-by-bound job from a pre-fix run exists in the database: the CLI and
  UI still render it, with its historical status intact.

## Resource bounds

1. Content sampling: cap the number of files hashed per tripped signature
   (order of tens, not thousands) and cap bytes read per file. State both.
2. Hash only a leading byte range sufficient to establish identicality; do not
   read whole files. A ransom note is small, and a 2 GB match must not be read.
3. The existing `LIMIT 2000` metadata sample stays as the ceiling for the
   extension/account evidence.
4. One indexed `COUNT` per detection, and per-process memoisation of tripped
   signatures, as now (lines 78-85). Do not regress to one query per file.
5. Sampling runs at most once per signature per job.

## Acceptance criteria

1. Fixture: 1,000 byte-identical ransom-note files matched by one signature.
   The scan **completes**; `scan_jobs.status` is not `halted`; all 1,000 are
   recorded as findings; destructive action stopped at the bound; the operator
   message does not describe them as a likely false positive.
2. Fixture: 1,000 *non*-identical files (README/CHANGELOG-shaped, varied
   content) matched by one signature. The scan completes, all are recorded,
   destructive action stopped, and the message points at signature suppression.
3. In both, nothing beyond the bound is quarantined — assert the quarantine
   directory count.
4. A critical `mass_detection` event is logged within the same scan in both
   cases.
5. Content sampling fails (unreadable files): outcome is an explicit "cannot
   determine", destructive action still stops, scan still completes, no
   exception escapes.
6. `scan_mass_signature_max = 0`: no bound, no sampling, no alarm.
7. Two signatures trip in one job: both reported, scan completes.
8. Replay of the 30 Apr shape — 154,323 matches of one signature on identical
   content — completes the walk and records all findings. **This is the
   acceptance test that proves the regression is gone.**
9. Replay of the 10 Nov shape — 154,323 matches of one signature on
   non-identical content — quarantines no more than the bound.
10. A test asserts the scan is not halted, by name, so a future change that
    reintroduces `halt()` fails.

---

## Context to record for whoever reads this later

A quick scan's `public_html`-only path interacts badly with
`scan_max_concurrent = 1` (`backend/lib/Database.php:387`, read at
`backend/lib/Scanner.php:292`) during an incident. While the nightly sweep holds
the only slot, a manual `serverscrub scan` is refused
(`backend/lib/Scanner.php:694` suggests raising the setting), and
`scan-stop-all` to make room kills the server-wide sweep. So during the exact
event this product exists for, the operator's options are "wait" or "destroy
your coverage." Not in scope here; worth a spec of its own.

Also: CPGuard was installed and running through the whole 2026-04-30 event and
reported none of it. Being the second security product on the box is not
coverage, and should not be treated as a reason to narrow ours.

## Sizing

Both items are **Z**.

- Item 1 changes the path set and prune list of a scan type that shipped in
  4.2.1. No new feature, no new architecture — `resolveScanPaths()` already
  exists and already has a `quick` branch. It is a fix to a shipped feature
  that was looking in the wrong place.
- Item 2 reworks code that has not shipped yet (2e160dc, in `[Unreleased]`). A
  correction to unreleased work does not add a feature; it changes what the
  pending patch does before anyone sees it.

If either lands with a commit subject that reads like a feature,
`scripts/check-version-bump.sh` and Gabbar will disagree with the bump — the
history that motivated the convention (3.14.0, 3.16.0, 3.17.0 all bumping minor
for fixes, one of them with a `fix:` subject) is exactly this. Write the
commits as fixes.

## Open questions

None of these block item 2. Item 1 question 1 does not block implementation but
does change what the operator gets on the first night.

1. **Should mail be in a quick scan?** `mail/` and `etc/` under `$HOME` were not
   named as artifact locations and mail spools are large. Assumed **excluded**
   from a quick scan. Flagged because it is an assumption, not a finding.
2. **Was the 2026-04-30 root-privilege entry vector ever established?** If it
   was not, no change to scan coverage is a containment measure — a root-level
   attacker can write anywhere a scan does not look, and can also remove the
   scan. Recorded so it is not mistaken for closed by this spec.
3. **Were the user crontabs that re-executed the droppers cleaned, and is
   anything watching crontabs now?** Containment on 2026-11-11 is recorded;
   crontab monitoring is explicitly out of scope above, which leaves the
   re-execution path unmonitored unless it already is.
