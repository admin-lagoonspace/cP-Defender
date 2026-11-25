# Remove the stale Sentinel Gate `Include` lines from csf.allow / csf.ignore

**Asked for:** "On servers migrated from Sentinel Gate to ServerScrub,
`/etc/csf/csf.allow` and `/etc/csf/csf.ignore` still contain
`Include /etc/sentinel-gate/csf_allow.txt` and
`Include /etc/sentinel-gate/csf_ignore.txt`. The legacy cleanup block in
`install.sh` ... deletes that directory but never removes those Include lines.
So every `csf -r` / `csf -ra` prints `*Error* File does not exist:
[/etc/sentinel-gate/csf_allow.txt] at /usr/sbin/csf line 2448.`"

**Status:** ready-for-shakaal
**Size:** Z — a fix to shipped migration/cleanup behaviour. No new feature, no
new page, no architectural change. Ships in Gabbar's Friday batch, not on its
own. Wasooli adds an entry under `## [Unreleased]` → `### Fixed` in
`CHANGELOG.md` and does not touch `VERSION`.

## What the user is actually trying to achieve

A migrated server's firewall must reload cleanly. Today every CSF reload on
such a server prints an `*Error*` for a file ServerScrub itself deleted. That
is noise the operator has to learn to ignore, and an operator trained to ignore
CSF errors will ignore a real one. It is also a ServerScrub-caused defect in a
config file the product does not own, so the fix must be surgical: remove the
two lines we left behind and nothing else.

Observed on prod 2026-11-23: `csf.allow` line 72 and `csf.ignore` line 30 hold
the stale includes; `/etc/sentinel-gate/` no longer exists.

## What exists today

- **Legacy WAF cleanup** — `install.sh:219-280`. Runs outside the migration
  block and outside every `REGISTER_ONLY` guard, so it runs on upgrades. But it
  is entirely inside `if [[ -d "${LEGACY_WAF_DIR}" ]]` (`install.sh:234`). It
  scrubs Apache includes that point at `/etc/sentinel-gate`, then
  `rm -rf /etc/sentinel-gate` (`:261`). It never looks at `/etc/csf/`. Once it
  has run, the directory is gone and the block never runs again. So adding the
  CSF cleanup *inside* this block would do nothing on prod.
- **Sentinel Gate migration block**: `install.sh:113-217`, gated on
  `/usr/local/sentinel-gate` existing. It has no CSF handling. `grep csf` finds
  nothing before line 290 apart from the `--no-csf` flag parse at `:50`.
- **Current CSF integration**: `install.sh:1266-1313`. It sits after the
  install-only section closes (`fi` at `:1221`), so it runs on both fresh
  installs and `--register-only`. When `/usr/sbin/csf` exists it appends
  `Include /etc/serverscrub/csf_allow.txt` / `csf_ignore.txt` if those lines
  are absent (`:1283-1290`). Then it **unconditionally** runs `csf -r`, falling
  back to restarting lfd (`:1300-1305`), on every install and every upgrade.
- **Upgrade path**: `update.sh:1319-1320` runs
  `bash "${INSTALL_DIR}/install.sh" --register-only` *after* copying the new
  `install.sh` into place (`UPDATE_FILES`, `update.sh:1166`). So a step in
  install.sh's register-only path runs on the release that ships it. That is
  the documented "update steps run one release late" workaround.
- **uninstall.sh**: `uninstall.sh:334-351`. It deletes lines containing
  `serverscrub/csf_allow.txt` / `serverscrub/csf_ignore.txt` and the two
  pignore exemptions, then reloads CSF unconditionally. It does **not** touch
  `/etc/sentinel-gate/` includes.
- **Existing test pattern**: `tests/test_legacy_waf_cleanup.php` makes
  source-text assertions on `install.sh` via `t_shell()`.
- **Docker harness**: `docker/` has an `apachectl` stub
  (`docker/Dockerfile:84`) but no CSF. Nothing in `docker/` mentions `csf`.

## Requirements

1. **R1: Remove stale includes.** When `install.sh` runs, any line in
   `/etc/csf/csf.allow` or `/etc/csf/csf.ignore` that is a CSF `Include`
   directive whose path starts with `/etc/sentinel-gate/` is removed. A
   matching line is optional leading whitespace, the literal `Include`,
   one or more whitespace characters, then `/etc/sentinel-gate/`, then
   anything. A trailing `\r` or trailing whitespace still matches.
2. **R2: Regardless of the old directory.** R1 applies whether or not
   `/etc/sentinel-gate` exists and whether or not `/usr/local/sentinel-gate`
   exists. It must not sit inside either existence guard.
3. **R3: On every install path.** R1 runs on a fresh install and on
   `install.sh --register-only`. It is not inside any `! $REGISTER_ONLY`
   block, and it is not gated on `--no-csf`, which only governs installing
   CSF.
4. **R4: Touch nothing else.** Every other line in both files is byte-for-byte
   unchanged and stays in its original order. That covers comments (including
   `# Include /etc/sentinel-gate/...`), other `Include` lines (including
   `/etc/serverscrub/...`), IP entries, blank lines, and any non-Include text
   that mentions `sentinel-gate`. File mode and ownership are preserved. If a
   file contains no matching line, it is not rewritten at all: mtime
   unchanged, no temp file left behind.
5. **R5: No other files.** No other file under `/etc/csf/` is read for this
   purpose or modified by this step.
6. **R6: Report what changed.** For each line removed, the install output says
   which file it came from and what the line was, through the existing
   `ok`/`info` helpers. When nothing is removed, the step prints nothing, or
   one `info` line at most.
7. **R7: Reload only when needed.**
   - If no line was removed, this step causes no CSF reload.
   - If a line was removed and `/usr/sbin/csf` exists, CSF is reloaded during
     that install run. The existing reload at `install.sh:1300` satisfies this
     if the step runs before it and that reload is reached. The run must not
     reload CSF **twice** because of this change.
   - If a line was removed but `/usr/sbin/csf` is absent (CSF uninstalled and
     `/etc/csf` left behind), the files are still cleaned and no reload is
     attempted.
8. **R8: Idempotent.** A second run on the same server removes nothing,
   rewrites nothing and prints no removal lines.
9. **R9: uninstall.sh also removes the legacy includes.** Decision: yes.
   `uninstall.sh` applies the same matcher as R1 to the same two files,
   alongside its existing `serverscrub/csf_*` removal and before its existing
   reload. Rationale: uninstall is ServerScrub's last chance to leave CSF
   clean. A server can be uninstalled without ever having run a fixed
   `install.sh`, for example when uninstall.sh is run from a freshly
   downloaded copy. The cost is one more line removal before a reload that
   already happens. The matcher must be the same strict pattern as R1, not a
   substring delete like the existing `\#serverscrub/csf_allow.txt#d`, so that
   a user comment mentioning `sentinel-gate` survives.

## Explicitly out of scope

- `csf.pignore`, `csf.deny`, `csf.rignore`, `csf.conf`, `csf.blocklists` and
  any other CSF file. Stale Sentinel Gate entries in those (for example a
  `cmd:.*sentinel-gate/...` pignore line) do not produce reload errors and are
  not asked for.
- Changing the existing unconditional `csf -r` at `install.sh:1300`, or
  uninstall's unconditional reload. Making those conditional is a separate
  change.
- Tightening uninstall.sh's existing substring `sed` for the
  `serverscrub/csf_*` lines (`uninstall.sh:336,340`). It is looser than it
  should be, but it is not this defect.
- Restoring or recreating `/etc/sentinel-gate/`.
- Any panel or UI surfacing of this cleanup.
- Removing `/etc/apache2/conf.d/modsec_vendor_configs/sentinel-gate/`. It must
  stay, for the reason given at `install.sh:264-267`.

## Failure behaviour

- `/etc/csf/` absent, or either file absent: skip that file silently. No
  error, no `touch`, no file created.
- File present but unreadable or unwritable (immutable bit, read-only FS):
  `warn` naming the file and the line(s) that should be removed by hand, then
  continue the install. Never abort the install over this step.
- The rewrite must be atomic. Write a temp file in `/etc/csf/`, copy mode and
  owner across, then `mv` it over the original. A failure mid-write must leave
  the original file intact. Never truncate first and write second.
- `csf -r` fails: existing behaviour (lfd restart fallback) applies. Nothing
  new.
- The step must not alter CSF's runtime state in any way except through the
  reload. It runs no `csf -a`, no `csf -d` and no `csf -x`.

## Resource bounds

- Exactly two files read, at fixed paths. No directory walk, no glob, no
  `find`.
- Each file is read once and, only if a match exists, written once. Prod
  csf.allow is a few hundred lines. No size cap is required, but the
  implementation must stream the file and must not shell out per line.
- At most one CSF reload per `install.sh` run attributable to the CSF section
  (R7).

## Acceptance criteria

Shakaal must demonstrate all of these. Docker results are the evidence;
source-text assertions alone do not count.

**Regression test**: `tests/test_legacy_csf_include_cleanup.php` (or an
equivalently named file), following the pattern of
`tests/test_legacy_waf_cleanup.php`, and passing under `tests/run-tests.sh`:

- A1. It asserts that install.sh contains the cleanup, and that it sits outside
  the `if [[ -d "${LEGACY_WAF_DIR}" ]]` block, outside the
  `/usr/local/sentinel-gate` migration block, and outside every
  `! $REGISTER_ONLY` block. Use position checks like the existing test's
  `strpos` ordering.
- A2. It asserts that uninstall.sh contains the same legacy-include removal,
  placed before its reload.
- A3. **Behavioural**: wherever bash is available, the test runs the actual
  cleanup logic against fixture copies of csf.allow and csf.ignore in a temp
  dir. If needed, Wasooli factors it into a function with overridable paths.
  The test then asserts each of the following:
  - both stale `Include /etc/sentinel-gate/...` lines are gone, including one
    with leading whitespace and one with CRLF;
  - `Include /etc/serverscrub/csf_allow.txt`,
    `# Include /etc/sentinel-gate/csf_allow.txt`, a comment
    `# migrated from sentinel-gate`, IP entries and blank lines are
    byte-identical and in their original order;
  - a file with no match has an unchanged mtime;
  - a second run changes nothing.

**Docker verification** in `docker/compose.yml`. Wasooli adds a `csf` stub
that appends each invocation to a log, the way `apachectl-stub.sh` does, plus
a seed step for `/etc/csf/csf.allow` and `csf.ignore` mirroring prod: stale
include on csf.allow line 72 and csf.ignore line 30, surrounded by real-looking
entries and comments. `/etc/sentinel-gate/` is absent.

- A4. Fresh install with that seed: both stale lines are removed, everything
  else is unchanged (diff the seed against the result; the only differences are
  the two removed lines plus the `/etc/serverscrub` includes install.sh appends
  as before), and the output names both removed lines.
- A5. `install.sh --register-only` on the same seed, reset: same result as A4.
  This is the upgrade path, and it is the one that matters for prod.
- A6. Second `--register-only` run: no removal output, both files' checksums
  and mtimes unchanged from after A5.
- A7. With `/usr/sbin/csf` absent but the seeded `/etc/csf` files present, the
  lines are removed and the stub log shows no reload. With no `/etc/csf/` at
  all, install completes with no error and no `/etc/csf` is created.
- A8. Stub log shows no more than one `csf -r` per install run in A4 and A5,
  i.e. this change adds no second reload.
- A9. `uninstall.sh` on a seeded container that still has the stale lines:
  both legacy and serverscrub includes are removed, and the user comment
  mentioning `sentinel-gate` survives.
- A10. On a real CSF (if Shakaal has one; otherwise state that it was not
  checked): `csf -r` after A5 prints no `File does not exist` error.

## Open questions

None blocking. The user said the requirement is fully decided, so these
assumptions were made without asking. Each is labelled so Wasooli can push back:

- **AQ1.** CSF's `Include` keyword is treated as case-sensitive (`Include`
  only). `include /etc/sentinel-gate/...` in lowercase is left alone.
- **AQ2.** No backup copy of csf.allow/csf.ignore is kept. The removed lines
  are ServerScrub's own and are echoed in the install output (R6), which is
  the record. A backup written into `/etc/csf/` was rejected because stray
  files there confuse operators.
- **AQ3.** The prefix `/etc/sentinel-gate/` covers any file under it, not
  just `csf_allow.txt` and `csf_ignore.txt`. Every such include is dead,
  because the directory is deleted by `install.sh:261`.
- **AQ4.** uninstall.sh should remove the legacy lines (R9). The user asked
  for this to be stated, not decided. The decision taken here is "yes" for the
  reasons given in R9.
- **AQ5.** The existing `install.sh:1300` reload is assumed to be the one
  that applies the cleanup on servers with CSF. If Wasooli places the step
  elsewhere, R7 still governs.

## Implementation (Wasooli, 2026-11-23)

**What was built**

- `install.sh`: `_ss_strip_legacy_csf_includes()` plus two calls (csf.allow,
  csf.ignore), placed right after `section "CSF / LFD firewall integration"`
  and BEFORE `if [[ -f /usr/sbin/csf ]]`. That position is after the
  legacy-dir block, after the migration block, after the INSTALL-ONLY span's
  closing `fi`, and inside no `REGISTER_ONLY` / `SKIP_CSF` guard. It adds no
  reload: the existing `csf -r` a few lines below applies the change when CSF
  is present (R7/AQ5); with no `/usr/sbin/csf` nothing reloads.
- `uninstall.sh`: the identical function (byte for byte, comments included)
  and the same two calls, after the existing serverscrub/pignore removal and
  before its reload (R9).
- `tests/test_legacy_csf_include_cleanup.php`: A1 (position checks, including a
  walk of every top-level `if ... REGISTER_ONLY` block to its matching `fi`),
  A2 (uninstall placement, identity of the two copies), A3 (the function is
  extracted from install.sh and run by bash under `set -euo pipefail` against
  fixtures: LF file with no final newline, CRLF file with leading/trailing
  whitespace, a clean file, a missing file, then a second run). 33 assertions.
  Mutation-checked: moving the calls into the INSTALL-ONLY span makes 4 of
  them fail.
- `docker/csf-stub.sh` (image path `/usr/local/lib/serverscrub-test/csf-stub`)
  logs every call to `/var/log/serverscrub-csf-stub.log` and, on `-r`/`-ra`,
  prints CSF's `*Error* File does not exist` for any missing `Include` target
  in csf.allow/csf.ignore. Not installed at `/usr/sbin/csf` by default.
- `docker/seed-csf.sh`: seeds `/etc/csf` (stale include at csf.allow:72 and
  csf.ignore:30, verified by the script), keeps a pristine copy in
  `/var/lib/serverscrub-test/csf-seed/`, resets the stub log, removes
  `/etc/sentinel-gate`. Options: `--with-ours`, `--no-binary` (A7 first half),
  `--absent` (A7 second half). Wired into `docker/Dockerfile`.

**Matcher**: `^[ \t]*Include[ \t]+/etc/sentinel-gate/` (ERE, literal tab),
case-sensitive (AQ1), any file under the directory (AQ3). No backup (AQ2).

**Deviations / judgement calls, for Shakaal**

1. A matching file is read twice, not once: `grep` first to decide whether
   there is anything to do (so a clean file gets no temp file, no rewrite and
   no directory mtime change), then `awk` to rewrite. Both are single streaming
   passes; no per-line shell-outs. I chose R4's "not rewritten at all" over the
   resource bound's "read once".
2. Mode/owner are preserved with `cp -p original tmp` before writing into the
   temp, then `mv`. SELinux context is not explicitly copied (`mv` of a file
   created in `/etc/csf` gets that directory's default label).
3. `awk -v BINMODE=3`: Git-for-Windows gawk otherwise strips `\r` on input and
   rewrote CRLF lines. Linux gawk/mawk ignore it. The CRLF fixture would have
   caught this on Linux only if gawk behaved like Windows; it is in the code
   for the Windows test run, not for prod.
4. A trailing newline is preserved as found (a file without one keeps not
   having one).
5. Unwritable/immutable files: `mktemp`, `cp -p`, `awk` or `mv` failing
   removes the temp and `warn`s with the file and each line to remove by hand;
   unreadable (grep exit 2) warns generically. Neither aborts. Not exercised by
   the PHP test (needs root / chattr) -- docker only.
6. A fresh install in docker without the stub will try `dnf install
   cpanel-csf`; use `--no-csf` for the A7 runs.

**Not done**: docker verification (A4-A10) -- Shakaal's.
7. `tests/test_rebrand.php` flags any old-name mention outside install.sh,
   uninstall.sh, docs/ and `test_legacy_*`. The docker files satisfy it by
   holding the old path in one `OLD=` variable and wording comments so every
   remaining mention carries `(legacy)` after it, per that test's convention.
   The rebrand test itself was not changed.
