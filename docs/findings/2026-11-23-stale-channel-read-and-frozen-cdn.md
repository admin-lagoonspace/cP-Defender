# Test run — 2026-11-23

**Build:** `fix/stale-channel-read-and-frozen-cdn` @ `cab106f` (not pushed), VERSION still 4.37.9
**Environment:** AlmaLinux 8 in docker/compose.yml, PHP 7.4.33 and 8.2, sqlite 3.26.0 (cli and PDO), python 3.6.8
**Verdict:** FAIL — one blocker, two majors. Holds the release.

**Status: fixed-pending-retest (Wasooli, 2026-11-23).** All three are fixed;
detail at the end of this file. Finding 1 was my error and the finding is
exactly right about it — I built a check that could not fail and then printed a
freshness assurance on top of it, which is a worse version of the defect the
spec was written against. Finding 4 is recorded, not actioned: the Z bump is
Gabbar's at the cut and `cdn-sync.sh` still has to be hand-copied to the box.

## Not tested

- **cpsrvd, WHM AppConfig, LiveAPI, the CGI wrappers.** Container installs `--mode standalone`.
- **The CDN freeze itself.** `host.lws-s1.com` unreachable from here; open question 1's eight
  read-only commands still stand, un-run. Nothing below changes that.
- **Real GitHub.** `raw.githubusercontent.com` and `api.github.com` were hijacked inside the
  container (hosts entry + a self-signed CA added to the trust store + a local HTTPS stub) so the
  new code paths execute for real against controlled fixtures. Fastly's actual cache behaviour is
  Dagdu's measurement, not re-measured here.
- **`publish.sh` end to end.** Never run against a real origin. The two new gates were read, and
  `tests/test_release_mirror_verified.py` does execute the extracted blocks with stubbed curl.
  The *re-run* behaviour in finding 2 is reasoned from the script, not executed.
- **Acceptance criterion 13 (Z bump).** VERSION is deliberately untouched on this branch, so
  `scripts/check-version-bump.sh` reports "VERSION unchanged since v4.37.9 — nothing to check".
- Real ModSecurity, real Exim, real ClamAV, and scale (8 seeded accounts, not 132).

## Findings

### 1. "Already up to date — Confirmed against <url>" is printed on a branch-only reading whenever the tags API does not answer — blocker

**What happens:** the reported incident reproduces on this build, and the output is now *worse*
than before: instead of no hedge, the operator gets an explicit assurance that the reading cannot
be stale.

Corroboration is a tautology. When `_immutable_channel_version()` returns nothing — rate-limited,
unreachable, nonsense, or any non-GitHub channel — the code substitutes the branch answer as the
"immutable" version and then confirms it by fetching `v<that same version>/latest.json`:

```bash
IMM_VER="$(_immutable_channel_version "$BASE" 2>/dev/null || true)"
if [[ -z "$IMM_VER" ]]; then
    IMM_VER="$LATEST_VERSION"        # <-- the branch answer, now "immutable"
fi
```

`v<X>/latest.json` proves that version X exists. It never proves X is the newest. Every released
version has a tag and therefore that path, so this check cannot fail, and `VER_IMMUTABLE=true` is
set in precisely the case requirement 4 exists to hedge.

All three implementations share it: `update.sh` (`IMM_VER="$LATEST_VERSION"`), `upgrade.sh`
(`[[ -n "$IMM_VER" ]] || IMM_VER="$LATEST"`), `UpdateChecker::bestManifest()` (`$iv = $bestVer`).

**Reproduce:** stub channel where the branch manifest is cached at 4.37.7, the real newest tag is
4.37.8, `v4.37.7/latest.json` exists (as it does on real GitHub for every release), and
`api.github.com/.../tags` returns 403 or does not answer. Installed 4.37.7.

```
bash update.sh --yes
  ok   Corroborated v4.37.7 against https://raw.githubusercontent.com/<repo>/v4.37.7/latest.json
  ok   Already up to date — v4.37.7
  ->     Confirmed against .../v4.37.7/latest.json (addressed by version; no cache can stale it).
EXIT=0
```

`upgrade.sh --check`, same fixtures:

```
  ->  Confirmed against https://raw.githubusercontent.com/<repo>/v4.37.7/latest.json - a url that names the version, so no
  ->    cache can have answered it with a different build.
  ok  Already on v4.37.7 - nothing to do.
```

`UpdateChecker::checkForUpdates()` through `setFetcherForTests`, CDN frozen at 4.37.0 with its
retained `v4.37.0/` folder, GitHub branch at 4.37.7, tag 4.37.8 real, API null:

```
corroborated     : true
version_source   : https://raw.githubusercontent.com/<repo>/v4.37.7/latest.json
uncorrob_note    :
```

So the panel's new three-state display collapses back to two in its target case: `corroborated`
is true, `uncorroborated_note` is empty, and `#dash-update-error` stays hidden.

The same thing happens with a single pinned channel, which is the shape open question 2 suspects
production was in: `SG_MANIFEST_URL=https://serverscrub.com/releases/latest.json`, install 4.37.0,
CDN frozen at 4.37.0 with `v4.37.0/latest.json` retained →
`Already up to date — v4.37.0 / Confirmed against .../v4.37.0/latest.json`, with nine releases
in existence.

Acceptance criterion 2 only passed in my first pass because that fixture omitted the installed
version's own tag manifest. Real GitHub always has it.

**Expected:** a pinned manifest may corroborate only a version that an *immutable source named*.
A version substituted from the branch answer is not corroboration and must leave
`VER_IMMUTABLE` / `_corroborated` false, so requirement 4's hedge prints. Note the same objection
applies to the CDN's per-build manifest: `cdn-sync.sh` retains `KEEP_VERSIONS` old folders, so
`<cdn>/v<old>/latest.json` also exists and also proves nothing about currency.

**Evidence:** above, plus the access log showing the only three requests that mattered —
`api.github.com/repos/<repo>/tags?per_page=10` (403), `main/latest.json` (4.37.7),
`v4.37.7/latest.json` (200, 4.37.7).

### 2. A publish blocked at the CDN gate cannot be finished — major

**What happens:** requirement 13 is implemented correctly and diagnosed well, but the failure is
not recoverable through any documented path.

Order of operations: commit, push, tag, push tag, verify the tag path, *then* wait up to 12
minutes for the CDN and `exit 1` if it never serves the new version. Git is correctly left alone.
But the tag is already on origin, and `scripts/publish.sh:70-73` is:

```bash
if git ls-remote --tags origin "refs/tags/${TAG}" 2>/dev/null | grep -q "${TAG}"; then
    die "Tag ${TAG} already exists on origin. Bump VERSION or delete the tag first."
fi
```

So: publish → blocked on the frozen mirror → operator fixes the CDN → re-runs `publish.sh` →
dies on line 72. The 7b failure text tells you to force the sync and lists four read-only
diagnosis commands, and says nothing about how to complete the release afterwards. The two routes
the line-72 message offers are both bad: burn a version number, or delete a pushed tag that
`update.sh` now treats as *the* authoritative version source. There is no `SG_SKIP_*` for this
gate (unlike `SG_SKIP_VERSION_CHECK` / `SG_SKIP_TESTS`), and nothing in `docs/KB-updating.md` or
the changelog covers the resume.

Concretely: the CDN is frozen now, the root cause is unknown, and production is unreachable from
this environment. The next `publish.sh` run will push a tag, wait 12 minutes and exit 1, and the
release will be stuck.

**Reproduce:** read `scripts/publish.sh:70-73` against the `exit 1` at the end of section 7b.
Not executed — I did not run `publish.sh` anywhere it could reach the real origin.

**Expected:** fail the release, yes — the user's rule is that a release is not done until it is
mirrored. But the failure must name the way out. Either the 7b failure text ends with the exact
resume command, or the line-72 guard learns to distinguish "tag exists and points at HEAD, so
resume from the mirror step" from "tag exists on another commit, so refuse" — it already makes
that exact distinction locally at `publish.sh:284-289` (`Tag ... already exists locally on
<sha> — reusing it`). Extending that to the remote guard is the smaller change.

**Evidence:** `publish.sh:72` vs the `exit 1` closing section 7b; no `SG_SKIP` for the CDN gate
(`grep -n 'SG_SKIP' scripts/publish.sh` yields only `SG_SKIP_VERSION_CHECK`).

### 3. `upgrade.sh` blames the release mirrors when the installed version is unreadable — major

**What happens:** `CURRENT="unknown"` (no or unreadable `${SG_ROOT}/VERSION` — the broken install
this script exists to repair) sorts *above* every real version under `sort -V`:

```
$ printf '4.37.9\nunknown\n' | sort -V | tail -1
unknown
```

so `_ver_gt "$LATEST" "$CURRENT"` is false and `[[ "$LATEST" == "$CURRENT" ]]` is false, and the
decide block takes its third branch — the one that means "every channel is behind this install".

**Reproduce:** stub channels, CDN 4.37.0, GitHub 4.37.9, `${SG_ROOT}/VERSION` absent:

```
  ->      https://serverscrub.com/releases -> v4.37.0
  ->      https://raw.githubusercontent.com/<repo>/main -> v4.37.9
  ok  Available: v4.37.9
  ->  Confirmed against .../v4.37.9/latest.json
  !!  No channel offers anything newer than the installed vunknown.
  !!    A mirror behind the installed version is a stalled sync, not a release
  !!    being withdrawn.
  !!    That reading is not corroborated either, so the decision is not made here.
  vunknown  ->  v4.37.9        <- and it proceeds
```

It does the right thing in the end — it hands over to the updater, so this does not block an
upgrade — but it tells the operator the release mirrors have stalled and that the reading is
uncorroborated, four lines after correctly reporting the newest version as corroborated. On this
build that is a false claim about infrastructure pointing at the CDN, when the actual fault is on
the server in front of them. The shipped code had an explicit `&& "$CURRENT" != "unknown"` guard
and never printed any of it.

**Expected:** handle `unknown` before the comparison. An unreadable installed version is "I cannot
tell what is installed — fetching the updater", not "every mirror is behind".

### 4. Acceptance criterion 13 is unverified, and requirement 14's fix is inert — minor

`check-version-bump.sh` cannot agree with a Z bump while VERSION is untouched; it will only be
exercised when Gabbar bumps. By the stated rule (fixes on shipped features) Z is right, and the
batch adds no new feature — but the criterion has not run, and this batch does add a gate that can
fail a release, which is the sort of thing worth a second look at bump time.

Separately: `scripts/cdn-sync.sh` lives on the production box and is hand-copied there. The
honest-exit fix (requirement 14) does nothing to the current freeze until someone copies it over.
Correctly out of scope; recorded so nobody reads requirement 14 as "the mirror is fixed".

## What passed

Real runs in the container against hijacked channels, not source-text assertions.

- **Full regression, both ends of the supported range.** `PHP_STREAM=7.4` and `PHP_STREAM=8.2`:
  5527 assertions, exit 0 each. Python checks ran under 3.6.8 on Linux.
- **Acceptance criterion 1 — the reported incident, with the API reachable.** Branch manifest
  4.37.7, tag v4.37.8: `update.sh` warns the manifests say 4.37.7, takes the version-pinned
  manifest, reports `Corroborated v4.37.8 against .../v4.37.8/latest.json`, and offers
  4.37.7 -> 4.37.8. No "Already up to date".
- **The per-version URL-shape bug is really fixed.** The access log shows
  `raw.githubusercontent.com/<repo>/v4.37.8/latest.json`, not the old always-404
  `.../main/v4.37.8/latest.json`.
- **Criterion 3 — genuinely current.** All sources at 4.37.8, install 4.37.8: one
  "Already up to date", source named, no disagreement warning, exit 0.
- **Criterion 4 — `latest/VERSION` 404.** Requested, 404, no abort, no error, and not counted as a
  passed cross-check.
- **Tag with no manifest under it.** `warn "... names v4.37.9 but .../v4.37.9/latest.json does not
  carry it - ignoring that ref."`, then falls back labelled. Nothing downloaded from it.
- **Tag ordering trap.** Tags listed `v4.9.0, v4.37.8, v4.10.0` -> resolves 4.37.8. `sort -V`, not
  list order, as the comment claims.
- **Criteria 5 and 6 — a lagging mirror no longer blocks.** CDN 4.37.0, GitHub 4.37.9, installed
  4.37.7: both channels named with their versions, CDN reported as a stalled sync, offers 4.37.9,
  exit 0. No "Refusing to downgrade". Unchanged when the stale channel is listed last
  (`SG_CDN_BASE` pointed at the fresh tree). This combination exits 1 on 4.37.9's code.
- **The updater comes from the version-pinned tree.** Real `upgrade.sh --yes` run: exactly one
  fetch, `raw.githubusercontent.com/<repo>/v4.37.9/update.sh`, first attempt. The frozen CDN root's
  4.37.0 updater is never requested.
- **`set -euo pipefail` and the `&&` short-circuits.** Verified empirically: `_ver_gt ... && continue`
  and `[[ ... ]] && { ... }` inside a loop do not trip `set -e`; the loop completes and the script
  exits 0. Wasooli's own hardest spot #1 holds.
- **Request bound.** 13 HTTP requests for a three-channel `update.sh` check, of which **4 are new**
  (1 tags API call + 3 pinned-manifest fetches) against the spec's budget of 6 added. Exactly one
  `api.github.com` request per check, as required — there is only one `raw.githubusercontent.com`
  entry in `CHANNELS`, so the per-channel loop cannot multiply it. Wasooli's hardest spot #2 is
  within bound.
- **`checkForUpdates()` returning `getCachedStatus()` is not an API change.** The new shape is a
  strict superset of the eight keys it used to return; all five call sites
  (`api/index.php:2357`, `cron/scheduler.php:387`, `cron/update-check.php:29`,
  `Updater.php:165,330`) read keys that still exist. `update_check_error` is still written only for
  "could not reach a channel", so `scheduler.php:394`'s early return is unaffected.
- **Panel, driven in the browser against :8777.** `#dash-update-error` and `#dash-mirror-lag` now
  exist in the DOM (they did not before — `getElementById` returned null and the whole branch was
  dead). With `update_corroborated=0` and a note seeded, both render `display: block` with the full
  sentence. `/api/update/status` serves `corroborated`, `version_source`, `uncorroborated_note` and
  `mirror_lag`. Clean console and network after login — the 401s and the `config.js` 404 in the log
  are my own pre-login probing and pre-existing behaviour.
- **The three changed assertions are all genuine, and none is weaker.**
  - `test_autoupdate.php`: the host-wide `api.github.com` ban did forbid the only immutable source
    the GitHub channel has. The replacement still bans the Releases API — by a regex within 120
    chars of the host, which is stricter than a substring test would be — and now *requires*
    `/tags?per_page=`. Net stricter.
  - `test_cron_and_cdn.php`: the pinned closing line genuinely no longer exists, because
    requirement 13 removes that code path. The replacement asserts
    `RELEASE IS IN GIT BUT NOT MIRRORED` is present, `CDN will pick it up` is absent, and the only
    surviving `Published` line is inside the both-halves-verified branch. Strictly stronger.
    `grep` does find `CDN will pick it up` at `publish.sh:487` — inside a comment quoting the old
    output, and `t_shell()` strips comments, so the assertion is about executable text. Correct.
  - `test_cdn_manifest_cache.py`: only the anchor moved. `_verify_public_manifest || true` is gone
    (0 occurrences), `if _verify_public_manifest; then` is present exactly once, and the ordering
    property asserted around it is unchanged.
- **`cdn-sync.sh` honesty.** `published v<ver>` is now only reachable inside the agreeing branch;
  the retention prune is gated on `PUBLISH_OK`, so a run that cannot confirm what the public URL
  serves does not delete old builds; `$PUBLISH_OK || exit 1`. The `set -uo pipefail` (no `-e`) and
  the `[ "$KEEP_VERSIONS" -gt 0 ] 2>/dev/null` idiom are unchanged in meaning.

---

## Wasooli — second pass, 2026-11-23

**Status: fixed-pending-retest.** Back to Shakaal. Build: this branch @ the
commit after `cab106f`. Preflight passes against exactly this tree, including
the docker Linux stage: 5,551 PHP assertions, 81 in
`test_update_corroboration.py`, 40 in `test_release_mirror_verified.py`.
VERSION still 4.37.9, no changelog heading added.

### 1. The tautology — blocker. Fixed.

You are right, and the reasoning is the part I got wrong rather than the code:
I treated "the pinned manifest answered" as corroboration, when all it shows is
that the version exists. Every released version has a tag, and `cdn-sync.sh`
retains `KEEP_VERSIONS` old `v<ver>/` folders, so the check could not fail —
and it set `VER_IMMUTABLE=true` precisely where requirement 4 exists to hedge.

The rule is now stated in the code: **a pinned manifest may only corroborate a
version that an immutable source NAMED as current.** There are two such sources
and no others — the tag list, and `<channel>/latest/VERSION`, which is read out
of the deployed build and can disagree with the manifest beside it. A channel
with neither has no immutable source today, and the answer from it stays
labelled.

Concretely, the fallback is gone from all three:

* `update.sh` — `[[ -z "$IMM_VER" ]] && IMM_VER="$LATEST_VERSION"` is now
  `continue`. The pinned manifest for a version nothing named is not even
  requested; that request could only ever produce a false confirmation.
* `upgrade.sh` — `[[ -n "$IMM_VER" ]] || IMM_VER="$LATEST"` is now
  `|| continue`.
* `UpdateChecker::fetchManifest()` — `$iv = $bestVer;` removed, so
  `_corroborated` stays false, `uncorroborated_note` is non-empty, and
  `#dash-update-error` shows in its target case.

Your reproduction is now a test, with the fixture shape you identified as the
one I had wrong — **the installed version's own tag manifest present**, because
real GitHub always has it:

* `tests/test_update_corroboration.py` — "THE TAUTOLOGY", the CDN-shaped
  variant with a retained `v4.37.0/`, and the end-to-end case that runs the
  corroboration block and the up-to-date gate together and asserts that neither
  "Already up to date" nor "no cache can stale it" appears.
* `tests/test_update_corroboration_panel.php` — the same at the
  `fetchManifest()` seam and through `checkForUpdates()` to `corroborated` /
  `uncorroborated_note`.

Verified failing against the pre-fix code: re-introducing the two shell
fallbacks turns 10 of the new assertions red, including
`(expected 'false', got 'true')` on the corroboration flag and
`got 'https://raw.githubusercontent.com/<repo>/v4.37.7/latest.json'` as the
claimed source. Restored, all green.

### 2. A blocked publish could not be finished — major. Fixed your way.

Extended the remote guard rather than adding an `SG_SKIP`, as you suggested — a
skip flag would let someone bypass the mirror rule, which is the one thing the
user asked to be enforced.

`publish.sh:70` now distinguishes a resume from a conflict: the remote tag
object must be byte-identical to the local one **and** the local tag must point
at HEAD. That is `RESUMING=yes`, announced, and the run continues to re-check
the mirror. Any other tag of that name on origin is still a hard refusal, and
the refusal now says that deleting a published tag withdraws the release,
because `update.sh` resolves versions from tags.

Two consequences of resuming that I had to handle, both of which would have
ended the run before the mirror step:

* `gh release create` / the API POST fail on a tag that already has a Release.
  A resume checks for an existing Release first, through `gh` or the token,
  whichever this machine has, and leaves it alone.
* a rebuild that stages a change would have made a **second** commit, moving
  HEAD off the tag already on origin and tripping the local tag guard after
  another push. A resume now stops before anything leaves the machine, lists
  the files, and gives the `git checkout --` line.

The 7b failure text ends with `bash scripts/publish.sh <ver>` and "Do NOT bump
VERSION and do NOT delete the tag".

Tested by executing the guard with `git` stubbed — four cases: no remote tag,
resume, different tag object, tag not on HEAD. Not end-to-end against a real
origin; that remains untested here, as it was for you.

### 3. `unknown` blamed the mirrors — major. Guard restored, earlier.

`CURRENT == "unknown"` is now handled **before** any comparison, so it cannot
reach the "every channel is behind this install" branch at all. It says what it
could not do — read `${INSTALL_DIR}/VERSION` — states that this says nothing
about the release channels, and hands over to the updater. The per-channel
report still names a lagging mirror, which is a different statement from
blaming it.

I dropped the old `&& "$CURRENT" != "unknown"` clause from the downgrade branch
instead of restoring it there: unknown can no longer reach that line, and a
condition that can never be false reads as a guard without being one. Say so if
you would rather have both.

### 4. Recorded, not actioned

Agreed on both halves. The Z bump is Gabbar's at the cut — no commit subject in
this batch begins with `feat`, so the heuristic will not fight it — and nothing
in requirement 14 touches the current freeze until `cdn-sync.sh` is copied to
the box. The spec's open question 1 commands are still the only route to the
cause, and still un-run.

### Where to look hardest this time

* The corroboration rule is now a **negative**: the absence of an immutable
  source must stay uncorroborated. Worth probing for another path that can set
  `VER_IMMUTABLE` / `_corroborated` from something that cannot disagree — I
  believe the only two left are the tag list and `latest/VERSION`, and
  `latest/VERSION` only when it *agrees* with the manifest.
* The resume path has three exits I added (release exists, rebuild dirty,
  conflicting tag) and none of them has been run against a real origin.
* With the tags API unreachable **and** no `latest/VERSION` anywhere — the
  firewalled-server case — nothing is ever corroborated now, so those servers
  will see the hedge on every check. That is honest but it is also permanent
  for them; if you think it reads as alarming rather than informative, that is
  a wording question worth raising with the user.

---

# Retest — 2026-11-23 (second pass)

**Build:** `fix/stale-channel-read-and-frozen-cdn` @ `191d716` (`e3c72e1` + `191d716` on `cab106f`), not pushed
**Environment:** AlmaLinux 8 in docker/compose.yml, PHP 7.4.33 and 8.2, sqlite 3.26.0, python 3.6.8
**Verdict:** FAIL — findings 1 and 3 are fixed and verified. Finding 2 is **not** fixed and is now worse: the resume it added cannot succeed. One new minor.

**Status: fixed-pending-retest (Wasooli, third pass, 2026-11-23).** Finding 2 is fixed and
exercised the way you asked — a real bare origin, a real build, no stubbed `git`. Finding 5 and
the hedge wording are done. Detail at the end of this file.

## Status of the previous findings

| | |
|---|---|
| 1. Tautological corroboration — blocker | **FIXED, verified** |
| 2. Blocked publish cannot be finished — major | **NOT FIXED — now a blocker** |
| 3. `unknown` blames the mirrors — major | **FIXED, verified** |
| 4. Criterion 13 unverified / req 14 inert — minor | accepted, unchanged |

### 1. Fixed, verified on all three paths

Same hijacked-GitHub fixtures as the first pass: branch manifest cached at 4.37.7,
`v4.37.7/latest.json` present (as on real GitHub), real newest tag 4.37.8, tags API 403,
install 4.37.7.

`update.sh --yes` — tags API 403, and again with the API unreachable:

```
->  Latest version:  v4.37.7
!!  No channel offered anything newer than the installed v4.37.7.
!!    Nothing addressed by version could be reached to confirm it, so this is
!!    NOT a confirmation that this install is current.
EXIT=0
```

No `Corroborated`, no `Already up to date`, exit 0. `upgrade.sh --check` likewise prints
`UNCONFIRMED` and hands over to the updater instead of `Already on v4.37.7 - nothing to do`.
`UpdateChecker::checkForUpdates()` through the fetcher seam now returns `corroborated: false`,
empty `version_source`, and a populated `uncorroborated_note` — so `#dash-update-error` shows.
The tautological `v4.37.7/latest.json` request is gone from the fetch log entirely; one fewer
request per check.

No regression on the good paths: the incident fixture (tags API healthy, tag v4.37.8) still
resolves `Corroborated v4.37.8 against .../v4.37.8/latest.json` and offers 4.37.7 -> 4.37.8;
the lagging-mirror case (criteria 5/6) is unchanged.

**Negative probed, as asked.** Three more fixtures, all against the pinned-channel worst case:

* *Firewalled* — only `latest.json`, no tags API, no `latest/VERSION`, no `v<ver>/` folders:
  never corroborated, hedge every time. Correct.
* *Repo-root `VERSION` agreeing* — `latest/VERSION` 404s, `main/VERSION` reads 4.37.7,
  `v4.37.7/latest.json` present: **still uncorroborated.** Root `VERSION` is read as a second
  opinion and is not allowed to confirm, matching `channelManifest()`'s
  `substr($liveSrc, -15) === '/latest/VERSION'` rule. Shell and PHP agree.
* *Frozen origin with a consistent tree* — `latest.json` and `latest/VERSION` both 4.37.0:
  corroborated via `latest/VERSION`. This is requirement 3 working as written (it names
  `latest/VERSION` as the corroborator) and it is a genuine second opinion — the two objects are
  separately keyed and the override block exists because they *can* disagree. Not a defect.
  The wording is, though — see finding 5.

Wasooli's belief that only the tag list and `latest/VERSION` remain is correct as far as I can
drive it.

### 3. Fixed, verified

`${SG_ROOT}/VERSION` absent, CDN 4.37.0, GitHub 4.37.9:

```
ok  Available: v4.37.9  (from .../main)
->  Confirmed against .../v4.37.9/latest.json - a source a cache cannot have
->    answered with a different build.
!!  Cannot read /harness/root/VERSION, so there is nothing here to compare
!!    v4.37.9 against. This says nothing about the release channels.
!!    Handing over to the updater, which decides for itself.
vunknown  ->  v4.37.9
```

No mirror blame, no spurious "uncorroborated", and it still hands over. **The dropped
`!= "unknown"` clause checks out:** `unknown` is now intercepted by the first branch of the
`if`, so the clause in the downgrade branch could never have been false. Dropping it is right.

## Findings

### 2 (reopened). The resume `publish.sh` now prints cannot succeed — blocker

**What happens:** the remote-tag guard is fixed and the resume is recognised, but a new
unconditional block downstream refuses it every time. Exercised against a **real local bare
repo as origin**, with `curl` stubbed and the repo-local interpreters on PATH.

Case A, CDN never serves the release: correct. Tag pushed, `exit 1`, right diagnosis
("The CDN IS answering, with the WRONG release"), and the new closing text:

```
    TO FINISH THIS RELEASE once the CDN serves 4.37.10:
      bash scripts/publish.sh 4.37.10
    ...
    Do NOT bump VERSION and do NOT delete the tag -- update.sh resolves
    versions from tags, so deleting this one withdraws the release.
```

Case B, that exact command, with the CDN now healthy and the working tree clean and HEAD on
the tag:

```
!!  Tag v4.37.10 is already on origin, as the same object, on HEAD (43c24c5).
!!    Treating this run as a RESUME of a release that got as far as the push.
[+] Built dist/serverscrub-4.37.10.zip (1400540 bytes), sha256 25b86c39084f8d99...
[x] Resuming v4.37.10, but the rebuild changed tracked files.
      dist/latest.json
      dist/serverscrub-4.37.10.zip
      latest.json
EXIT=1
```

The release artifacts are committed to the repo and **the build is not byte-reproducible**: two
consecutive runs produced sha256 `25b86c39...` and `dbcb9b48...`. The zip changes, so
`latest.json`'s `sha256` changes, so `dist/latest.json` changes. The rebuild runs *before* the
`RESUMING` + `git diff --cached` check, so the check is dirty by the time it is reached, on every
possible run. The resume is unreachable by construction, not by operator error.

And the recovery it offers does not work even on its own terms:

```
      git checkout -- $(git diff --cached --name-only | tr '\n' ' ')
```

`git checkout -- <paths>` restores the **working tree from the index**, and the index is what is
dirty. Run verbatim:

```
$ git diff --cached --name-only         # dist/latest.json dist/serverscrub-4.37.10.zip latest.json
$ git checkout -- $(git diff --cached --name-only | tr '\n' ' ')   # rc=0
$ git diff --cached --quiet && echo CLEAN || echo "STILL DIRTY"
STILL DIRTY
```

So: the operator runs the printed resume command, gets a refusal, runs the printed fix, re-runs,
and gets the identical refusal. A loop. I confirmed `git checkout HEAD -- <paths>` does clean the
index — and that it makes no difference, because the next run rebuilds and re-dirties it anyway.

Net effect is finding 2 unchanged: a release blocked at the mirror still cannot be finished, and
the two routes that do exist are now the two the text correctly tells you not to take.

**Reproduce:** `git init --bare origin.git`; clone the repo; `git remote set-url origin` to the
bare repo; bump VERSION / `latest.json` / `config.php` / `index.html` and date the changelog
heading; put a `curl` stub and the repo-local `python3`/`php` on PATH; then
`SG_SKIP_VERSION_CHECK=1 SG_SKIP_TESTS=1 SG_CDN_POLL_TRIES=2 SG_CDN_POLL_SECS=1 SG_GH_POLL_TRIES=1 bash scripts/publish.sh`
with the stub serving the old version, then again with it serving the new one.

**Expected:** on `RESUMING=yes`, do not rebuild — the artifacts for this tag are already
committed and already on origin; skip section 1 and the staging step and go straight to the
verification steps. If a rebuild must happen, compare it against the tag's artifacts excluding
the zip bytes and the sha256 derived from them, and say so. Either way the printed recovery
command needs to be `git checkout HEAD -- <paths>` or `git reset --hard HEAD`, not
`git checkout --`.

**Also note:** `publish.sh` reported `[*] Repository: C:/tmp/pubsand/origin` and then
`GitHub channel serves 4.37.10 at https://raw.githubusercontent.com/C:/tmp/pubsand/origin/v4.37.10/latest.json`.
That is my sandbox's remote URL being parsed into `SLUG`, not a product defect — recorded so the
log above is not misread.

Case D, conflicting remote tag (origin tag on a different commit): correct, hard refusal,
`exit 1`, with the withdraw warning. Case C (an existing Release page left alone) could not be
exercised — no `gh` and no token in the sandbox, so the script took its documented
"no gh and no GH_TOKEN" branch.

### 5 (new). `update.sh` claims the evidence is "addressed by version" when it is `latest/VERSION` — minor

**What happens:** the confirmed-current line has a hardcoded parenthetical:

```
->    Confirmed against https://serverscrub.com/releases/latest/VERSION (addressed by version; no cache can stale it).
```

`latest/VERSION` is not addressed by version. It is a mutable path on the mirror, and
`_purge_manifest_cache()` is explicitly best-effort. The version reported is right; the stated
reason it can be trusted is not — which is the class of defect this whole spec is about.

Wasooli fixed exactly this wording in `upgrade.sh` this round ("a source a cache cannot have
answered with a different build"), and `update.sh`'s copy was left behind.

**Reproduce:** CDN healthy at 4.37.9 with `latest/VERSION`, GitHub tags API unreachable,
install 4.37.9, all channels (no `SG_MANIFEST_URL`) — i.e. normal operation with a rate-limited
API, not a contrived pin:

```
ok  Corroborated v4.37.9 against https://serverscrub.com/releases/latest/VERSION
ok  Already up to date — v4.37.9
->    Confirmed against https://serverscrub.com/releases/latest/VERSION (addressed by version; no cache can stale it).
```

**Expected:** the same two-case wording `upgrade.sh` now uses, or a parenthetical chosen from
`VER_SOURCE`.

## Answers to the two questions raised

**The firewalled server's permanent hedge.** My read: honest, and the right default, but the
wording is pitched for the incident rather than for the steady state. Six warn-coloured lines
plus two curl commands, every check, forever, on a server where nothing is wrong and nothing can
be — and the operative sentence ("NOT a confirmation that this install is current") is the last
of the six, after five lines of Fastly cache archaeology. On a daily cron that is noise that
trains people to skip the block, which is how the next real warning gets missed. I would keep the
claim and shorten the delivery: one line of what is true ("no channel offered anything newer than
v4.37.7; this could not be confirmed against an immutable source, so it is not a guarantee"), the
measurement detail behind a `--verbose`, and the two curl commands only when the operator asked
interactively rather than on every cron run. Not a release blocker either way, and the call is
the user's.

**`preflight.py` and `text=True`.** It did not affect this run — there is no system Python on
this machine, and I ran the docker suite directly (`docker compose run --rm test`) rather than
through `scripts/preflight.py`, on both passes. Two things follow. First, I have never used
preflight as a gate, so my verdicts rest on the container suite plus the targeted work above, not
on preflight's extra stages. Second, the bug is plausible rather than theoretical: the suite's
own banners are full of box-drawing characters and they show up throughout the output I captured,
so a cp1252 console reader thread is being fed exactly the input described. Out of scope here;
worth its own ticket before anyone relies on preflight in CI.

## What passed on the retest

- **Full regression, both streams.** PHP 7.4.33: 5562 assertions, exit 0. PHP 8.2: 5562
  assertions, exit 0. Python checks under 3.6.8 on Linux.
- Findings 1 and 3 fixed as described, with the negative probed three ways.
- `publish.sh` case A (mirror never appears) and case D (conflicting remote tag) both behave
  correctly against a real local bare origin.
- No regression on acceptance criteria 1, 3, 4, 5, 6, or on the version-pinned updater fetch.

---

## Wasooli — third pass, 2026-11-23

**Status: fixed-pending-retest.** Back to Shakaal.

**On verification, stated plainly:** `scripts/preflight.py` does **not** pass on this tree, and
not for anything in this change. Another agent's in-progress CSF work has two untracked files in
`docker/` (`csf-stub.sh`, `seed-csf.sh`) that still carry the old product name, which fails the
rebrand assertion and, through it, preflight's docker stage. So I verified my own work by running
the container suite directly, as you did: `docker compose -f docker/compose.yml run --rm test`
→ **5742 assertions, exactly one failure, and it is that rebrand assertion naming those two
files.** Locally `php tests/run.php` gives the same single failure (5729 assertions there). My
three test files pass in both. Nothing of mine is named in it, and I have not touched their
files.

### 2 (reopened). The resume could never succeed — fixed

Your diagnosis was exact, and the test I wrote could not have caught it: four stubbed-`git`
cases with nothing built. I reproduced it first, in your sandbox shape, before changing anything.

**The fix is the shape you proposed.** `RESUMING=yes` now skips step 1 (build), step 2 and
step 3 (stage, zip-coverage check, commit) **entirely**; the run resumes at 3b and goes on to the
tag verification, the GitHub tag path and the mirror gate. The committed artifacts at the tag are
the release — a rebuild can only produce a different one. The resume reads the committed zip for
its size and sha, and refuses if it is not on disk, because then this checkout is not the tree
that was released:

```
[x] Resuming v4.37.10 but dist/serverscrub-4.37.10.zip is missing. This checkout is not the
    tree v4.37.10 was built from; check out v4.37.10 and re-run.
```

The dead `RESUMING` branch in the commit block is gone with it — it was inside the region that is
now skipped. Its replacement is in 3b, which *is* reached on a resume.

**And the recovery command was wrong twice, not once.** You measured
`git checkout -- <paths>`. The obvious correction,
`git checkout HEAD -- $(git diff --cached --name-only | tr '\n' ' ')`, is also wrong: when the
dirt is **unstaged**, that substitution is empty, so the command is `git checkout HEAD --`, which
git accepts, ignores, and exits 0 from. Measured on the sandbox:

```
$ git status --porcelain              #  M frontend/index.html
$ git checkout HEAD -- $(git diff --cached --name-only | tr '\n' ' ')
M       frontend/index.html
rc=0
$ (git diff --quiet && git diff --cached --quiet) && echo CLEAN || echo "STILL DIRTY"
STILL DIRTY
```

Same loop, one level down. What is printed now is `git reset --hard HEAD`, which clears both
sides unconditionally, with `git checkout HEAD -- <path>` given literally for the per-file case
rather than built from a substitution that can come out empty. Both are in a comment in the
script so the next person does not re-derive the broken one.

**Exercised against a real local bare origin, with a real build.** `git init --bare origin.git`,
a clone of this branch with `origin` pointed at it, a `curl` stub for the CDN and raw, the
repo-local `php`/`python3` on PATH, VERSION bumped to 4.37.10 with the other three files and the
changelog heading, `SG_SKIP_VERSION_CHECK=1 SG_SKIP_TESTS=1 SG_CDN_POLL_TRIES=2
SG_CDN_POLL_SECS=0 SG_GH_POLL_TRIES=1`:

* **A — mirror stuck on 4.37.9.** Builds, commits, pushes, tags, pushes the tag, verifies the
  tag path, waits, then `RELEASE IS IN GIT BUT NOT MIRRORED`, exit 1, tree clean, and the
  `TO FINISH THIS RELEASE / bash scripts/publish.sh 4.37.10` text.
* **B — that exact command, mirror now serving 4.37.10.** Recognised as a resume;
  `Resume: not rebuilding. Using the committed dist/serverscrub-4.37.10.zip (1401275 bytes),
  sha256 de972b5f…`; `Everything up-to-date` on both pushes; tag reused; tag path verified;
  `CDN mirror verified`; `Published v4.37.10: in git, readable at the tag, and mirrored on the
  CDN.`; **exit 0**. `make-release.sh` was not called.
* **C — dirty tree during a resume.** Refuses at 3b before anything is pushed, prints the
  resume-specific recovery; running `git reset --hard HEAD` verbatim leaves the tree clean, and
  the next resume then completes as in B. The loop closes.
* **E — committed zip missing.** Refuses with the message above.

Checked while there, since the resume prints a sha: the zip on disk, the committed blob, the
`sha256` in `latest.json` and the sha the resume printed are all `de972b5f…`. The resume does
not report a figure that disagrees with the manifest it is mirroring.

Case D (conflicting remote tag) is unchanged code and you verified it; I did not re-run it.
Case C (existing Release page) still cannot be exercised without `gh` or a token — unchanged.

**Automated as well as demonstrated.** `tests/test_release_mirror_verified.py` now extracts the
real build-or-resume block and runs it with `make-release.sh` replaced by a script that records
being called: resume → not called, completes; normal release → called; resume with no committed
zip → exit 1. 47 assertions in that file.

### 5 (new). "addressed by version" for `latest/VERSION` — fixed

The reason now comes from the source rather than from a hardcoded string: `VER_SOURCE_WHY` is set
beside `VER_SOURCE` at each of the three places that can corroborate, so a tag-pinned manifest
says "addressed by version, so no cache can hold a wrong answer for it" and `latest/VERSION` says
"read out of the deployed build, so it cannot name a version the tree does not hold". Pinned by
two assertions in `tests/test_update_corroboration.py`: the right reason appears, and
"addressed by version" does **not** appear for the `latest/VERSION` case.

### The hedge, shortened as you suggested

Your read is right and I have taken it. The default output is three warning lines, operative
claim **first**:

```
!!  NOT CONFIRMED: nothing newer than the installed v4.37.7 was offered,
!!    but that is not a confirmation that this install is current - the only
!!    answer came from https://raw.githubusercontent.com/<repo>/main/latest.json, a cacheable
!!    url that can be up to 5 minutes behind a release.
->    Re-run with --verbose for why, or in a few minutes for a confirmed answer.
```

The cache measurements move behind `--verbose` (or `SG_VERBOSE=1`, because cron lines get
inherited rather than edited), and the two by-hand `curl` commands print only when `-t 1` — i.e.
never on a cron run.

**One deliberate deviation from "one line".** The channel name and the five-minute bound stay in
the default output, because requirement 4 names both specifically ("naming the channel and that
its answer may be up to 5 minutes old"). What moved is the ETag/X-Cache archaeology. If you would
rather the bound went behind `--verbose` too, that is a spec change and the user's call, not
mine. A test asserts the default block is at most four warning lines and contains no `X-Cache`.

### One test assertion changed, for the wording

`tests/test_update_corroboration.py` asserted the literal `NOT a confirmation`; the sentence is
now `not a confirmation that this install is current` and reordered to come first. The assertion
matches the new wording and its message says why the order matters. Same property, and the
harness gained `VERBOSE` / `VER_SOURCE_WHY` because the gate reads them — a harness that omits a
variable the code under test reads is not running its preconditions.

### 4. Still recorded, not actioned

Unchanged: the Z bump is Gabbar's at the cut, and `cdn-sync.sh` has to be hand-copied to the box
before requirement 14 affects the live freeze.

### Where to look hardest this time

* The resume now skips a large region. Everything it skips is build-and-commit; everything it
  still runs is verification. Worth checking I have not skipped something a *first* release needs
  that a resume also needs — `ZIP` and `SHA` are the only two variables the skipped region sets
  that later steps read, and both are set in the resume branch.
* The resume reads `dist/serverscrub-${VER}.zip` from the worktree, not from the tag. On a
  resume from a *different* commit the clean-tree gate at 3b and the tag-identity guard both have
  to catch that; I believe they do, and case E covers the missing-file half.
* `-t 1` as the test for "someone is watching". Correct for cron and for the panel's detached
  updater, both of which redirect; if there is a caller that keeps a tty and still logs, it will
  now get two extra lines.
