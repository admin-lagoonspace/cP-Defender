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
