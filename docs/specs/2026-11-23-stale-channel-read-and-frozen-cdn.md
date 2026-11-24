# Update channel tells the truth, and a release is not done until the mirror has it

**Asked for:** "fix everything and ship new one" / "find whats causing this cdn issue and get the team to fix it gabbar - when release is ready just publish it"
**Status:** ready-for-shakaal
**Size:** Z (fixes on shipped features: update.sh, upgrade.sh, UpdateChecker, publish.sh)

## What the user is actually trying to achieve

Two things, and they are the same thing seen from both ends.

They want to be able to run the upgrade on production and believe what it says.
They ran it minutes after v4.37.8 was published and were told "Already up to
date — v4.37.7". That statement was produced honestly from evidence that was
five minutes stale, and nothing in the output hinted that it might be. On a
security product, a confident wrong negative about patch level is the same class
of defect as the WAF reporting `action='block'` while blocking nothing.

And they want a release to actually be released. The standing rule is that a
release is not done until the build is in git **and** in a `v<version>/` folder
on the CDN. Nine releases (4.37.1 … 4.37.9) are in git and none are on the CDN.
`publish.sh` printed a cheerful "it pulls within ~10 min" and exited 0 for every
one of them, so nobody found out for a month.

## What exists today

### The stale read is reproduced, and the existing mitigation does not work on this channel

`update.sh` is **not** naive. It already:

- queries all three channels and keeps the highest version (`update.sh:225`
  `CHANNELS=(...)`, loop at `update.sh:386-445`, `_ver_gt` at `update.sh:371`);
- cache-busts every version-bearing URL with a single-use `?cb=` (`_nocache()`,
  `update.sh:286-295`);
- lets `<channel>/latest/VERSION` **override** a lower manifest version
  (`update.sh:505-560`), with a per-version `v<ver>/latest.json` fetch so the
  download stays checksum-verified;
- warns when channels disagree (`update.sh:448-456`).

`backend/lib/UpdateChecker.php` carries the same logic: `fetchManifest()` (:224)
takes the highest across channels, `channelManifest()` (:257) cross-checks
`latest/VERSION` and prefers the tree, `httpGet()` (:324) appends `?cb=`.
`git diff v4.37.7 HEAD -- update.sh upgrade.sh backend/lib/UpdateChecker.php
scripts/publish.sh scripts/cdn-sync.sh` is **empty**, so the copy that ran on
production had all of this.

Both mitigations fail on the GitHub channel, for reasons measured today:

1. **`?cb=` does not defeat GitHub raw's edge cache.** The query string is not
   part of Fastly's cache key for `raw.githubusercontent.com`. Measured from
   this machine, same object, two consecutive requests:

   ```
   .../main/latest.json                   -> X-Cache: MISS  ETag "f7a7cab…"  4.37.9
   .../main/latest.json?cb=17954488137754 -> X-Cache: HIT   ETag "f7a7cab…"  4.37.9
   ```

   Identical ETag, cache HIT on the "cache-busted" URL. `Cache-Control:
   max-age=300` on the branch path is the ~5-minute window the user landed in.
   The stale side was reproduced directly: right after v4.37.9 was pushed,
   `.../main/latest.json` served **4.37.8** while `.../v4.37.9/latest.json`
   served **4.37.9**.

2. **The `latest/VERSION` cross-check is a no-op on the GitHub channel.**
   `https://raw.githubusercontent.com/admin-lagoonspace/cP-Defender/main/latest/VERSION`
   → **404** (measured). That path only exists on a CDN-shaped channel that
   extracts a `latest/` tree. So the one safety net built specifically to catch
   a cached manifest has never been able to fire on the channel that is now the
   only working one. The repo root `…/main/VERSION` **does** exist and read
   4.37.9 — same 300s cache, but a separately-keyed object. A tag-pinned path is
   immutable and cannot be stale at all: `.../v4.37.9/latest.json` served 4.37.9
   on first request.
   `https://api.github.com/repos/admin-lagoonspace/cP-Defender/tags?per_page=5`
   returned `v4.37.9` first, with `Cache-Control: s-maxage=60` and
   `X-RateLimit-Limit: 60` per hour unauthenticated.

### `upgrade.sh` is the unfixed twin, and today it would refuse outright

`upgrade.sh:96-105` is the exact pattern that was removed from `update.sh`:

```bash
for BASE in "${CHANNELS[@]}"; do
    info "Trying ${BASE}/latest.json"
    if MANIFEST="$(curl -fsSL --max-time 20 "${BASE}/latest.json" 2>/dev/null)"; then
        CHANNEL_USED="$BASE"; ok "Answered: ${BASE}"; break
    fi
```

First channel that answers wins. No cache-buster, no `latest/VERSION`
cross-check, no cross-channel comparison, no disagreement warning. Then
`upgrade.sh:121` `ok "Already on v${LATEST} — nothing to do."; exit 0` and
`upgrade.sh:126-131` which, when the chosen channel's version is **lower** than
the installed one, prints "Refusing to downgrade" and `exit 1`.

With the live state — CDN first in `CHANNELS` and serving 4.37.0, installed
4.37.7 — the documented upgrade path (`docs/KB-updating.md:62-86`) exits 1
without ever reaching `update.sh`. The frozen mirror does not merely fail to
help; it blocks upgrades.

### The CDN has been frozen at 4.37.0 since 4.37.0, from origin, not from a cache

Measured now:

```
https://serverscrub.com/releases/latest.json          -> 4.37.0  (plain and ?cb=, identical)
https://serverscrub.com/releases/latest/VERSION       -> 4.37.0  (HTTP 200)
https://serverscrub.com/releases/v4.37.8/latest.json  -> HTTP 404
```

Manifest and extracted tree agree, so this is not the nginx proxy cache that
caused the 4.35.1 incident. The sync has not successfully published since
4.37.0 — or has been publishing to a path nothing serves.

`scripts/cdn-sync.sh` already does a public read-back
(`_verify_public_manifest()`, :545-572) and already logs `WARNING:` with the
right diagnosis — **and then logs `published v${NEW_VER}` anyway (:574) and
`exit 0` (:586)**. Its docroot default is a hard-coded account path
(`cdn-sync.sh:49` `DOCROOT="${SG_DOCROOT:-/home/serversc/public_html/releases}"`),
overridden by the cron line that `scripts/cdn-setup.sh:96` writes from the
docroot it reads out of `/var/cpanel/userdata`. Which of those is in effect on
the box cannot be determined from here — see Open questions.

`scripts/publish.sh:433-486` asks the CDN exactly once, immediately after
pushing, i.e. at the moment it is guaranteed to still be serving the previous
version, and treats the answer as information:

```
info "CDN is live, serving ${_cdn_ver:-unknown} — it pulls ${VER} within ~10 min"
...
ok "Published ${TAG}. CDN will pick it up within ~10 min."
```

Exit 0. Nothing ever looks again. By contrast its git-side verification
(`publish.sh:390-430`) is strict and fails the release — the asymmetry is the
whole defect.

### Prod run detail that does not add up, and is not assumed anywhere below

The quoted output shows **one** channel probed (GitHub) and no "Channels
disagree" warning, which the shipped `update.sh` would have printed given a CDN
at 4.37.0. So either the paste is an excerpt, or the run had `SG_MANIFEST_URL`
pinned (`update.sh:227`, as the hint at `update.sh:626` suggests). Nothing in
the product sets that variable. Recorded as an open question; no requirement
below depends on which it was.

## Requirements

**Version resolution**

1. On a channel served from a mutable branch path, the version the updater acts
   on must come from a source that cannot be served stale. For the GitHub
   channel this means an immutable ref: the newest release tag, and the manifest
   read from that tag's path, carrying that tag's `url` and `sha256` so the
   download stays checksum-verified.
2. If the immutable source cannot be reached (API unreachable, rate-limited, no
   tags), the updater still works from the branch path — but the answer it
   produces from it is labelled, per requirement 4.
3. A channel's answer must be corroborated by a second, differently-addressed
   object before it can be reported as fact. `<channel>/latest/VERSION` stays
   the corroborator where it exists; where it 404s the updater must try the
   alternatives that do exist on that channel (repo-root `VERSION`, the
   tag-pinned manifest) and must not treat a 404 as "cross-check passed".
4. "Already up to date" is only printed when the newest version seen was
   corroborated by at least one source that cannot have been cached. When it was
   not, the output says so in plain words, naming the channel and that its answer
   may be up to 5 minutes old, and does not claim the install is current. Exit
   status for this case stays 0 (cron and the one-click updater both call it; a
   nonzero exit would read as a failure).
5. When channels disagree, the output names every channel and the version it
   gave, and says which one was used. (`update.sh` does this already; it must
   also hold for `upgrade.sh`.)

**`upgrade.sh`**

6. `upgrade.sh` queries every channel, compares versions across all of them, and
   uses the highest — never the first that answers. It cache-busts and
   cross-checks on the same terms as requirements 1-4.
7. `upgrade.sh` never refuses to proceed because one channel is behind. It only
   reports "already current", or refuses as a downgrade, on the basis of the
   highest corroborated version across all channels. A channel older than the
   installed version is reported as a lagging mirror and otherwise ignored.
8. When `upgrade.sh` cannot corroborate that the install is current, it fetches
   the updater and lets it decide rather than exiting 0 on its own reading.

**Panel**

9. `UpdateChecker` resolves versions on the same terms as requirements 1-4, and
   records enough state for the panel to distinguish three cases: a newer version
   is available; the install is confirmed current; the check could not be
   corroborated. The third must be visible in the dashboard — the existing
   `dash-update-error` element (`frontend/js/app.js:425-433`) already carries the
   unreachable-channel case and is the right place.
10. When a channel is behind the newest version seen, the panel surfaces it as a
    release-mirror problem. Nine releases went unmirrored with no indication
    anywhere a human looks.

**Release process**

11. `publish.sh` verifies the GitHub side through the tag, not the branch path,
    so its own check cannot be satisfied by a cached object.
12. After pushing, `publish.sh` waits for the mirror and then verifies it:
    `<CDN>/latest.json` serves the new version on a **plain** request (the URL
    installed servers actually use) and `<CDN>/v<version>/latest.json` returns
    200. Both must hold.
13. If requirement 12 is not satisfied within its time bound, `publish.sh` fails
    loudly and exits non-zero, stating plainly that the release is in git but
    **not** mirrored, and printing the force-sync and diagnosis commands. It must
    never print a sentence promising a mirror that it has not observed.
14. `cdn-sync.sh` must not log `published v<ver>` when its own public read-back
    disagreed. It reports the failure, and exits non-zero so a cron log and a
    caller can tell the two apart.
15. The fixed updater logic must take effect through the path the KB documents
    (`upgrade.sh` fetched fresh, which fetches `update.sh` fresh), so it works on
    the next run rather than one release later. No new update-time registration
    step is introduced; if one turns out to be needed it goes in
    `install.sh --register-only`, never in `update.sh` (the running copy is
    always the old one).

## Explicitly out of scope

- Back-filling `v4.37.1/` … `v4.37.9/` onto the CDN. `cdn-sync.sh` publishes only
  the newest build, so the historical folders will stay missing even once the
  sync is fixed. Not worth the prod risk; the rule is that the *current* release
  is mirrored.
- Changing the CDN's cache purge story. `_purge_manifest_cache()` is best-effort
  because the account is unprivileged; that is correct and stays.
- Removing `LEGACY_BASE`.
- Any write to the production box from this work. Diagnosis commands only.
- Authenticating to the GitHub API (a token on 132 customer servers is not worth
  the rate-limit headroom).
- `github.com/<repo>/releases/latest` as a source: measured today, it 302s to
  `/releases` rather than to a version, so there is no usable "latest release"
  object to read. Whether `gh release create` in `publish.sh:319` is actually
  producing release objects is a separate question (see Open questions).

## Failure behaviour

- GitHub API unreachable, 403 rate-limited, or returning nonsense: fall back to
  the branch path, mark the answer uncorroborated (requirement 4), keep going.
- No channel answers at all: unchanged behaviour — `update.sh` already prints
  DNS/HTTPS diagnostics and exits 1 (`update.sh:461-487`).
- Tag-pinned manifest 404s (tag pushed, file not in that tree): treat that
  channel as having no immutable source and fall back, labelled.
- `latest/VERSION` 404s: normal, not an error, must never abort the update — the
  `|| true` on `update.sh:400` exists because its absence once killed the updater
  on a live server. Keep it.
- A channel answers with a valid manifest for a *higher* version than the tree
  beside it: mid-sync, warn only, do not download from it.
- CDN unreachable during publish verification: distinguish "CDN not answering"
  from "CDN answering with the wrong version" in the failure text. Both fail the
  release; the fix is different.
- `publish.sh` failing at requirement 13 must leave git untouched and must not
  attempt to roll back the push.

## Resource bounds

- Version resolution adds at most **2** extra HTTP requests per channel per
  check (immutable-ref discovery + tag-pinned manifest), each with a **10s**
  timeout: worst case ~6 requests / ~20s wall for 3 channels. The existing retry
  budget is unchanged — full retries for the first channel, 1 attempt for the
  rest (`update.sh:380-383`).
- GitHub API: at most 1 request per update check. Scheduled checks run once a
  day; the unauthenticated limit is 60/hour/IP.
- `publish.sh` CDN wait: poll every **30s** for a maximum of **12 minutes** (24
  attempts), each request `--max-time 15`. The sync cron is `*/10`
  (`cdn-setup.sh:96`), so 12 minutes covers one full cycle plus the sync's own
  runtime. On success it stops at the first good read.
- No filesystem walking anywhere in this work.
- No new cron entries, no new background processes.

## Acceptance criteria

Demonstrated in docker (`docker/compose.yml`) against a stubbed channel —
`UpdateChecker::setFetcherForTests()` (:67) already provides the seam; the shell
scripts take `SG_CDN_BASE` / `SG_MANIFEST_URL` / `SG_RELEASES_REPO`.

1. **The reported incident.** Channel serves manifest 4.37.7 from the branch path
   while the immutable ref holds 4.37.8; install is 4.37.7. The updater resolves
   4.37.8, downloads it, and the checksum verifies. It does not print "Already up
   to date".
2. **No immutable source available.** Same stale branch manifest, immutable
   lookup fails. Output does **not** assert the install is current; it states
   that the only answer came from a cacheable URL and names the channel. Exit 0.
3. **Genuinely current.** All sources agree with the installed version. Output
   says "Already up to date" once, with no stale-evidence hedge and no
   disagreement warning.
4. **`latest/VERSION` 404.** A channel with no `latest/` tree completes a check
   with no error, no abort, and does not report the cross-check as satisfied.
5. **Lagging mirror does not block.** CDN channel at 4.37.0, GitHub at 4.37.9,
   installed 4.37.7. `upgrade.sh` reports both channel versions, says the CDN is
   behind, offers 4.37.9, and hands over to the updater. It does **not** print
   "Refusing to downgrade" and does **not** exit 1. This exact combination fails
   on 4.37.9's code.
6. **`upgrade.sh` ordering is irrelevant.** The result of criterion 5 is
   unchanged when the stale channel is listed first and when it is listed last.
7. **Panel, three states.** With the dashboard driven by a stubbed fetcher:
   newer-version state shows the banner; confirmed-current shows no banner and no
   warning; uncorroborated shows a visible notice and no clean "up to date"
   claim. Lagging-mirror state shows a mirror warning.
8. **Publish fails when the mirror does not appear.** `publish.sh` run against a
   stub CDN that never serves the new version: exits non-zero, text says the
   release is in git and not mirrored, and prints the force-sync command. No
   output anywhere in the run promises a mirror.
9. **Publish passes when it does appear.** Stub CDN starts serving the new
   version and `v<version>/latest.json` on the third poll: exits 0, reports the
   mirror as verified, having taken under the 12-minute bound.
10. **Partial mirror fails.** `latest.json` serves the new version but
    `v<version>/latest.json` 404s: non-zero. The `v<version>/` folder is half the
    user's definition of done.
11. **`cdn-sync.sh` is honest.** With a read-back that disagrees, the run does not
    log `published v<ver>` and exits non-zero. With a read-back that agrees,
    unchanged behaviour and exit 0.
12. **Nothing regressed on the download path.** An update whose manifest `sha256`
    does not match the downloaded zip is still refused; `--version`/`--url`
    overrides still work and still warn that integrity is unverified.
13. `scripts/check-version-bump.sh` agrees with a **Z** bump for this batch.

## Open questions

**1. Root cause of the CDN freeze (blocking for the prod half, not for the code
half).** `host.lws-s1.com` is not reachable from this environment — no SSH key,
confirmed on the previous spec. The requirements above make a failed mirror
impossible to miss; they cannot make it publish. The standing hypothesis is
unconfirmed: `cdn-sync.sh` writing to a hard-coded
`/home/serversc/public_html/releases` that stopped being the served docroot
(addon domain / subdomain / docroot move), publishing successfully to disk and
exiting 0 the whole time.

Read-only, bounded, as root on host.lws-s1.com:

```bash
# 1. Is the sync still scheduled, and what docroot does the cron pass it?
crontab -l -u serversc | grep -n -i 'cdn\|sync'

# 2. What has it been saying? (tail only; this log is months long)
tail -n 120 /home/serversc/logs/cdn-sync.log
grep -nE 'ERROR|WARNING|published|cannot|Permission' /home/serversc/logs/cdn-sync.log | tail -40

# 3. What docroot does cPanel itself say serves serverscrub.com?
grep -hE '^(documentroot|main_domain|servername):' /var/cpanel/userdata/serversc/* 2>/dev/null | sort -u
ls -1 /var/cpanel/userdata/serversc/

# 4. What is actually on disk at the hard-coded path?
ls -l /home/serversc/public_html/releases/ | head -20
head -c 200 /home/serversc/public_html/releases/latest.json; echo
cat /home/serversc/public_html/releases/latest/VERSION 2>/dev/null

# 5. Was anything written anywhere else recently? (one account tree, maxdepth 4, metadata only)
find /home/serversc -maxdepth 4 -name latest.json -printf '%TY-%Tm-%Td %p\n' 2>/dev/null | sort | tail -20

# 6. Which version of the sync script is on the box? (it is hand-copied)
ls -l /home/serversc/bin/cdn-sync.sh
grep -nE 'SG_DOCROOT=|PUBLIC_BASE|_verify_public_manifest' /home/serversc/bin/cdn-sync.sh | head

# 7. Is it wedged on a lock, or out of quota?
ls -l /home/serversc/.sg-cdn/ 2>/dev/null
quota -s -u serversc 2>/dev/null

# 8. The product's own answer, which changes nothing:
bash /home/serversc/bin/cdn-setup.sh --check
```

Steps 1-7 only read. Step 8 is `cdn-setup.sh`'s documented verify-only mode
(`cdn-setup.sh:26`). Nothing here writes, deletes, or restarts anything. Once
the cause is known, the force-sync printed at `publish.sh:458` is the fix to run
— that one does write, to the CDN docroot only.

**2. Which command produced the quoted prod output.** One channel probed, no
disagreement warning; see "Prod run detail" above. If `SG_MANIFEST_URL` was
pinned in that shell, requirement 4's hedge is what the operator will see next
time, which is the desired outcome either way. Re-running
`bash /home/upgrade.sh --check` and pasting the whole output settles it.

**3. Is `gh release create` (`publish.sh:319`) producing GitHub Release
objects?** `github.com/admin-lagoonspace/cP-Defender/releases/latest` 302s to
`/releases`, which is what a repo with no published releases does. Out of scope
here — flagged because, if true, it is another release-time claim nobody has
checked, and it would make the releases API unusable as the immutable source
(tags are used instead, and those do exist).

**4. Who watches the mirror between releases?** Requirements 12-14 catch a
failure at publish time and requirement 10 shows it in the panel. Neither
notices a mirror that rots on a Tuesday. Deliberately not specified; raise
separately if the user wants a monitor.

---

## Implementation (Wasooli, 2026-11-23)

`python scripts/preflight.py` passes, including the docker Linux stage
(5,516 assertions). `docker/entrypoint.sh` runs `php tests/run.php`, which
globs `tests/test_*.py`, so the new shell-executing tests ran under real bash
and python3 on Linux as well as locally. Changelog entry is under
`## [Unreleased]`; `VERSION`, `latest.json` and `config.php` untouched.

Defects 1 and 2 were NOT re-implemented: the all-channels loop, the `?cb=`
helper and the `latest/VERSION` override are the shipped code and were left in
place. What was added sits beside them.

### Per requirement

**1-2. Immutable version source.** `_immutable_channel_version()` and
`_pinned_manifest_url()` in `update.sh`; the same pair in `upgrade.sh` as
`_immutable_channel_version` / `_pinned_prefix`; and
`UpdateChecker::immutableChannelVersion()` / `pinnedManifestUrl()`. Newest tag
from `api.github.com/repos/<repo>/tags?per_page=10`, taken **highest by
version, not first in the list**, then the manifest committed under that tag,
which carries that tag's `url` and `sha256` so the download stays
checksum-verified. Unreachable, rate-limited or nonsense: fall back to the
branch answer, labelled. One API request per check.

A real bug found while doing this, and fixed: the shipped per-version fetch
built `${BASE}/v<ver>/latest.json`, which on the GitHub channel is
`.../<repo>/main/v4.37.8/latest.json` -- a 404, always. On raw a version is a
git ref and REPLACES the branch component. The override block meant to rescue a
cached manifest could therefore never have found a pinned manifest on that
channel even if `latest/VERSION` had existed there.

**3. Corroboration, and a 404 is not a pass.** `channelManifest()` now tries
repo-root `VERSION` when `latest/VERSION` 404s, and marks that reading as a
separately-keyed *second opinion* rather than a confirmation -- it sits behind
the same `max-age=300`.

Only two things set corroborated, and the distinction matters — getting it
wrong the first time was the blocker in
`docs/findings/2026-11-23-stale-channel-read-and-frozen-cdn.md`:

1. a pinned manifest **for a version that an immutable source named as
   current** — the tag list, or `latest/VERSION`;
2. `latest/VERSION` agreeing with the manifest beside it (the one place `?cb=`
   was measured to work).

A pinned manifest for the version the branch path already handed us proves only
that the version exists, never that it is current, and every released version
has that path. Substituting the branch answer there made the check unfalsifiable
and printed "no cache can stale it" over a stale read. The `|| true` on the
`latest/VERSION` fetch is untouched.

**4. The hedge.** `update.sh` prints "Already up to date" only when
`VER_IMMUTABLE=true`, and names the url that confirmed it. Otherwise it says
which channel answered, that the reading may be up to 5 minutes old, and that
this is **not** a confirmation that the install is current -- then exits 0.

**5.** Channel-by-channel report and lagging-mirror warning added to
`upgrade.sh`; `update.sh` already had the disagreement warning.

**6-8. `upgrade.sh`.** The first-answer loop is gone: every channel, highest
wins, cache-busted, `latest/VERSION` cross-checked, tag-corroborated. It
refuses as a downgrade only when the highest **corroborated** version anywhere
is older than the install; uncorroborated, it hands over to `update.sh` (which
has the downgrade guard and the rollback) rather than deciding on a reading it
could not confirm. Verified against HEAD's own code: with CDN 4.37.0, GitHub
4.37.9 and 4.37.7 installed, the old code prints "Refusing to downgrade" and
exits 1; the new code resolves 4.37.9 and hands over, in either channel order.

Also changed, and worth a look: the updater is fetched from the
**version-pinned** tree first (`.../<repo>/v4.37.9/update.sh`), then the
channel roots, then `<channel>/latest/`. Fetching `${CDN}/update.sh` from a
mirror frozen at 4.37.0 would have handed the 4.37.0 updater to a 4.37.9
upgrade, which is requirement 15 failing quietly.

**9-10. Panel.** `update_corroborated`, `update_version_source`,
`update_uncorroborated` and `update_mirror_lag` are persisted;
`getCachedStatus()` returns `corroborated`, `version_source`,
`uncorroborated_note`, `mirror_lag`. `checkForUpdates()` now returns
`getCachedStatus()` so the two cannot disagree about a field.

`#dash-update-error` **did not exist**. `app.js` has written to it since the
unreachable-channel fix and no element with that id was anywhere in
`index.html`, so the unreachable-channel case has never been visible either.
Added, plus `#dash-mirror-lag`. `update_check_error` is left strictly for
"could not reach a channel", because `scheduler.php:394` returns early and
SKIPS the automatic update when it is non-empty, and an uncorroborated check is
not a reason to stop applying an update that was found.

**11-13. `publish.sh`.** The GitHub side is verified through
`.../<repo>/<TAG>/latest.json` (6 attempts, 10s apart). Then the CDN is
**waited for**: every 30s, up to 24 times (`SG_CDN_POLL_SECS` /
`SG_CDN_POLL_TRIES` to shorten it in a test), requiring `latest.json` to serve
the new version on a **plain** request AND `v<version>/latest.json` to return
200. Failure is non-zero, says the release is in git and not mirrored,
distinguishes "not answering" from "wrong version", and prints the force-sync
plus the read-only diagnosis commands. "CDN will pick it up" is gone from the
file; the only remaining `Published` line is inside the verified branch.
Nothing rolls back git.

**14. `cdn-sync.sh`.** `_verify_public_manifest || true` is now a real branch.
`published v<ver>` is logged only when the read-back agreed; otherwise it logs
that it did **not** publish, skips the retention prune (deleting old builds
while it is unclear what the public url serves could remove the only version
customers can still reach) and exits 1.

**15.** No new registration step. `docs/KB-updating.md` step 1 already
re-fetches `upgrade.sh` from the channel on every run, and that fresh copy now
fetches `update.sh` from the version-pinned path, so the fix applies on the
next run rather than one release later. Added a KB note that the `main/` path
itself can be 5 minutes stale, with the tag-pinned `curl` as the certain
alternative.

### Tests

* `tests/test_update_corroboration.py` -- 63 assertions. Executes the real
  `_pinned_manifest_url`, `_immutable_channel_version`, the corroboration block
  and the up-to-date gate out of `update.sh`, plus the whole decision slab out
  of `upgrade.sh`, against a stubbed curl. Acceptance criteria 1-6.
* `tests/test_release_mirror_verified.py` -- 29 assertions. Executes the CDN
  wait, the tag verification and `cdn-sync.sh`'s read-back branch. Criteria
  8-11, including the mirror appearing on the third poll and the partial
  mirror.
* `tests/test_update_corroboration_panel.php` -- the `UpdateChecker` fetcher
  seam and the three panel states. Criterion 7.

Criterion 12 (download path unchanged) and 13 (`check-version-bump.sh`) rest on
the existing suite: nothing in the download, `--version` or `--url` paths was
touched, and `check-version-bump.sh` reports "VERSION unchanged -- nothing to
check", which is correct mid-week. No commit subject in this batch begins with
`feat`, so a Z bump at the cut will not trip its feature heuristic.

### Three test assertions were changed. Not quietly -- review these first

1. `tests/test_autoupdate.php` asserted `strpos($uc, 'api.github.com') === false`.
   It was written to forbid the **Releases** API (which `publish.sh` can skip
   creating, so it can lag behind the manifest), but it banned the host, and
   with it the only immutable "what is newest" reading the GitHub channel has.
   Narrowed: `/releases` under `api.github.com` is still forbidden by name,
   `/tags?per_page=` is now required. If you disagree, the consequence is that
   the panel can only ever corroborate the version it was already told, and
   cannot discover a release that a cache is hiding.
2. `tests/test_cron_and_cdn.php` pinned the closing line
   `Installs will use the GitHub mirror (CDN is not serving)`. That line closes
   an unmirrored release with exit 0, which requirement 13 reverses. Replaced
   with: the failure text exists, `CDN will pick it up` appears nowhere in the
   script, and the only `Published` line is the verified one.
3. `tests/test_cdn_manifest_cache.py` located the read-back by the literal
   `_verify_public_manifest || true`. That `|| true` is exactly what
   requirement 14 removes. The anchor moved to `if _verify_public_manifest; then`
   and the ordering assertion it supports is unchanged.

### Not done, and why

* **The CDN freeze itself is not fixed.** Root cause needs the production box,
  and `host.lws-s1.com` is not reachable from here. Open question 1's eight
  read-only commands stand as written; nothing in this change assumes a cause.
  What this change does is make a failed mirror impossible to miss next time.
* Back-filling `v4.37.1` ... `v4.37.9` onto the CDN: out of scope, as
  specified.
* Open questions 2 and 3 are untouched. 3 (`gh release create` possibly not
  producing Release objects) deserves its own spec -- it is another
  release-time claim nobody has checked.

### Where to look hardest

* `upgrade.sh` is the file with the most new bash under `set -euo pipefail`.
  The AND-list short-circuits (`[[ ... ]] && cmd`) do **not** trip `set -e` --
  verified in this shell -- but that is the class of bug that would exit 1
  mid-run with no message.
* The request bound: worst case one tags-API request plus up to three
  pinned-manifest fetches per check, 10s each. The spec allows ~6 requests and
  ~20s.
* `publish.sh` now has two new ways to fail a release that is correct in git. A
  transient raw.githubusercontent.com or CDN outage after a successful push
  fails the run; nothing is rolled back, but Gabbar sees a red release and has
  to re-verify by hand.
* Whether `check_error` vs `uncorroborated_note` is the right split, given that
  `scheduler.php:394` returns early on a non-empty `update_check_error`.

### Second pass (Wasooli, 2026-11-23)

Shakaal returned FAIL — one blocker, two majors. All three fixed; the write-up
is at the end of `docs/findings/2026-11-23-stale-channel-read-and-frozen-cdn.md`.
Briefly: corroboration could not fail and has been made falsifiable; a release
blocked at the mirror gate can now be finished by re-running `publish.sh`,
which recognises its own tag on its own commit as a resume; and an unreadable
installed `VERSION` no longer makes `upgrade.sh` blame the release mirrors.
