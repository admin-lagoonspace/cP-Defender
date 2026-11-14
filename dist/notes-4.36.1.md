# ServerScrub 4.36.1

[4.36.1] - 2026-11-14

### Fixed

- **The v4.36.0 release was invisible to every installed copy, and so was
  every release before it for a while.** After v4.36.0 was published and the
  CDN sync ran, `https://serverscrub.com/releases/latest.json` served 4.35.1,
  with `Server: nginx` and a `Last-Modified` of the 4.35.1 publish six days
  earlier. Reproduced twice, back to back:

  | request | answer |
  | --- | --- |
  | plain `GET` | 4.35.1 |
  | `-H 'Cache-Control: no-cache' -H 'Pragma: no-cache'` | 4.35.1 |
  | `?cb=<timestamp>` (a cache key it had not seen) | **4.36.0** |

  The origin files were correct the whole time: `v4.36.0/latest.json` and
  `latest/VERSION` both read 4.36.0. cPanel's nginx reverse-proxy cache was
  holding the old object and ignoring client revalidation, so only a different
  url missed it. The same nginx layer is what served stale WAF-event JSON at
  4.35.1 — this cache is a known hazard of this deployment, not a surprise.

  Three defects, all fixed:

  - `update.sh` treated the `latest/VERSION` cross-check as informational. It
    read 4.36.0, printed "channel mid-sync", and went ahead with the cached
    4.35.1 manifest — so `update.sh --yes` compared 4.35.1 against the
    installed 4.35.1 and reported "Already up to date". The correct answer was
    in hand and being discarded. `latest/VERSION` is now authoritative when it
    is NEWER than the manifest (and only then — a manifest ahead of the tree is
    a sync still extracting, and there is nothing to download there). The
    per-version manifest at `v<ver>/latest.json` is then fetched for that
    build's url and sha256, so the download stays checksum-verified; a url
    requested about once ever cannot be in any cache. The tree reading is also
    kept from channels whose manifest LOSES the version comparison — the CDN
    can serve a stale manifest and a current tree at the same time, which is
    exactly what it did.

  - `backend/lib/UpdateChecker.php` had the same bug from the panel side, plus
    the original first-answer bug: `fetchManifest()` returned the first channel
    that replied, and `httpGet()` sent only `User-Agent` and `Accept`.
    Reproduced with the product's exact headers: 4.35.1. The in-panel update
    notification would not have fired for any operator. It now polls every
    channel and takes the newest, cross-checks `latest/VERSION` the same way
    `update.sh` does, and reports a version with no url or checksum rather
    than presenting a stale manifest's hash as verification of a different
    build.

  - `scripts/cdn-sync.sh` replaced `${DOCROOT}/latest.json` and never touched
    the cache in front of it. This was never specific to 4.36.0: EVERY release
    has had a window in which the canonical manifest advertised the previous
    version, with nothing in any log to say so. That is the likely source of
    the long-standing impression that installs "silently fell back to the
    GitHub mirror" — they were not falling back, they were being told the old
    version was current. The sync now writes a cache-control block into the
    docroot's `.htaccess` marking `latest.json`, `VERSION` and `get.sh`
    uncacheable (the zips stay cached hard — the version is in the filename),
    attempts a purge, and reads the PUBLIC url back, logging a warning when it
    disagrees with what was just published instead of reporting success. The
    `.htaccess` is written as a marked block appended to whatever is already
    there, never as an overwrite: that docroot is shared with the website.

  Every version-bearing fetch in both clients now carries a single-use query
  parameter, since that is the only thing demonstrated to miss this cache.

  `scripts/cdn-sync.sh` runs from `/home/serversc/bin/cdn-sync.sh` on the
  production server and **must be copied there by hand** — the repo copy is the
  source of truth and nothing deploys it.

- **38 consecutive releases created no git tag at all, and each one reported
  success.** Tagging was never a step in `scripts/publish.sh`. The tag existed
  only as a side effect of creating the GitHub Release, and that step is
  skipped when neither `gh` nor `GH_TOKEN` is present — which is the permanent
  state of the release machine. So every release took the `else` branch,
  printed a warning worded as if only the Release *page* needed making by
  hand, and silently left no tag.

  `v4.25.1` through `v4.35.1` — 38 releases — pushed a release commit and no
  tag, locally and on origin. `v4.36.0` exists only because it was tagged by
  hand on 2026-11-13.

  Tagging is now step 4b: annotated, unconditional, before the Release step,
  and the release fails if it does not end with that tag in place. The
  no-`gh` warning now states separately that the tag and the commit are
  pushed and that the Release page alone is outstanding, so the two can no
  longer be read as one item. The dirty-tree gate moved ahead of the push, so
  a refusal no longer leaves a pushed commit behind.

- **The version bump gate passed without testing the release.**
  `check-version-bump.sh` takes the newest tag as its baseline, so while tags
  were missing it compared the wrong range. For the v4.36.0 release it
  compared `4.25.0 -> 4.36.0`, classified 85 commits spanning eleven
  releases, found `feat` subjects in pre-4.35.1 history, and printed
  `consistent`. A passing gate that had not looked at the batch is worse than
  no gate.

  It now tests its own baseline first and refuses to run when the baseline is
  not trustworthy: any untagged `Release vX.Y.Z` commit after the newest tag,
  or a newest tag more than one minor behind `VERSION`. Both are listed
  explicitly rather than folded into the old one-line "a release may have been
  missed" warning, which did print for v4.36.0 and was passed over.

- **The tag baseline was repaired, and only the baseline.** `v4.35.1` is now
  an annotated tag on `8552261`, dated to that commit rather than to the day
  it was created, and pushed. The 37 older missing tags (`v4.25.1` ..
  `v4.35.0`) were deliberately left alone: the version gate needs a baseline
  it can trust, not a complete tag history, and 37 cosmetic tags pushed to a
  published repo buy nothing. `docs/findings/2026-11-14-missing-release-tags.md`
  records what is missing and the commit each one would point at, so the
  decision can be revisited without re-deriving it.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
