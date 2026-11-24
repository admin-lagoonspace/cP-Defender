# ServerScrub 4.37.10

[4.37.10] - 2026-11-24

### Fixed

- **"Already up to date — v4.37.7", printed minutes after v4.37.8 was
  published.** The operator upgraded production right after the release and was
  told the server was current. The claim was produced honestly from evidence
  that was five minutes stale, and nothing in the output hinted that it might
  be. On a security product a confident wrong negative about patch level is the
  same class of defect as the WAF reporting `action='block'` while blocking
  nothing.

  Both mitigations that exist for exactly this were already in the copy that
  ran — `git diff v4.37.7 HEAD -- update.sh` was empty — and both fail on the
  GitHub channel, measured 2026-11-23:

  * `?cb=` does not defeat `raw.githubusercontent.com`'s edge cache. Same
    object, two consecutive requests: plain → `X-Cache: MISS`, `?cb=…` →
    `X-Cache: HIT`, identical ETag. The branch path carries `max-age=300`,
    which is the five-minute window the operator landed in.
  * `…/main/latest/VERSION` is a **404** — there is no `latest/` tree in the
    repo — so the cross-check written specifically to catch a cached manifest
    has never been able to fire on the channel that is now the only working
    one. A 404 was being treated as nothing to disagree with, which reads
    downstream as a cross-check that passed.

  The version now comes from a path that NAMES it and so cannot be served
  stale: the newest release tag, and the manifest committed under that tag,
  carrying that tag's `url` and `sha256` so the download stays
  checksum-verified. When no such path can be reached the branch answer still
  stands — a firewalled server must still be able to update — but it is
  labelled, and "Already up to date" is not printed: the output says which
  channel answered, that the answer may be up to five minutes old, and that
  this is not a confirmation that the install is current. Exit status stays 0,
  because cron and the one-click updater both read it. `update.sh`,
  `upgrade.sh` and `UpdateChecker` all resolve on these terms.

  The per-version manifest fetch was also asking for the wrong path on this
  channel: on raw, a version is a git ref and REPLACES the branch component,
  so `…/<repo>/main/v4.37.8/latest.json` is a 404 and always was.

  The unconfirmed case says its one thing and stops: what is true first, the
  channel and the staleness bound with it, three lines. The cache measurements
  behind `--verbose` (or `SG_VERBOSE=1`), and the two by-hand `curl` commands
  only when a terminal is attached. It was six warning lines plus two commands
  on every daily cron run of a server where nothing was wrong — and on a
  firewalled server, where nothing can be — with the operative sentence last.
  A block that long and that frequent is how an operator learns to skip the
  one that will matter.

  And the confirmed case now states the reason that actually applies to the
  source it used. It said "(addressed by version; no cache can stale it)" for
  every source, including `latest/VERSION`, which is a mutable path whose cache
  purge is explicitly best-effort. The version was right and the stated reason
  was not, which is the defect this whole change is about.

- **A mirror frozen since September blocked the documented upgrade path
  outright.** `upgrade.sh` took the first channel that answered, with no cache
  buster and no cross-check — the pattern removed from `update.sh` at v4.28.10
  and left here. With the CDN first in the channel list and serving 4.37.0
  against an installed 4.37.7, it printed "Refusing to downgrade" and exited 1
  **without ever reaching `update.sh`**, which would have found 4.37.9 on
  GitHub. It now asks every channel, takes the highest, names every channel and
  the version it gave, reports a channel behind the others as a stalled mirror,
  and only refuses as a downgrade on the basis of the highest **corroborated**
  version anywhere. It also fetches the updater from the version-pinned tree
  that ships with the release being installed, rather than from a mirror
  frozen three weeks earlier.

- **Nine releases were reported as mirrored when none of them were.** 4.37.1
  through 4.37.9 are in git; the CDN has served 4.37.0 since 4.37.0, from
  origin and not from a cache (`latest.json` and `latest/VERSION` agree,
  `v4.37.8/latest.json` 404s). Nobody found out for a month because both ends
  of the release process reported success:

  * `cdn-sync.sh` already read the public url back, already reached the right
    diagnosis and already logged `WARNING:` — and then logged
    `published v<ver>` anyway and exited 0. A failed read-back is now a failed
    publish: it says it did not publish, skips the retention prune rather than
    deleting builds in a state nobody has verified, and exits non-zero.
  * `publish.sh` asked the CDN exactly once, immediately after the push — the
    one moment it is guaranteed to still be serving the previous version — and
    printed "it pulls <ver> within ~10 min". It now waits for the mirror (every
    30s for up to 12 minutes, one full `*/10` sync cycle plus runtime) and
    requires both halves of done: `latest.json` serving the new version on a
    **plain** request, and `v<version>/latest.json` returning 200. If either
    fails the release fails, non-zero, stating that it is in git and not
    mirrored and printing the force-sync and read-only diagnosis commands. No
    sentence anywhere now promises a mirror that has not been observed. Its
    GitHub-side check reads the tag path too, so it cannot be satisfied by a
    cached copy of the previous release.

- **A release blocked at the mirror gate could not be finished.** The CDN check
  runs after the tag is pushed — a mirror cannot be verified before the thing it
  mirrors is on origin — so failing it left the tag on origin, and the re-run
  then died on the "tag already exists on origin" guard. The two routes that
  guard offered were burning a version number or deleting a pushed tag, and
  `update.sh` now resolves versions **from** tags, so deleting one withdraws
  that release from every server in the field.

  `publish.sh` now recognises its own tag — same object, same commit — as a
  **resume**, and a resume **does not rebuild**. The release artifacts are
  committed and `make-release.sh` is not byte-reproducible (the zip records
  file mtimes), so a rebuild changes the zip, the `sha256` in `latest.json`
  derived from it, and `dist/latest.json` — which would either refuse the run
  or publish a different build under a tag that describes the first one. The
  committed artifacts at the tag *are* the release: a resume verifies the tag,
  the GitHub channel and the mirror, and nothing else. It leaves an existing
  Release page alone, and refuses if the committed zip is not on disk, because
  then this checkout is not the tree that was released.

  The mirror failure text ends with the exact command to finish the release and
  says not to bump or delete anything. A tag of that name on any other commit
  is still a hard refusal. If the tree is dirty during a resume the run stops
  before anything is pushed, and the recovery it prints is
  `git reset --hard HEAD` — not `git checkout -- <paths>`, which restores the
  working tree *from the index* and so exits 0 having changed nothing when the
  index is the dirty side.

- **`upgrade.sh` blamed the release mirrors when it could not read the installed
  version.** `sort -V` puts the literal string `unknown` above every real
  version, so a missing or unreadable `VERSION` — the broken install the script
  exists to repair — took the "every channel is behind this install" branch and
  told the operator a mirror's sync had stalled, four lines after correctly
  reporting the newest version. An unreadable installed version is now handled
  before any comparison: it says what it could not read and hands over to the
  updater.

- **The dashboard had no element to show a failed update check in.** `app.js`
  has written to `#dash-update-error` since the unreachable-channel fix and no
  element with that id existed anywhere in `index.html`, so a server that had
  not reached a release channel for weeks looked identical to a patched one.
  The element now exists, and it carries the third state as well: a check that
  could not be corroborated is no longer rounded down to a clean dot. A second
  element reports a release channel that is behind the newest version seen,
  which is where nine unmirrored releases would have surfaced.

- **`publish.sh` refused to run from a git worktree.** The check was
  `[[ -d .git ]]`, and in a worktree `.git` is a *file* holding
  `gitdir: …` rather than a directory, so the script died on its fourth
  line with "Not a git repo" about a directory that is one, having built
  nothing. This release is the first cut from a worktree, which is itself the
  safer way to do it: the main checkout held three unrelated workstreams, and
  the staging step would have swept them into a customer release. The check is
  now `git rev-parse --is-inside-work-tree` plus a comparison of the toplevel
  against the script's own root — the second half matters, because being
  *inside* a repository is also true of a copy of this script sitting in some
  other project's subdirectory, and this script stages and commits.

### Known limitations in this release

- **The CDN freeze itself is not fixed.** serverscrub.com/releases still serves
  4.37.0. The production host could not be reached while this was built, and
  the read-only commands that would show why the mirror stopped (open question
  1 in the spec) have still not been run. This release makes the next failed
  mirror impossible to miss and lets a blocked publish be finished; it cannot
  make the mirror publish. Until the mirror is repaired, servers update from
  GitHub, which this release now reads correctly.
- **A firewalled server will always see "could not confirm".** A server that
  can reach neither the GitHub tags API nor the CDN's `latest/VERSION` has no
  path that names a version, so it now always shows the "not confirmed" note
  instead of "Already up to date". That is deliberate: it is the honest answer
  for that server. It still updates, and the exit status is still 0.
- **cPanel-mode integration is untested.** All verification ran on a
  standalone install: cpsrvd, the WHM AppConfig registration, LiveAPI and the
  CGI wrappers were not exercised.
- **`publish.sh` has not been run against the real origin or the real GitHub
  API.** Its new mirror wait and resume were tested end to end against a local
  bare repository with the CDN stubbed. This release is its first real run, and
  is expected to push the tag and then stop at the mirror gate while the CDN is
  still frozen.
- **No real ModSecurity, Exim or ClamAV** in the test environment, and 8 seeded
  accounts rather than a full server.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
