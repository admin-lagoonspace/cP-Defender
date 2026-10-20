# ServerScrub 4.7.0

[4.7.0] - 2026-10-20

Unattended updating. ServerScrub already checked for new versions daily and
cached the result; nothing installed anything. A security product that is
itself months out of date behind an "update available" badge nobody reads is
the wrong default, so updates now install themselves.

### Added

- **Automatic updates, on by default** (`Updater.php`). `update.sh` already
  knew how to apply a release safely â€” verify the SHA-256, back up, rsync,
  restart, roll back if the new version does not answer. What was missing was
  the decision to run it. That decision is the whole of the risk here, because
  it replaces the security software on a production server with nobody
  watching, so it refuses in five cases and **states the reason in words**:
  - a **major** version (X is reserved for a breaking change â€” opt in with
    "Include major versions" if you want them)
  - a **scan** is running (`update.sh` rsyncs over the install directory with
    `--delete`, which would pull the scanner's code out from under a worker)
  - a **backup** is running
  - an update is **already running** â€” and a state file claiming to run but
    untouched for 15 minutes is treated as a crash, not as slow, so one failed
    attempt cannot block that server for ever
  - after a failure it **backs off** 1h â†’ 2h â†’ 4h, and after three it stops and
    names the log to read. Each attempt rsyncs over a live install directory; a
    daily retry of an update that cannot work is not harmless.

- **A `wpdbscan`-style `autoupdate` scheduler task**, daily at 04:30 â€” after
  the 03:30 database sweep and 04:00 CMS discovery, so a service restart does
  not land on top of either. It reconciles the *previous* run first, because
  the updater rsyncs over its own code and cannot be relied on to record its
  own outcome.

- **An Updates panel** in Settings: installed vs available, when it last
  checked, when it last succeeded, the toggles, and â€” the important line â€” what
  it will do next, verbatim from the server. "Automatic updates: on" must never
  quietly mean "blocked by something".

- **`upgrade.sh`**, for upgrading a server by hand. It fetches the *current*
  `update.sh` from the release channel before handing over, because the copy on
  a server is always the one that shipped with the version already installed â€”
  so a fix to the updater can never reach the servers that need it. It
  downloads nothing else and replaces nothing itself; `update.sh` keeps that
  job and its rollback. Refuses to downgrade, warns on a major version, and
  rejects a downloaded updater that is not valid shell.

### Fixed

- **The update checker and the updater read different sources, and disagreed.**
  `UpdateChecker` asked the GitHub Releases API; `update.sh` downloads
  `latest.json` from the release channel. `publish.sh` skips creating the
  GitHub Release when the machine doing the release has no `gh` and no
  `GH_TOKEN` â€” **which is exactly how 4.6.0 shipped** â€” so the API still
  described 4.5.1 while the manifest, the CDN and the committed zip all
  described 4.6.0.

  The panel would have reported "up to date" on a server a version behind, and
  automatic updating, which asks this class whether to run, **would never have
  fired at all**. Both now read `latest.json`, CDN first and GitHub raw second,
  in the same order. The Releases API is not consulted even as a fallback: a
  fallback to a source that can lag would reintroduce the same disagreement
  under a rarer condition, which is worse than not having one.

- **An unreachable release channel no longer reads as "up to date."** A failed
  check kept the previous `checked_at`, so the dashboard showed a recent
  successful check on a server that had not reached the channel in weeks â€”
  which is the state an unpatched install sits in, looking healthy throughout.
  The error is now stored and shown.

- **`POST update/run` existed in the API and was called by nothing.** The
  "update" button showed a toast telling the operator to SSH in and run
  `update.sh` â€” the exact script that route starts, detached, with locking. The
  button now works, with progress and an honest outcome: the API goes away
  mid-update, so a failed poll is expected and only the state file decides
  whether it worked.

- **Two owners for update checking.** `install.sh` wrote a second cron entry at
  08:00 that only cached a notice, while the scheduler's task checks and
  installs. New installs get one entry; `update.sh` removes the duplicate from
  existing ones, after copying the cron file aside, matching only the line this
  project wrote.

### Changed

- `publish.sh` now commits the source the release zip was built from.
  `STAGE_LIST` is release metadata and has never covered `backend/lib`,
  `backend/daemon`, `frontend/js` or `tests`, while `make-release.sh` packages
  from the working tree â€” so 4.6.0 shipped a zip containing two new library
  modules and committed a repository without them. The tag described something
  other than what customers received, and nothing reported the difference.

### Notes

- `tests/test_autoupdate.php` is almost entirely refusals: the one "yes" is a
  line, and the rest is the conditions under which this must not touch a live
  server. It also asserts that `UpdateChecker` and `update.sh` read the same
  manifest and know the same two channels, which is the defect above expressed
  as a test.
- Automatic updates can be switched off in Settings â†’ Updates. Turning them off
  does not disable the daily check, so the panel still tells you what is
  available.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
