# ServerScrub 4.36.3

[4.36.3] - 2026-11-15

### Fixed
- Quarantining a threat from the UI now makes the file inert before it moves it,
  and records who owned it. Both steps existed, but only on the automatic path
  (`handleByPolicy`), so a scheduled scan did the right thing and the Quarantine
  button did not. Two consequences, and the second is the one that bites on a
  hosting server: the file stayed executable by the web server until the move
  completed — microseconds for a `rename()`, but `rename()` is not what runs
  when quarantine lives on another filesystem, and `install.sh` deliberately
  relocates quarantine to `/home` for exactly that reason, so the copy path is
  the normal path and the window was as long as the copy took. And nothing wrote
  `orig_uid`/`orig_gid`/`prev_mode`, so a restore had to infer the owner from the
  destination directory and fall back to mode `0644` — the state the 154,323
  files from job 12457 came back in, and the reason those columns exist. Both
  now happen inside `Scanner::quarantine()`, so every caller gets them; a failed
  move puts the original mode back rather than leaving an unreadable file that
  is still infected; `prev_mode` is never recorded as `0000`; and the `0600` on
  the quarantined copy is read back instead of trusted, the way
  `disableInfected()` already did.

### Changed
- The packaging rules are now actually checked when a release is cut.
  `tests/test_packaging.php` asserts against the finished zip, but it looked
  only in `dist/` — and `preflight.py` runs *before* `publish.sh` builds, so
  between a version bump and the build there was no zip and the file printed
  `SKIP` and returned. Its 57 assertions, including the four-list agreement
  between `make-release.sh`, `build.py`, `install.sh` and `update.sh`, did not
  run in the one check that gates a release; they ran afterwards against the
  previous version. A skipped assertion is indistinguishable from a passing one
  in a count, so the suite reported green throughout. Preflight now builds a
  package into a scratch directory when none exists and points the suite at it
  (`SG_PACKAGE_ZIP`), a missing package fails instead of skipping, and the zip
  under `dist/` — whose sha256 the live manifest and the CDN advertise — is
  never rewritten by a check. The regression suite went from 4811 to 4868
  assertions, which is the 57 that had been disappearing.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
