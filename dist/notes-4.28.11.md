# ServerScrub 4.28.11

[4.28.11] - 2026-11-03

### Fixed

- **A stale mirror pinned every server to an old version, silently.** The
  updater walked its channel list and stopped at the first one that replied.
  That was right while a broken channel 404d -- it fell through to the next.
  It is wrong when a channel replies with OLD data.

  The CDN's sync died before writing its manifest, so serverscrub.com served
  v4.28.9 while GitHub had v4.28.10. The updater asked the CDN, got an
  answer, never asked GitHub, and reported "Already up to date" on a server
  two releases behind. The CDN being BROKEN worked better than the CDN being
  WRONG: a channel that fails loudly is safe, one that is confidently wrong
  is not.

  Every channel is asked now and the newest version wins, with the download
  base following the channel that won -- fetching 4.28.10 from a mirror still
  serving 4.28.9 would only 404. Comparison is by `sort -V`, because a string
  compare puts 4.28.9 after 4.28.10 and would have preserved the exact bug.
  Channels that already answered get a single retry instead of the full
  budget, so the common path does not pay for the rare one.

- **And it says when they disagree.** Taking the newest fixes the update; it
  does not fix the mirror, and nothing else on the server would ever mention
  that one had stopped syncing.

- `scripts/check-shell-pipefail.py` **crashed while reporting a finding.**
  Windows consoles default to cp1252 and the script prints offending source
  lines verbatim; `update.sh` is full of arrows, so a `UnicodeEncodeError`
  killed the run mid-report. The first finding containing a non-ASCII
  character hid every finding after it, and the traceback read as a broken
  tool rather than as a problem in the code. It found a real bug in this
  release and then died printing it.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
