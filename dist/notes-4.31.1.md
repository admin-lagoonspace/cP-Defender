# ServerScrub 4.31.1

[4.31.1] - 2026-11-05

### Fixed

- **A scan the updater stopped was lost when it could not restart at once.**
  On a live server the restart was refused because rsync was running --
  correctly, since a full /home sweep competes with it for the same disks --
  and the marker file was then deleted regardless. The nightly sweep was
  simply gone until its next slot a day later.

  The refusal is transient, so the right answer is to try again rather than
  give up. Anything deferred stays on disk, and a new scheduler task picks
  it up on its ordinary tick: one stat of an absent file on almost every
  run. A path that is already scanning again is dropped rather than started
  twice, because several workers on one tree is how six clamscans came to be
  running at once.

- **It printed 132 paths on one line.** A scheduled sweep's `scan_path` is
  every account's docroot joined with commas, so the one thing the operator
  needed -- why it was refused -- sat at the end of a wall of text. A
  multi-account scan is summarised by count now.

- **And it reported the failure with a green tick.** "0 scan(s) resumed"
  next to a checkmark is exactly how a missed nightly sweep goes unnoticed.
  Nothing resumed is a warning, and says that the scheduler will retry.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
