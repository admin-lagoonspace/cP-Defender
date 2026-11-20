# ServerScrub 4.37.5

[4.37.5] - 2026-11-20

### Fixed

- **The installer hung on "Fixing permissions", and the hang was the mild
  symptom.** That section was four bare recursive calls -- the last of them
  over a path read out of the database -- with nothing printed between its
  header and "Permissions applied". Two defects, and the bug report is the
  signature of both at once.

  It was **unbounded**. `chmod -R` walks straight through a mount point, and
  `quarantine_dir` is routinely a mount to the big volume -- that is why the
  installer relocates quarantine off the root partition in the first place.
  Worse, `moveQuarantine()` accepted any path that was absolute, existing and
  writable, so `/home` was a legal value. On a cPanel server that made the
  step `chmod -R 700 /home`, and `/home/virtfs` bind-mounts a copy of the
  whole filesystem once per account: the walk is multiplied by the account
  count and re-enters `/usr`, `/lib` and `/etc` through the mounts. It does
  not finish, and what it completes on the way has set `700` on customer
  `public_html` directories. Scanner, Heuristics, the path walker and the CDN
  setup all prune `/home/virtfs` for exactly this reason. The installer was
  the one place that did not.

  It was also **silent**. With no output, an operator watching a stalled
  installer cannot tell which path is being walked, so the single fact needed
  to diagnose it was the one fact not on the screen.

  Every tree is now walked with `find -xdev`, which stops at the filesystem
  boundary and therefore cannot follow a bind mount -- also the correct scope,
  since files on the far side of a mount belong to that volume's permissions,
  not to ours. Each walk is bounded by a 300-second timeout, and a timeout is
  reported with the path, the note that the update itself succeeded, and the
  command to finish the hardening by hand, rather than being swallowed. Each
  path is printed before it is walked.

  The database read is bounded too, at 60 seconds. `Database::get()` runs
  migrations on connect and six processes share that SQLite file, so a locked
  or mid-migration database could stall on that line with the section header
  as the last thing on screen.

- **`quarantine_dir` could be set to a whole volume.** `moveQuarantine()`
  checked that the path was absolute, that it was not the current location,
  that it existed or could be created, and that it was writable. `/home`
  passes all four. The depth of the path is now checked first, before
  anything is created, so a single-component path is refused with a usable
  suggestion built from what was typed; `/home/virtfs` is refused by name, and
  so are `/proc`, `/sys` and `/dev`. `update.sh` independently refuses to walk
  such a path, because a server that already holds a bad value got it from the
  version before this one.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
