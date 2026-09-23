# Sentinel Gate 3.30.0

[3.30.0] - 2026-09-23

### Added
- **Real-time monitoring now stands down while a backup or bulk transfer is
  running, and resumes when it finishes.** JetBackup walks every account on the
  server and rsync streams the result off-box; a real-time scanner trying to
  keep up is competing with the backup for the same disks at the moment the
  server can least afford it.

  While one is detected the monitor keeps reading inotify events -- so the
  kernel queue does not overflow, which is not a state it recovers from
  cleanly -- and discards them instead of scanning. The polling fallback skips
  its filesystem walk entirely, and deliberately does **not** refresh its
  baseline while paused: doing so would adopt everything the backup window
  changed as the new normal, so a file planted during the pause would never be
  reported. The first pass after resuming compares against the state from
  before the backup.

  Detection reads `/proc` directly rather than forking `pgrep` every twenty
  seconds, matches on process name with a JetBackup command-line fallback, and
  cannot match the monitor itself. Both the inotify and polling loops consult
  it, so the behaviour does not depend on whether `inotify_simple` happens to
  be installed.

- **Settings for it**, in the Real-Time Monitor card that saves them: an
  on/off toggle (on by default), the process names to watch for
  (`jetbackup,rsync` by default), how long to wait after they disappear before
  resuming, and a maximum suspension.

### Security
- **The pause is capped, because it is a trigger anyone on the box can pull.**
  Matching on a process name means a process merely *named* `rsync` is enough
  to suspend scanning, so someone who can start a process could otherwise
  suppress monitoring indefinitely. Past `rt_backup_max_suspend_secs` -- four
  hours by default -- the monitor resumes regardless and raises a security
  event, and a wildcard in the process list is rejected rather than matching
  everything. Suspending and resuming are both recorded as events, with the
  length of the gap, so an unusual pause is visible rather than silent.
- **A pause is reported as its own state, not as "Active".** The daemon is
  running while suspended, so a check for "running" alone rendered a green
  badge over a monitor that is deliberately not scanning -- claiming protection
  that is paused. The badge now reads "Paused", names what is running, and the
  card states plainly that changes made during the window are not scanned in
  real time and that the next scheduled scan covers them.

### Fixed
- The first `poll()` of the detector waited out a full check interval before
  looking at anything. Starting the daemon in the middle of a nightly backup
  therefore meant scanning hard for the first twenty seconds -- precisely the
  case this feature exists to avoid.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
