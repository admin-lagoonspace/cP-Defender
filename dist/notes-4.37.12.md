# ServerScrub 4.37.12

[4.37.12] - 2026-11-27

### Fixed

- **Every CSF reload on a migrated server printed an error for a file
  ServerScrub had deleted.** Sentinel Gate added
  `Include /etc/sentinel-gate/csf_allow.txt` to `csf.allow` and
  `…/csf_ignore.txt` to `csf.ignore`. The legacy WAF cleanup removes
  `/etc/sentinel-gate` but never looked in `/etc/csf`, so from then on every
  `csf -r` said `*Error* File does not exist: [/etc/sentinel-gate/csf_allow.txt]`.
  On prod the lines sat at `csf.allow:72` and `csf.ignore:30`. The firewall
  still loaded; the cost was an operator learning to scroll past a CSF
  `*Error*`, which is how a real one gets missed.

  install.sh now removes exactly those lines: an `Include` of a path under
  `/etc/sentinel-gate/`, and nothing else. Comments that mention
  sentinel-gate, our own `/etc/serverscrub` includes, IPs and blank lines stay
  byte-for-byte, and a file with nothing to remove is not rewritten. It runs
  outside the legacy-directory block (which has already run once on every
  affected server and will not run again) and outside every `--register-only`
  guard, so the upgrade that ships it applies it. Each removed line is printed.
  The existing CSF reload applies the change; no second reload was added.
  uninstall.sh runs the same function before its reload.

- **"Protected" is now earned only by a complete server scan.** Green meant
  "the newest job row has no open threats", whatever happened to that job.
  Every release cancels running scans ("stopped by the 4.37.x update"), so
  after each update the dashboard and the topbar pill read "Protected / The
  last scan finished and nothing is open" about a scan that had not finished;
  a failed or interrupted scan did the same. And while any scan ran, the
  newest row had no finish time, so a server scanned every night read "Not
  yet scanned". Now green needs a `done` scan that covered the whole server
  (scheduled, or an operator or `serverscrub scan` CLI scan over every
  account home or `/home`),
  at most 8 days old. A customer's one-account scan never counts toward it.
  A scan that was cancelled, failed or interrupted shows amber "Last scan did
  not finish" unless a complete scan within 8 days exists, in which case the
  green title says a later scan did not finish. A complete scan older than 8
  days shows amber "Last complete scan N days ago". The decision is made once,
  in `Scanner::protectionStatus()`, and the card and the pill both render it.

### Known limitations in this release

- **The "Protected" change was tested in automated tests only.** It was not
  checked in the browser panel or in cPanel mode, against real scans, or at
  the scale of a 132-account server. If the dashboard card or the topbar pill
  shows something unexpected after upgrading, report it; a fix ships the
  following Friday.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
