# ServerScrub 4.37.11

[4.37.11] - 2026-11-24

### Changed

- **Quick scan now covers each account's whole home directory, mail
  included, and no scan skips `.cache` any more.** The April 2026 dropper sat
  at `/home/officialwebspace/.cache/.<41 hex>`. Quick walked only
  `public_html`, and every scan type, full included, pruned `cache`, `.cache`,
  `node_modules`, `.git` and `.svn` by name at every depth, so no scan could
  ever have opened the directory it was in; the 57-hour full scan walked
  straight past it. Quick now covers every cPanel account's home (accounts
  with no `public_html` included), and those five names are no longer pruned
  anywhere; only `virtfs`, snapshot, CageFS and our own directories still are.
  Quick stays quicker than full through a bound per account (1,000,000 files,
  depth 25, 60 minutes) and 20 hours for the run. These figures are estimates,
  not measurements. Full and custom scans are not bounded. The Settings page,
  the scan target label and the CLI help now say what quick covers.

### Fixed

- **A bounded or unreadable scan is reported as incomplete, not clean.** An
  account that hits a bound, or whose home cannot be opened, ends the job as
  **incomplete** (amber, naming the accounts and bounds), never `done`, which
  the dashboard and the customer's page show as "Clean". The dashboard card
  and top-bar pill show it as "Last scan incomplete", not "Protected".
- **A customer's own quick scan stays in their own home.** The quick branch
  ignored the path whenever any account existed, so one customer's "scan my
  account" walked every account; with the change above it would have walked
  every mailbox, for up to 20 hours, with the backup wait waived. Only a scan
  root, or no path, now expands to every home.

### Known limitations in this release

- Real ClamAV was not tested; detection ran against a stub.
- The 60-minute and 20-hour time limits were not exercised.
- Mail-heavy accounts may show "incomplete" until the limits are tuned on
  prod.
- Full scans now walk `node_modules`, `.git` and `cache` directories and will
  take longer.
- A scan path containing `..` is not normalised. Customer paths come from
  passwd, so this is minor.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
