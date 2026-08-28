# Sentinel Gate 3.25.0

[3.25.0] - 2026-08-28

### Changed
- **Auto-quarantine now ships disabled.** Quarantine *moves* a detected file
  into `/usr/local/sentinel-gate/quarantine`, which is on the root partition. On
  a hosting server whose customer data lives on a separate volume, an
  enthusiastic scan can fill `/` - and a security tool that takes the server
  down has done more damage than the file it moved. Detection is unchanged;
  threats are recorded either way, and acting on them is now opt-in.

- **Existing installs are not touched.** Settings are seeded with
  `INSERT OR IGNORE`, so a server where quarantine was deliberately enabled
  keeps it. Silently disabling a protective action during an update is not a
  change to make on someone's behalf without saying so - turn it off in
  Settings, or with the command in the release notes.

### Fixed
- The scanner page stated "auto-quarantine enabled" as fixed text regardless of
  the setting. It reports the live value now.
- The Settings toggle explains what enabling it costs, and that detection
  continues without it.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
