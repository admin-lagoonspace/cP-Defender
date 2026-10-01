# Sentinel Gate 3.35.0

[3.35.0] - 2026-10-01

### Added
- **rkhunter and chkrootkit are installed with the product.** The Rootkit
  Scanner page offered both tools and then reported them "Not installed",
  leaving the operator to work out what to do about it. A tool the product
  offers should be there when the product is.

  On RHEL-family hosts these live in EPEL, and cPanel cautions against enabling
  it because it can shadow packages cPanel manages. So the configured
  repositories are tried first, and only if that fails is EPEL added — with the
  repository left **disabled** and enabled for that single transaction
  (`--enablerepo=epel`). Nothing else on the server is exposed to it, then or
  at any later update.

  Nothing here can fail the install: `RootkitEngine` is built in and needs
  neither tool. `--no-rootkit-tools` declines them outright.

- **rkhunter's file property database is initialised at install**, in the
  background. Until it exists every system binary looks modified, so the first
  scan is a wall of warnings that means nothing.

- `sentinel install-rootkit-tools` retries the install — for a host with no
  network at install time, or an operator who declined and changed their mind.
  The Rootkit page now says this rather than just showing "Not installed".

### Changed
- **Rootkit scanning is nightly by default** (03:00, after the usual backup
  window). The schedule, its settings and its scheduler task all already
  existed and were fully wired, but shipped *unseeded* — so it fell back to the
  code default of weekly. A rootkit that arrives on Monday should not wait
  until Sunday to be noticed.

### Fixed
- The new installer step first landed inside the cPanel-only Apache restart
  block, where a standalone install would have skipped it entirely. There is
  now a test asserting it sits at top level, ahead of that section.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
