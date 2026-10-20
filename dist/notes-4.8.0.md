# ServerScrub 4.8.0

[4.8.0] - 2026-10-20

ServerScrub now installs the third-party tools it integrates with, so a fresh
install is a complete security stack rather than a list of prerequisites.

### Added

- **ModSecurity is installed during setup**, from the package manager, and left
  in **detection-only**. Installing the engine is what makes this a complete
  package; deciding what to block is not an installer's call — a rule that
  matches ordinary traffic blocks paying customers. `--no-waf-pkg` declines.

- **CSF is installed on cPanel servers** from `cpanel-csf`, cPanel's maintained
  fork (source: github.com/cpanel/cpanel-csf). It is left in CSF's own
  **TESTING mode** — rules not enforced, lfd down — because turning a brand-new
  firewall live on a production server unattended is not a decision an
  installer should make. The SSH port is read from `sshd_config` (not assumed
  to be 22) and added to `TCP_IN` first, since losing SSH is the one failure
  here that cannot be undone remotely. `--no-csf` declines.

- **A CSF upstream check.** Way to the Web Ltd closed on **2025-08-31** and
  `download.configserver.com` no longer resolves. CSF's updater **runs as
  root**, so a server still running the retired vendor's build with
  `AUTO_UPDATES` on would fetch and execute code from an unregistered domain
  the day somebody buys it. ServerScrub now reports this, entirely locally —
  it never contacts those hosts. A build newer than 15.00, the vendor's final
  release, is recognised as a maintained community fork and not flagged.

- **`serverscrub deps`** — what is installed, where it came from, and what is
  degraded without each one, so the "complete package" claim is auditable on a
  real server rather than taken on trust.

### Notes

- **Everything comes from the OS package manager. Nothing is downloaded.** This
  is a security decision, not a convenience one:
  - A tarball fetched at install time is **pinned forever** — the server's own
    `dnf update` does not know it exists. The package manager *is* the patch
    channel, so downloading to "always have the latest" achieves the opposite.
  - ModSecurity must match Apache's ABI. On EasyApache 4 it has to be
    `ea-apache24-mod_security2`; a generic binary or a wrong-headers build means
    httpd will not start, which on a shared host is every site down at once.
  - CSF and ClamAV are GPL. Installing them as separate OS packages is
    aggregation and carries no obligation onto this product. Vendoring either
    would. `FirewallEngine.php` is a clean-room implementation for the same
    reason.

- **CSF is an integration, not a prerequisite.** ServerScrub manages
  nftables/iptables through its own engine and `FirewallEngine::detect()` simply
  prefers CSF where it already exists. Off cPanel, `cpanel-csf` refuses to
  install by design, so ServerScrub uses its own engine — a supported
  configuration, not a degraded one.

- **The community fork is documented, not installed.** Black-HOST's fork
  (github.com/Black-HOST/csf) is actively maintained and has no cPanel
  dependency, which makes it the only maintained CSF for a non-cPanel server.
  ServerScrub detects it and uses it as the firewall backend, but will not
  install it: its installer is `bash <(curl -sL …)` from a third-party domain,
  and CSF runs as root. That is the same shape as the configserver.com problem,
  untriggered. Handing root to a third party is a decision to leave with the
  operator rather than make silently on every server this product touches. The
  guidance points at a pinned release rather than the one-liner.

### Fixed

- **`t_code()` was a PHP tokeniser being applied to shell scripts.** Four tests
  asserted on `install.sh`, `update.sh`, `make-release.sh` and `build.py`
  through it. `install.sh` writes PHP heredocs, so `token_get_all()` entered PHP
  mode at the first `<?php` and stripped `#` comments and syntax from there on
  — the assertions were being evaluated against mangled text. `t_code()` now
  refuses a non-PHP file, and `t_shell()` handles `#`-comment languages,
  leaving `#` inside quoted strings alone.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
