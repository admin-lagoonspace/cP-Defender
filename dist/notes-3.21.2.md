# Sentinel Gate 3.21.2

[3.21.2] - 2026-08-28

### Fixed
- **The version in the sidebar never changed, however many updates were
  applied.** An install first set up on 3.18.2 kept reporting 3.18.2.

  `mode.php` is written once at install time and recorded `SG_VERSION`. It is
  deliberately not rewritten by updates - `install.sh --register-only`, the path
  `update.sh` takes, leaves it alone so the licensing secret survives. In 3.19.6
  `config.php` was reordered to load `mode.php` FIRST, to silence a redefinition
  warning, and that frozen version started winning.

  This was a regression introduced by that reordering. The sidebar was the
  visible symptom; the update checker comparing against a frozen version was the
  serious one.

  `SG_VERSION` describes the code, not the installation, so `config.php` now
  defines it before including `mode.php` and the installer no longer records it
  there. Existing installs are migrated: the frozen line is stripped from
  `mode.php`, everything else - the licensing secret above all - is left exactly
  as set, and a backup is kept.
- The migration runs on `--register-only`, so an ordinary `update.sh` applies
  it. Placing it with the other install-time work would have skipped precisely
  the installs that need it.
- The **build now stamps the sidebar version label**. It had only ever been
  updated by hand as part of a release, so it drifted whenever a release was cut
  any other way.
- `build.py` stamps the frontend before running preflight rather than after. A
  test asserting the stamp could otherwise never pass: the build that would
  apply it refused to run because the test had not passed yet.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
