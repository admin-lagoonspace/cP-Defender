# Sentinel Gate 3.27.5

[3.27.5] - 2026-09-23

Fixes for five faults seen in one production install run, none of which
anything in the pipeline had an opinion about.

### Fixed
- **The firewall engine was initialised with php-cgi**, which rejects `-r`
  outright, so the installer reported its firewall backend as a php-cgi usage
  screen and then warned that initialisation had failed. `php` and
  `/usr/bin/php` are not interchangeable on a cPanel box: the latter is
  routinely a symlink to php-cgi, and the former is often the EasyApache Perl
  wrapper. The installer now resolves one interpreter at startup by asking each
  candidate what SAPI it is and taking the first that answers `cli`, and every
  PHP call -- including the cron entries and the boot-time firewall restore
  unit, which bake in an absolute path -- goes through it.
- **`install.sh: line 622: : No such file or directory`, twice.** `MANIFEST`
  was defined further down the script than the firewall section that appends to
  it, so those two redirects ran with an empty filename. The definition block
  also opens the file with `>`, so even had they worked the keys would have been
  truncated away and the uninstaller would never have known about the firewall
  service it was meant to remove. `MANIFEST` is now defined at the top, outside
  the `--register-only` guard, since the cPanel registration section appends to
  it in both modes.
- **ClamAV signatures downloaded successfully and were then reported missing.**
  The search list held distro paths only; cPanel keeps its database under
  `3rdparty/share/clamav`. The installer now asks `clamconf` where the database
  lives and derives a path from the `clamscan` actually in use before falling
  back to a fixed list.
- **`install_plugin` failed for both cPanel themes** with `lacks the required
  parameter "icon"`, leaving the plugin to appear only through the legacy
  dynamicui fallback. The icon is now copied in beside `install.json` and
  declared in it, and in the dynamicui conf.
- **The post-install self-test failed a working installation.** It demanded a
  cPanel Perl shebang on the WHM CGI and ran `perl -cw` over it -- left over
  from when that CGI was Perl. It is a `/bin/sh` dispatcher, and the
  installer's own API check returned JSON in the very same run. The test now
  takes the interpreter from the shebang, checks it exists, and syntax-checks
  with it. Two further false alarms in the same run: the AppConfig check looked
  for `acls=all` while the installer deliberately writes `acls=any` and called
  the field missing, and `pgrep -x cpsrvd` never matches because cpsrvd
  rewrites its process title, so it warned that cpsrvd was down on a server
  actively serving WHM.

### Added
- `tests/test_install_wiring.php`: asserts the interpreter resolution, that no
  call bypasses it, the manifest ordering, the ClamAV search paths, the plugin
  icon, and that the self-test no longer contains the three stale assertions.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
