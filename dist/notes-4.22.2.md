# ServerScrub 4.22.2

[4.22.2] - 2026-10-30

### Fixed

- **No icon appeared in cPanel's Security section.** Everything was installed
  — plugin directory, icon, `install.json`, dynamicui conf, AppConfig, all
  present — and cPanel drew nothing. No error anywhere, which is what made it
  expensive: every check said the plugin was registered.

  The dynamicui conf was written as `key=value` lines. cPanel's parser wants
  **one line of comma-separated `key=>value` pairs**, Perl-hash style, so the
  file was read and silently discarded. cPGuard sits in the same Security
  group on the same cPanel, and its conf is the single-line form — that is
  where the correct shape was taken from.

  Two other things were wrong in the same file. The `url` was absolute
  (`/frontend/<theme>/serverscrub/index.php`); it has to be **relative** to the
  theme directory. And the entry now carries the `type`, `subtype`, `width`
  and `height` keys that cPGuard's does, without which the item has no icon to
  draw.

  There is deliberately **no `feature=>` key**: gating is what hid this entry
  from every account whose feature list belongs to a reseller rather than the
  default, which on a reseller box is most accounts.

- **cpsrvd was restarted only when registration failed.** `register_appconfig`
  restarts cpsrvd for the AppConfig it just registered and knows nothing about
  the dynamicui conf, which is theme data cached separately — and that restart
  is what makes the menu entry appear. So on every install where everything
  else went right, the icon did not show up. It is now restarted
  unconditionally, and says so when the script is missing instead of silently
  not restarting.

  Two existing tests asserted the old `group=security` spelling. They were
  encoding the bug: the assertion passed while no icon ever appeared.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
