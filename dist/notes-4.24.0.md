# ServerScrub 4.24.0

[4.24.0] - 2026-10-31

### Added

- **The cPanel user page is now a panel, not a report.** It has a branded
  header and tabs, in the shape a cPanel customer already recognises from
  cPGuard: **Home**, **Virus scanner** (with a dropdown for *Manual scan* and
  *Scanner logs*), **CMS threats**, **WAF**, **Attacks** and **File changes**.

  Home leads with thirty-day counters — threats found, attacks blocked, CMS
  issues, and how many threats are still active — then the scan button and the
  ten most recent findings.

  The tabs are **server-side**. The page already runs PHP and already renders
  the panels, so each tab is a plain link to `?tab=<name>`: it survives a
  reload, a bookmark and the back button, and works with scripting off. There
  is no JavaScript on the page at all. Links are relative so cPanel's
  `/cpsessNNN/` session prefix is preserved, and the tab name is whitelisted
  before it picks a branch. The Virus scanner dropdown opens on hover *and* on
  keyboard focus, and its parent is itself a link to the scanner — so on a
  touch device, where there is no hover, the menu is a shortcut rather than the
  only way in.

- **Three new per-account data sets in the report.** The page can only show
  what the privileged side puts in its report, so `UserReport` now also
  collects:

  - **WAF events** for this account's domains
  - **Attacks** recorded against those domains
  - **Scan history** for this account, for the Scanner logs tab
  - **Thirty-day counters** for the dashboard tiles

  A WAF event is keyed on a **host**, which is the only thing that ties one to
  a customer, so `UserReport::domainsFor()` reads the account's own cPanel file
  (`DNS=` and `DNS1..n`). Every value is validated as a hostname before it goes
  near SQL or a page, because that file is written by cPanel rather than by us
  — traversal, wildcards, spaces and overlong names are all rejected.

  An account with **no** domains runs no query at all rather than one with an
  empty `IN` clause: `host IN ()` is a syntax error, and `IN (NULL)` silently
  matches nothing while looking like it worked.

  The Attacks tab states plainly that it shows only events naming this
  account's own domains, rather than implying the customer is being shown the
  whole server. Nothing on the page reaches the server-wide database — it still
  reads exactly one file, in the customer's own home.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
