# ServerScrub 4.21.2

[4.21.2] - 2026-10-27

### Fixed

- **The Firewall page was manufacturing its own rules.** A live server had
  **343,000** firewall rules in a table the operator had added about a dozen
  entries to. The schema seeds ten default rules with `INSERT OR IGNORE`, and
  `firewall_rules` carried no UNIQUE constraint for `OR IGNORE` to conflict
  against — so all ten were appended again on *every database open*, which is
  every API request. Roughly 34,000 page loads is all it takes to reach six
  figures. The development machine here had 5,064 copies of each.

  The rule identity now has a unique index, so `OR IGNORE` has something to
  ignore, and an upgrade collapses what has already piled up, keeping the
  earliest row of each set. `port`, `source_ip` and `dest_ip` are nullable and
  SQLite treats NULLs as distinct, so the index is on `COALESCE`'d expressions
  — a plain one would have let `BLOCK_NULL_PACKETS` keep duplicating.

  Adding a rule that already exists is now reported as a duplicate and hands
  back the existing rule, rather than raising a constraint error.

- **The Firewall page loaded every rule at once.** Independently of the count
  above, the rules table rendered the entire table into one `innerHTML`
  assignment. That is not slow, it is fatal: the tab stops responding long
  before the request finishes, so the page "takes forever to load" with no clue
  why. The table is now paged at **100 rules a page**, each page fetched on
  request, with the product's spinner while one is in flight — a table that
  simply sits there is indistinguishable from one that has broken, which is
  exactly how 343,000 rules presented itself.

  A per-page selector offers **100 / 250 / 500** and is remembered for the
  browser session, and a search box covers name, port, protocol and source or
  destination address, because paging to rule 200,000 is not a way to find it.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
