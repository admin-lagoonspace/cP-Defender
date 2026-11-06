# ServerScrub 4.34.0

[4.34.0] - 2026-11-06

### Added

- **`serverscrub waf triage [days]`** — what arming the rule engine would
  actually do, answered from the events already recorded rather than by
  switching it on and finding out. For each rule it reports whether the
  traffic looks like *somebody scanning the internet* or like *one site's own
  traffic*, from three signals: how many distinct addresses tripped it, how
  many distinct sites, and what fraction of its URIs are paths nobody requests
  by accident (`/.env`, `/wp-config.php.bak`, `/.aws/credentials`). Verdicts
  are `arm`, `likely-arm`, `review`, `false-positive-risk` and `too-few`, each
  with its reasoning, example URIs and the sites it would affect — the
  judgement has to be checkable, not taken on trust. Also lists addresses that
  tripped two or more different rules, which is a scanner rather than a
  misfire. Read-only, aggregated in SQL, capped at 200,000 rows, and `--json`
  for a machine-readable copy.
- **Indexes on `waf_events(timestamp)` and `(rule_id, timestamp)`.** Every WAF
  read filters by time and there was no index; 148,551 rows is a fast scan but
  not a free one, several times per page load.

### Notes

- The report leads with what would break, not with what is safe: the safe
  rules need no decision. A tool that says "safe to block" about a rule that
  is not costs a customer's site.
- Counts in the report are distinct rule+IP observations, not requests —
  `saveWafEvent()` drops a repeat from the same IP within 60 seconds. Right
  for comparing rules against each other, wrong as a measure of attack
  volume, and the report says so where the numbers appear.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
