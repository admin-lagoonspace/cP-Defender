# Sentinel Gate 3.34.0

[3.34.0] - 2026-10-01

### Added
- **Clicking a WAF event opens a detail dialog.** The table truncates the
  message and the URI — the two fields that say what was actually attempted —
  so a row could be read but not understood, and there was no way to see the
  rest. The dialog shows every stored field in full, wrapped rather than cut
  off, and offers the actions that follow from reading one: block the source
  address, check its reputation, or copy the details. Rows are reachable by
  keyboard, and the two IP actions are disabled for events that have no source
  address.

### Fixed
- **Every event was stored with an empty source IP.** ModSecurity's section A
  is `[time] uniqueId clientIp clientPort serverIp serverPort`, and the pattern
  looked for an address immediately after the closing bracket — where the
  unique id actually is. It never matched. The WAF page was therefore listing
  attacks with no way to act on their source, which is most of the value of
  having the log. The server address is now captured separately, and IPv6
  parses.
- **`user_agent` had a column and nothing ever filled it.** It is parsed now
  and shown in the dialog.

### Security
- **The WAF table rendered attacker-controlled data as raw HTML.** Every field
  in it arrives in an HTTP request from whoever is probing the server — the
  URI, the user agent, and the rule message, which quotes the data that
  matched. The renderer interpolated them straight into `innerHTML`, so a
  request crafted to carry markup would execute as script in the dashboard of
  whoever read the log. An attack log is the last place that should be true.

  Every column is escaped now, and the dialog sets `textContent` rather than
  `innerHTML`. Verified in a browser against the shipped renderer with a
  payload in the URI, the user agent and the rule message: it renders as text
  and does not execute.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
