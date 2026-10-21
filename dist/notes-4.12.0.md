# ServerScrub 4.12.0

[4.12.0] - 2026-10-20

Both fixes come from a live incident: a mail queue stuck for four days while
the panel reported nothing wrong.

### Added

- **Delivery failures, with the reason the receiving server gave.** The Spam
  Monitor only ever counted what was *sent*. A queue that had not moved in four
  days therefore showed as silence — and the answer was in the log the whole
  time:

  ```
  421-4.7.0 [IP] Gmail has detected an unusual rate of unsolicited mail
  452-4.2.2 The recipient is out of storage space
  routing defer: retry time not reached
  ```

  Three problems that all present as "mail is stuck" and need three completely
  different responses. `==` deferral lines were previously discarded entirely.

  Each is explained rather than just counted:
  - **421 / rate limit** → high. The IP's reputation is damaged. **And the
    advice says not to run `exim -qff`** — against a 421 that sends the
    provider exactly the burst it is objecting to, which is what happened
    during the incident.
  - **452 / full mailbox** → medium, and says plainly that nothing is wrong
    with this server; somebody needs telling their mail is bouncing.
  - **routing defer** → low, a symptom not a cause, pointing at
    `exinext <address>` where the real error lives.

  Reasons are normalised — IPs, message ids, addresses and digits collapsed —
  so a thousand identical refusals aggregate into one row instead of a thousand
  distinct strings. A failure at volume becomes a finding; a handful does not,
  because every server defers some mail.

### Fixed

- **The queue viewer named the wrong customer.** Every
  `bgkgvs@host.lws-s1.com` row was attributed to `lwss1`, because it resolved
  the *domain* — and the server's own hostname belongs to `lwss1`. Technically
  correct ownership, materially useless: seventy messages pointed the operator
  at an account that had nothing to do with them.

  WordPress sends as `<account>@<server hostname>` whenever a site has no From
  address configured, which is most of them. When the domain is the server
  itself, the **local part is the account** — checked against
  `/var/cpanel/users` so a system user or a hostile string can never become an
  "account".

- `mail_delivery` is pruned alongside `mail_activity`; the new table would
  otherwise have grown without bound.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
