# ServerScrub 4.10.0

[4.10.0] - 2026-10-20

Outbound mail monitoring â€” the gap that had already cost this server its mail
reputation once.

### Added

- **Outbound mail monitoring (`MailGuard.php`), and a page for it.**

  On 2026-10-18 a single Contact Form 7 autoresponder relayed **92,954
  messages** off a live server in about a day, roughly 1,690 an hour. **No file
  was modified**, so the malware scanner had nothing to find, and no tool
  noticed. It was discovered by hand, afterwards, by reading `exim_mainlog`.
  Every signal needed to catch it inside the first hour was already on the
  server the whole time.

  What it watches, all from data already present:
  - **Queue depth** (`exim -bpc`). 93,255 queued is not a busy day.
  - **Send rate** per account per hour, default 500.
  - **The sending script.** exim's `cwd=` on a locally injected message names
    the directory that sent it. This is the signal that turns *"inditdel is
    sending a lot"* into *"this form on this site is the relay"* â€” the part
    that took hours to establish manually.
  - **Authenticated sends** (`A=dovecot_login:â€¦`), which are a *different*
    incident: a real mailbox password is in use, so credentials leaked rather
    than a script being exploited. Reported separately, with different advice,
    because changing a password fixes one and does nothing for the other.
  - **Failures and frozen messages.** A frozen spike is usually the first
    outside sign of a relay, because the spam is being refused by its targets.

- **`serverscrub`-side throttling** through cPanel's own per-account hourly
  limit â€” the mechanism cPanel already enforces and reports on, rather than a
  second one exim would not consult.

### Notes

- **Outbound only.** Inbound filtering belongs to whatever handles it on the
  server (MagicSpam here), and two tools fighting over inbound policy is worse
  than one. Nothing in this module reads a message body or makes a spam/ham
  judgement â€” it counts and attributes.

- **It does not clear the queue and does not suspend accounts.** 92,954 of
  93,255 queued messages were the relay, which still left **301 that a customer
  was waiting for**. Throttling requires an explicit number: there is no
  default, because the right cap for a newsletter is not the right cap for a
  contact form.

- **Nothing was adopted from the projects suggested for this.** `spamscanner`
  is under the **Business Source License**, whose Additional Use Grant forbids
  using it for "a commercial offering that allows third partiesâ€¦ to access the
  functionality" â€” which is precisely this product. GitHub reports it as
  `NOASSERTION`, so the LICENSE file has to be opened to see that.
  `smtp-monitor` (MIT) watches outbound SMTP *connections*, but on cPanel PHP
  `mail()` hands off to local exim, so it would attribute sends to exim rather
  than to the account. `outgoer` (MIT) is an SMTP *proxy*, unmaintained since
  October 2023, and would sit in the mail path of every account.

- **Cost control.** The log grew by hundreds of megabytes during the incident,
  so reads are incremental with a remembered offset and capped at 8 MB a pass.
  A cap defers work rather than losing it, and rotation is detected by the file
  being smaller than the offset. A monitor that read "everything new" would
  have read all of it at once on a server already in trouble.

- **An unreadable queue reports as "unknown", never as 0.** Those mean opposite
  things, and "0 queued" on a server whose exim cannot be reached is the most
  misleading thing the panel could say.

- 3Ã— the configured threshold is critical, not 4Ã—. The relay ran at 3.4Ã— the
  default and sustained it for a day â€” at 4Ã— the one incident this was built
  from would have been reported merely as "high".

### Fixed

- **A duplicate top-level JavaScript function would have silently changed every
  number in the product.** A `fmtNum()` helper was written for the new page
  without noticing `app.js` already had one 4,600 lines earlier. JavaScript
  allows this and the later declaration replaces the earlier for every caller
  in the file; the two were not identical. `scripts/check-js-duplicates.py` now
  fails preflight on any top-level `function` or `var fn =` declared twice.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
