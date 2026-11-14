# ServerScrub 4.36.2

[4.36.2] - 2026-11-14

### Releases now carry the CDN scripts, so a fix to them can deploy itself

`scripts/` was never packaged. That is the reason 4.36.1 could not clear the
stale `latest.json` it was released to fix: the fix lived in
`scripts/cdn-sync.sh`, no release shipped `scripts/cdn-sync.sh`, and the only
route onto the server was a human copying a raw GitHub URL. A fix that cannot
reach the machine it fixes is not shipped.

The directory is still not packaged wholesale, and must not be — it holds
`publish.sh`, `make-release.sh`, `preflight.py`, `build.py`, the `check-*`
gates and `webhook.php`, which are release machinery and site infrastructure
with no business on a server. Three names ship: `cdn-sync.sh`, `cdn-setup.sh`
and `cdn-trigger-watch.sh`.

That list lives in three files which have to agree — `make-release.sh` puts
them in the zip, `install.sh` copies them on a fresh install, `update.sh`
refreshes them on every update — so `tests/test_release_payload.php` derives
the list from each and compares them, rather than grepping for a string it was
handed. A name added to one file and not the others gives a script that ships
but never updates, or updates but was never installed; both read as "it is
there" to anyone checking by eye. The same test pins the exclusions, so release
tooling cannot drift into the payload, and a named ops script missing from the
tree now fails the build instead of producing a zip quietly without it.

**One manual step remains on the host that serves the releases.** Its cron
invokes a hand-placed path, and a cron line pointing outside the install
directory keeps running the old file however many updates land. Repoint it at
`/usr/local/serverscrub/scripts/cdn-sync.sh` once and it maintains itself from
then on.

### The installer and updater had not been tested since 23 September

`tests/run-tests.sh` is the only thing that exercises `install.sh` and
`update.sh` end to end against a mock server — the paths by which the product
reaches a machine at all. It was failing 26 of its 27 assertions, and had been
since 23 Sep, for one reason: `install.sh` stopped trusting PHP by name that
day and started asking each candidate `php -r 'echo PHP_SAPI;'`, taking the
first that answered `cli`. The stub, untouched since May, did not recognise
that `-r` and answered `[stub-php] -r executed`, so the installer rejected it
and died at step 1.2. Every later assertion then failed on a missing install
directory. None of the 26 was about the product.

Nothing gated on it, so nothing noticed. Fixed, along with four other
expectations that had gone stale underneath it:

- The suite demanded four cron jobs — `scan.php quick`, `scan.php full`,
  `update-sigs` and an `update-check.php` line at 08:00. There are two
  (`scheduler.php` every 15 min, `user-scans.php` every minute); the rest moved
  into Settings. Worse, `update-check.php` was asserted *present* and passed on
  the comment explaining why it is deliberately not scheduled — a grep for a
  filename cannot tell an entry from the prose about it. Its absence is now
  asserted outright, and every active line is checked for well-formedness,
  since cron skips a malformed line silently rather than rejecting it.
- The update mock was still a GitHub Releases API response. `update.sh` reads a
  `latest.json` manifest from whichever channel answers first, so the mock
  described an endpoint nothing requests, every channel came back empty, and
  three assertions failed on a stale fixture. The manifest now carries the real
  sha256 of the zip the suite builds, so the download verification runs for
  real.
- Backup integrity demanded `quarantine/` in the pre-update backup. It is
  deliberately not copied: the update rsyncs `backend/`, `frontend/` and `whm/`
  and touches nothing else, while copying quarantine duplicated it onto the
  root partition and made updating impossible on exactly the servers that
  needed it. The assertion is inverted, and `mode.php` and `custom.sig` are now
  checked as present.
- The PNG magic-byte check piped the whole file through `od | head -1`. `head`
  closes the pipe, `od` dies of SIGPIPE, and under `pipefail` the test could
  not pass on any machine. It had reported "od unavailable or format differs"
  since the day it was written, and the skip made that look like a local quirk.

118 assertions, 0 failures, 0 skips.

### A release can no longer be cut over an unrun test suite

`preflight.py` already ran `tests/run.php`, so the unit and regression tests —
the WAF rollback tests pinning the 7 Nov 502 outage among them — have been
release-blocking all along. `tests/run-tests.sh` was not run by anything, which
is how it stayed broken for seven weeks.

It now runs as part of preflight, and **a suite that cannot be run fails the
preflight rather than being skipped.** Verified by removing the script: exit
127, `PREFLIGHT FAILED`. `SG_SKIP_TESTS=1` opts out loudly, in the same shape
as `SG_SKIP_VERSION_CHECK`.

Also closed in passing: the regression-suite step was guarded by `if php:` with
no `else`, so a machine with no interpreter skipped the whole suite and still
printed `PREFLIGHT PASSED`. The parse gate fails first in practice, so it never
bit — but a check that quietly does not run is the thing this file exists to
prevent. And preflight's own docstring still described the four checks it had
in its first version, while the static analysis, the API smoke test and the
regression suite had all grown in unlisted; that omission is why the suites
were believed ungated when they were not.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
