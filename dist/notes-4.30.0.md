# ServerScrub 4.30.0

[4.30.0] - 2026-11-05

### Added

- **Detection patterns live in the database, mirrored to a file.** They were
  twenty regexes in `Scanner`'s constructor: they could only change by
  shipping a release, a single false positive on a customer's live site could
  not be switched off, and nothing could add to them from a threat feed. The
  only thing that updated at all was ClamAV's own database, weekly, through
  freshclam.

  Three places, each narrower than the last:

  - the **database** is the working set -- queryable, and one rule can be
    disabled with `serverscrub signatures disable <name>`
  - **signatures.json** beside it is a mirror, rewritten after every change.
    A lost or corrupted database does not mean losing rules learned from
    feeds, which exist nowhere in the code
  - the **BUILTIN array** is the floor. With no database and no mirror, the
    scanner still runs on the twenty shipped patterns

  That last one is the point: a scanner running on zero patterns finds
  nothing and reports a clean server, which is the one wrong answer nobody
  questions.

  A pattern that does not compile is refused on the way in and skipped on the
  way out of the mirror -- stored, it would emit a warning per file and match
  nothing.

  `serverscrub signatures` shows the counts and where they came from;
  `export` and `restore` handle the mirror by hand.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
