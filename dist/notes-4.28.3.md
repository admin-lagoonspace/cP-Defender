# ServerScrub 4.28.3

[4.28.3] - 2026-11-02

### Added

- **`cdn-setup.sh --diagnose`**, for the one failure the script could report
  and not resolve: the sync published, `latest.json` is on disk with the right
  owner and mode, and the public URL still 404s. Its advice at that point was
  three things to go and check, which is what the operator already had.

  It now runs them. It asks **Apache directly**, with the Host header, on the
  port cPanel records -- bypassing whatever proxy is in front of it, which is
  the test that splits the problem in half. It walks the directory permissions
  from `/` down to the file, because a parent without `o+x` makes the file
  unreachable while an `ls` of the file itself looks perfect. It counts every
  vhost on the machine that claims the domain, since the one that wins may not
  be the one just published into. And it shows the `.htaccess` files in
  between.

### Fixed

- Three bugs in that diagnostic, found by running it rather than reading it:
  the `.htaccess` walk appended a path segment before testing, so
  `public_html/.htaccess` -- the likeliest culprit -- was the one file it never
  looked at; the connection probe printed `HTTP 000` **and** `no answer`,
  because curl prints its `-w` line and exits non-zero when it cannot connect,
  so both branches fired (the same shape as the `404000` fixed in 4.27.1); and
  a header was labelled `Server=` while printing the content type.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
