# ServerScrub 4.37.2

[4.37.2] - 2026-11-19

### Fixed
- **Large WordPress editor saves timed out behind the WAF.** With the 4.37.1
  limits, a large Elementor/Gutenberg save was accepted, but then took too long
  to inspect. Several CRS 4.7 rules (941160, 941330, 933110, 944140, ...) take
  time that grows with the square of field length, and EA4's ModSecurity runs
  without PCRE JIT: a 200 KB save took 26 s and 500 KB hit the 60 s proxy
  timeout (504). New built-in rule `id:30100` skips body inspection only for
  a non-multipart body over 64 KB, sent to `admin-ajax.php`, `post.php` or
  `/wp-json/wp/v2/`, by a session carrying a `wordpress_logged_in_` cookie.
  All other requests are inspected as before. The chain was validated against
  ModSecurity 2 + CRS 4.7.0, including that `ctl` must sit on the chain's last
  link: on the first link it disabled inspection for every admin-ajax request.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
