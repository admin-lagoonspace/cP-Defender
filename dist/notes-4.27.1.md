# ServerScrub 4.27.1

[4.27.1] - 2026-11-02

### Fixed

- The CDN probe added in 4.26.2 printed `HTTP 404000`. `curl -f` exits
  non-zero on a 404, so the `|| echo 000` fallback fired as well and the two
  concatenated. It also printed "CDN will pick it up within ~10 min" directly
  under "CDN IS NOT SERVING ANYTHING" — saying both is how the 404 stayed
  invisible in the first place.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
