# serverscrub.com redesign, new logo, canonical https://www host

**Asked for:** "This is section for serverscrub website, current website UI is horrible also the logo which was uploaded is horrible. i have new UI skill added and i want you to work on the website and get me some good looking pages. www.serverscrub.com and it should always default to https"
**Status:** ready-for-shakaal
**Size:** Z (UI on a shipped surface plus a deploy-script fix; the marketing site is not part of the plugin package and no plugin behaviour changes). If Gabbar's release tooling requires a plugin version bump for a `scripts/deploy-site.sh` change, it is a Z bump.

## What the user is actually trying to achieve

The public site is the first thing a hosting company sees before paying $10 a month to put an agent on their production server. Right now it looks amateur, and the logo looks worse, so it undercuts trust in a security product before anyone reads a word. The user wants a site that looks credible and deliberate, one brand mark that holds up from favicon size to footer size, and one canonical address (`https://www.serverscrub.com`) that every visitor lands on.

Underneath that is a constraint the user didn't spell out. The same domain and docroot are the **update CDN** for every installed server. A redirect rule that is harmless for a browser can silently stop every installed server from seeing updates. Getting that wrong costs far more than an ugly site.

## What exists today

**Pages:** `website/index.html` (197 lines), `features.html` (282), `pricing.html` (176), `install.html` (133), `status.html` (328). They share `website/assets/css/site.css` (212 lines), but every page also carries inline `style=""` attributes and hard-coded colours (e.g. `index.html:139-141`, `pricing.html:29-45`). `status.html:13-35` has its own page-local `<style>` block of dark-theme colours.

**Images:** `assets/img/logo.png` (189 KB raster, rendered at 480x304 in the footer, `index.html` footer), `mark-64.png` (8 KB, header brand on every page), `icon-180.png` (48 KB, apple-touch-icon), `favicon.png` (2.5 KB), `hero.svg` (4 KB, an illustrated dashboard).

**Validator:** `website/check-site.py` checks tag balance, internal links, asset existence, `alt` presence, the cart URL on any "Order" text, and raw `&` in hrefs. It does not check canonical links, external resources, or heading order.

**Deploy:** `scripts/deploy-site.sh`. `PAGES` (line 42) and `ASSETS` (lines 49-56) are the manifest. Files are fetched from GitHub raw `main/website/` or from `SG_SITE_SRC`, then installed into `/home/serversc/public_html/`. The script never touches `.htaccess` today. **Defect found:** the `chown` at lines 98-100 lists index/features/pricing/install but **not `status.html`**, so status.html stays root-owned after a deploy.

**Live defect found, and it's in the site copy:** the install command on `index.html:140` and `install.html:52` is
`bash <(curl -fsSL https://serverscrub.com/serverscrub/code/get.sh)`.
`scripts/cdn-sync.sh:34-48` explains that `/serverscrub/` is shadowed by a global `Alias /serverscrub` that `install.sh` writes into `/etc/apache2/conf.d/serverscrub.conf`, so that path 404s on the CDN host. The live bootstrap is `https://serverscrub.com/releases/get.sh` (`get.sh:10,55`; kept current by `cdn-sync.sh:177-190`). **The site currently tells customers to run a command that fails.** `INSTALL.md:29,35,82` and `scripts/build.py:63` carry the same stale URL. Those are outside this spec's file scope (see Out of scope), but they're recorded here.

**URLs installed servers fetch (all on the apex host, all HTTPS):**

| Client | URL | Source |
|---|---|---|
| Panel update check | `https://serverscrub.com/releases/latest.json` (+ `latest/VERSION`) | `backend/lib/UpdateChecker.php:78` |
| update.sh / upgrade.sh | `https://serverscrub.com/releases/...` | `update.sh:213`, `upgrade.sh:51` |
| get.sh bootstrap | `https://serverscrub.com/releases/get.sh`, `/releases/dist/*.zip` | `get.sh:55`, `latest.json:3` |
| Release tooling | `https://serverscrub.com/releases` | `publish.sh:571`, `make-release.sh:280`, `cdn-sync.sh:543` |
| GitHub webhook (POST) | `https://serverscrub.com/releases/webhook.php` | `scripts/webhook.php:22` |
| Legacy (dead, aliased away) | `https://serverscrub.com/serverscrub/code/...` | `INSTALL.md`, `build.py:63` |

**Proof that clients do not follow redirects safely.** `UpdateChecker.php:563-577` fetches with `file_get_contents` and then takes the status from the **first** `HTTP/` line in `$http_response_header`, accepting only `200`. PHP's stream wrapper follows a 301 itself, but the first header line is then the `301`, so a redirected manifest is reported as **unreadable** and every installed panel silently stops seeing updates. A POST to `webhook.php` that gets a 301 is retried by GitHub as GET, or dropped. So `/releases/` must never redirect, on either host or scheme. The curl calls in `get.sh`/`update.sh` use `-L` and would survive a redirect, but the panel checker would not, and that settles it.

**Plugin UI logo is a different file.** `frontend/index.html:9,18,65,106` uses `frontend/images/logo.png` and `icon-180.png` inside the plugin. `tests/run-tests.sh:235,505` asserts on that file, and `cpanel/serverscrub/index.live.php:179` samples colours from it. Nothing outside `website/` and `deploy-site.sh` refers to `website/assets/img/*`. No email templates refer to either one. The website logo can be replaced without touching the plugin.

**Docker:** `docker/Dockerfile.waf` builds real AlmaLinux 8 httpd 2.4.37, the same Apache major/minor version as prod. It can be used to test the rewrite block.

## Decisions made (no prompt, per user preference)

- **D1. No frameworks and no external hosts for page resources.** Fonts, if any, are self-hosted WOFF2 files under SIL OFL or a similar open licence, with the licence file shipped alongside. Two families at most and ≤ 160 KB of fonts in total. `font-display: swap`. No Google Fonts or CDN: that would be an extra third-party host that sees every visitor on a security vendor's site, plus a dependency the deploy can't verify. A system-font stack is also acceptable if the developer prefers it.
- **D2. The logo is website-only for now.** The plugin's `frontend/images/logo.png` is not changed (see Open questions, OQ3).
- **D3. Stable asset URLs are kept.** `favicon.png`, `icon-180.png` and `mark-64.png` keep their names and are regenerated from the new SVG. `logo.png` is no longer referenced or shipped. Because `deploy-site.sh` never deletes, the old file stays on the server and nothing breaks.
- **D4. `/releases/` (and `/serverscrub/`, `/.well-known/`) are exempt from every redirect**, both scheme and host. The proof is in the section above.
- **D5. `status.html` reads the CDN at the apex URL** (`https://serverscrub.com/releases`), not a relative `/releases`. Once the page lives on www, a relative path would read a different URL from the one servers read. That URL has a different nginx proxy-cache key, so it could look healthy while servers see stale data, which is the exact failure the page exists to catch. This needs `Access-Control-Allow-Origin: *` on `/releases/` responses. The files are public and no credentials are involved, and `*` also lets the localhost preview work.
- **D6. HSTS** is `max-age=31536000`, **without** `includeSubDomains` or `preload`. Subdomains such as `cpanel.`, `webmail.` and `mail.` are cPanel-managed and their certificates aren't ours to guarantee. Preload is very hard to undo.
- **D7. The apex→www redirect is conditional on www actually working.** `deploy-site.sh` probes `https://www.serverscrub.com/` with certificate verification before enabling it (see R14).
- **D8. Add `robots.txt` and `sitemap.xml`** with www URLs. `status.html` stays `noindex` and stays out of the sitemap. `/releases/` is not disallowed: there's no reason to hide it, and crawlers don't hurt it.

## Requirements

### A. Design system and pages

1. **One shared stylesheet** (`assets/css/site.css`, rewritten) defines the design tokens as CSS custom properties: colour, type scale, spacing, radius and shadow. No page has `style=""` attributes or a page-local `<style>` block, with one exception: `status.html` may keep page-specific *selectors*, but they must use the shared tokens, with no hex literals outside `:root`. Measured: `grep -c 'style="' website/*.html` = 0, and hex colours appear only inside the token block.
2. **All five pages are redesigned** to that system, and the developer loads `frontend-design:frontend-design` before designing. Header, nav, footer and CTA treatment are identical on every page. The direction should read as a serious infrastructure security vendor, not a template. The developer picks the aesthetic and records it in two or three sentences at the top of `site.css`.
3. **Responsive:** no horizontal scroll at 360, 768, 1280 and 1920 px widths. The nav stays usable at 360 px. If a menu toggle is used, it works with the keyboard and announces its state (`aria-expanded`).
4. **Accessible:** one `<h1>` per page with no skipped heading levels. Every `<img>` has an `alt` (decorative images use `alt=""`). Body text contrast is ≥ 4.5:1 and large text and UI is ≥ 3:1 (WCAG AA), including the status colours on their backgrounds. There is a visible `:focus-visible` style, a "skip to content" link, `lang="en"`, and `prefers-reduced-motion` is respected for any animation.
5. **Fast:** no JavaScript on any page except `status.html` (its existing script) and, if needed, one nav-toggle script ≤ 2 KB. First load of any page, excluding status.html's data fetches, is ≤ 350 KB uncompressed in total (HTML + CSS + fonts + images). Images have `width`/`height` set so layout doesn't shift.
6. **The copy is truthful.** All copy comes from the existing pages and the product (`CHANGELOG.md`, `backend/lib/`). Specifically:
   - Testimonials, customer logos, "trusted by", user or server counts, uptime figures, certifications, and any numbers that can't be sourced are **forbidden**.
   - Every module count in the copy must equal the number of module cards on `features.html`. Today `features.html:32` says "Fifteen" and the index says "15+" while 16 cards are listed. Either fix the number or drop it.
   - The **WAF** copy must not say it blocks. `features.html:156-159` says "see what was blocked", but the WAF can run in DetectionOnly mode (CHANGELOG: 148,551 events recorded as `block` that weren't blocked). Wording must cover both modes, e.g. "see what it matched, and whether it is blocking or only detecting."
   - Remove timing claims that can't be backed up ("Installed in about a minute"). Use "one command".
   - Facts kept as they are: $10 per server per month, unlimited accounts, CSF integration with nftables/firewalld/iptables fallback, ClamAV + signatures + heuristics, recoverable quarantine, per-cPanel-user page, settings preserved across updates.
   - Product illustrations (e.g. a redesigned `hero.svg`) must be visibly stylised, or be a real screenshot taken from the docker frontend. No fake account names, domains or threat counts that pass as real data.
7. **The install command is corrected everywhere on the site** to `bash <(curl -fsSL https://serverscrub.com/releases/get.sh)`, with the wget variant on `install.html`. This stays on the **apex** host because it's the CDN path. No page may contain `/serverscrub/code/`.
8. **Order CTAs** still point at `https://clientarea.lagoonspace.net/cart.php?a=add&amp;pid=29`. The client-area link is kept.
9. **status.html keeps its functionality.** These are unchanged: the four readings (repository manifest, CDN busted, CDN plain, `latest/VERSION`), the zip and mirror checks, the plain-vs-busted diagnosis, the verdict banner semantics (ok/warn/bad/"could not tell"), the update command block, `noindex`, and the "every fetch resolves" behaviour. Only presentation and the `CDN` constant change (D5: `'https://serverscrub.com/releases'`). Element IDs the script uses may be renamed only if the script is updated in the same change.

### B. Logo and icons

10. **A new original logo**, `assets/img/logo.svg`: a mark plus the "ServerScrub" wordmark. It must be hand-authored, not traced from or resembling another vendor's mark. The wordmark is text converted to paths, or a font the site self-hosts, so it renders the same everywhere. ≤ 8 KB. A separate `assets/img/mark.svg` is the mark alone, square viewBox, legible at 16 px.
11. **The icons are rendered from `mark.svg`:** `favicon.svg` (may be `mark.svg` itself, optionally with a `prefers-color-scheme` style), `favicon.png` (32x32), `icon-180.png` (180x180, opaque background, because iOS ignores transparency), `mark-64.png` (64x64), and `/favicon.ico` at the docroot (16+32), which stops the default-request 404s. Each PNG ≤ 20 KB. The commands used to render them go in a comment at the top of `mark.svg` or in the Wasooli handoff note, so they can be regenerated.
12. **Every page head has** `<link rel="icon" href="/assets/img/favicon.svg" type="image/svg+xml">`, the PNG fallback, and the apple-touch-icon. The header uses the SVG logo or mark inline or via `<img>`. No page references `logo.png`.

### C. Canonical host, HTTPS, HSTS

13. **Every page** has `<link rel="canonical" href="https://www.serverscrub.com/<page>">` (`/` for index), and `og:url` matches it. Internal links stay root-relative.
14. **Rewrite block.** It lives in `website/htaccess.site` (the source file, deliberately not named `.htaccess`), and `deploy-site.sh` inserts it into the docroot `.htaccess` (R18). Its behaviour:
    - (a) Requests whose path begins with `/releases/`, `/releases` exactly, `/serverscrub/` or `/.well-known/` are **never redirected**, on any scheme or host.
    - (b) Any other request on plain HTTP gets a **301** to `https://www.serverscrub.com<same path and query>`.
    - (c) Any other request on HTTPS to `serverscrub.com` gets a **301** to `https://www.serverscrub.com<same path and query>`.
    - (d) Requests on HTTPS to `www.serverscrub.com` are served normally.
    - (e) It only matches hosts `serverscrub.com` and `www.serverscrub.com` (case-insensitive). Any other Host (cPanel proxy subdomains, the server IP) passes through untouched.
    - (f) HTTPS detection must not loop behind cPanel's ea-nginx proxy. "Is HTTPS" means `%{HTTPS} = on` **or** `X-Forwarded-Proto: https`. Spoofing that header only lets a client skip a redirect, which is harmless.
    - (g) `Strict-Transport-Security: max-age=31536000` is sent on HTTPS responses only, inside `<IfModule mod_headers.c>`. On HTTPS that includes `/releases/` responses, which is harmless because clients already use HTTPS.
    - (h) `Access-Control-Allow-Origin: *` is sent on responses under `/releases/` (D5).
    - (i) Everything is wrapped in `<IfModule mod_rewrite.c>`, so a missing module degrades to "no redirect", not a 500.
    - (j) The apex→www rule (c), and the www target in (b), are written in a form `deploy-site.sh` can switch off. When www is disabled, (b) redirects to `https://serverscrub.com…` and (c) is omitted.
15. **The rules for /releases/ are defined once, in the root block.** Nothing is written into `/releases/` itself: `cdn-sync.sh` owns that directory.

### D. Deploy

16. **The manifest** (`PAGES`/`ASSETS` in `deploy-site.sh`) lists every file the new pages reference, including SVGs, fonts with their licence file, any nav script, `robots.txt`, `sitemap.xml` and `favicon.ico`, and drops `logo.png`. `favicon.ico`, `robots.txt` and `sitemap.xml` publish to the docroot. `htaccess.site` is fetched and staged but **not** installed as a file (it is consumed by R18). A mismatch between the manifest and what the pages reference fails `check-site.py` (R21).
17. **Fix the ownership defect:** after a deploy every published file, `status.html` and the root files above included, is owned by the account user (`serversc`).
18. **`.htaccess` merge** must not clobber cPanel's own rules (`# php -- BEGIN cPanel-generated handler`, AutoSSL, Hotlink and others):
    - It manages only the text between `# BEGIN ServerScrub site` and `# END ServerScrub site`.
    - If the markers exist, it replaces only the text between them. If they don't, it **prepends** the block, because redirects must run before anything else, and leaves every other byte unchanged.
    - If `.htaccess` doesn't exist, it creates it with the block only, mode 644, owned by `serversc`.
    - It writes a timestamped backup (`.htaccess.ss-bak-<epoch>`, keeping the last 5) **before** it changes anything. Per the "validate before destroying" rule, the check comes first.
    - It writes atomically: temp file in the same directory, then `mv`.
    - It is idempotent: running it twice produces a byte-identical `.htaccess`.
    - Malformed markers (BEGIN without END, or two BEGINs) make it **refuse** to touch the file. It prints why and leaves the file and site unchanged. It must not guess.
19. **www probe (D7).** Before writing the block, `curl -fsS --max-time 15 https://www.serverscrub.com/robots.txt` runs with normal certificate verification, against the files just published (the docroot is shared, so the new robots.txt is already there). If it fails (DNS, TLS name mismatch, timeout), the block is written with www disabled (R14j). A yellow warning names the reason and says how to fix it (add the www DNS record, re-run AutoSSL). An `SG_FORCE_WWW=0|1` override exists.
20. **Post-deploy verification with automatic rollback.** After writing, the script checks with `curl --max-redirs 0`:
    - `https://serverscrub.com/releases/latest.json` → **200** with no `Location` header
    - `http://serverscrub.com/` → 301 to the expected https target
    - `https://serverscrub.com/` → 301 to www (when enabled)
    - `https://www.serverscrub.com/` → 200 with a `Strict-Transport-Security` header (when enabled)
    - a follow-redirects fetch of `http://serverscrub.com/features.html` ends at 200 within ≤ 2 hops

    If **the /releases/ check fails, or any check returns 5xx or loops**, the backup is restored, the failure is printed in red, and the script exits non-zero. Other mismatches are warnings. The existing "checking the site responds" loop uses the canonical host.

### E. Validation tooling

21. **`website/check-site.py` is extended** so it fails on:
    - a page missing `rel="canonical"`, or one whose canonical isn't `https://www.serverscrub.com/…` for that page
    - any `src`/`href` to an external host in `<link>`/`<script>`/`<img>` (anchors to the cart and client area are fine)
    - any reference to `logo.png` or `/serverscrub/code/`
    - more than one `<h1>`, or a skipped heading level
    - any `style="` attribute
    - a referenced local asset that is missing from the `deploy-site.sh` `PAGES`/`ASSETS` arrays (parsed from the script)
    - an `htaccess.site` that lacks the BEGIN/END markers or the `/releases` exemption

    It keeps all of its existing checks.

## Explicitly out of scope

- The plugin UI logo (`frontend/images/*`), `cpanel/serverscrub/index.live.php` colours, and `tests/run-tests.sh` logo assertions (OQ3).
- The stale `/serverscrub/code/` URL in `INSTALL.md` and `scripts/build.py:63`. These are real defects, and `build.py` may matter for manifests. They're raised as a separate spec candidate and not fixed here, so this change stays website-only.
- Moving the CDN to www or changing any client's CDN base URL. The apex stays the CDN host.
- `includeSubDomains`, HSTS preload, CSP headers, custom 404 page, og:image social cards, analytics, a blog, new pages, a dark/light theme toggle.
- DNS records and AutoSSL issuance for `www`. These are server-side and belong to the user (OQ1).
- Deleting old files (`logo.png`) from the server.

## Failure behaviour

- **www has no DNS or no valid certificate:** the site stays on `https://serverscrub.com` with HTTPS forced, no apex→www, a warning at deploy, and it is fully functional. Canonical tags still name www, which is acceptable: search engines use them as a hint, and the user needs to finish the server-side work anyway.
- **mod_rewrite or mod_headers is missing:** the `IfModule` guards mean no redirect or no HSTS, never a 500.
- **The `.htaccess` has malformed ServerScrub markers:** deploy refuses the `.htaccess` step and exits non-zero, after the pages are published (pages and rules are independent). The message names the file and the line numbers of the markers.
- **The rules break /releases/ or cause a 5xx or a loop:** the backup is restored automatically (R20), and the run fails loudly.
- **status.html cannot read the CDN cross-origin** (CORS header missing, e.g. a stale nginx-cached response from before deploy): the reading shows the existing "could not tell" state, never a healthy or green state.
- **Self-hosted font fails to load:** the system font fallback stack renders. No invisible text.

## Resource bounds

- Network in deploy: ≤ 6 extra `curl` calls (probe + 5 checks), each `--max-time 15`. That adds at most 90 s worst case.
- `.htaccess` backups: keep the last 5, delete older ones (only files matching `.htaccess.ss-bak-*`).
- Page weight: ≤ 350 KB first load per page (R5). Fonts ≤ 160 KB, `logo.svg` ≤ 8 KB, each PNG ≤ 20 KB.
- No server-side code, cron, or filesystem walks are added.

## Acceptance criteria

Shakaal must demonstrate each of these, with output captured in the report.

1. `python/python.exe website/check-site.py` exits 0 with the extended checks. It also **fails** on deliberately seeded defects, one at a time and reverted after: removing a canonical link, adding `style="x"`, adding a Google Fonts `<link>`, referencing `logo.png`, and removing an asset from the `ASSETS` array.
2. Browser preview (`.claude/launch.json` "site", port 8900): screenshots of all 5 pages at 1280x800 and 375x812. No horizontal scroll at 360 px. The console has zero errors on the four marketing pages. On status.html the only allowed console entries are failed cross-origin reads from localhost, and those readings render the "could not tell" state rather than staying on the `…` placeholders.
3. status.html run against live data (from preview or prod) shows real readings for all four channels, and the verdict banner matches what `curl https://serverscrub.com/releases/latest.json` returns at that moment.
4. Accessibility: per page, the heading outline (one h1, no skipped levels), an alt-text inventory, and keyboard-only navigation through header and nav with a visible focus. Contrast ratios computed for the body text, muted text, link, button, and the three status colours on their backgrounds, all ≥ the AA thresholds in R4.
5. Truthfulness review: list every numeric or capability claim on the five pages, each with its source (existing page line or backend file). There must be zero unsourced claims, the WAF wording must cover DetectionOnly, and the module count must equal the number of cards. `grep -r "serverscrub/code" website/` must return nothing.
6. Logo: `logo.svg` and `mark.svg` render in the browser. The mark is legible at 16 px (a screenshot of the browser tab favicon). The PNG sizes and byte sizes match R11, and `favicon.ico` contains 16 and 32.
7. **Apache test of `htaccess.site`** in the `docker/Dockerfile.waf` httpd 2.4.37 image (or an equivalent AlmaLinux 8 httpd container). Use a vhost with `AllowOverride All`, ServerName `serverscrub.com`, ServerAlias `www.serverscrub.com`, :80 and :443 with a self-signed cert, a `releases/latest.json` file, and the block placed by running the R18 merge logic against a sample cPanel-style `.htaccess` with a `cPanel-generated handler` section. Use `curl -k --max-redirs 0 -H 'Host: …'` and show:
   - `http://serverscrub.com/` → 301 `https://www.serverscrub.com/`
   - `http://www.serverscrub.com/pricing.html?x=1` → 301 `https://www.serverscrub.com/pricing.html?x=1`
   - `https://serverscrub.com/features.html` → 301 `https://www.serverscrub.com/features.html`
   - `https://www.serverscrub.com/` → 200 with HSTS
   - `https://serverscrub.com/releases/latest.json` → **200, no Location**, with `Access-Control-Allow-Origin: *`
   - `http://serverscrub.com/releases/latest.json` → **200, no Location** (exempt on both schemes)
   - `https://serverscrub.com/releases` → no 301 to www
   - `http://serverscrub.com/.well-known/acme-challenge/x` → not redirected
   - Host `cpanel.serverscrub.com` and Host `<ip>` → not redirected
   - A request carrying `X-Forwarded-Proto: https` on :80 for www → 200 (no loop)
   - The www-disabled variant (R14j): `https://serverscrub.com/` → 200 and `http://serverscrub.com/` → 301 `https://serverscrub.com/`
   - `UpdateChecker`'s actual fetch path, i.e. PHP `file_get_contents` with the same context, pointed at the container's `/releases/latest.json`, parses version 200 OK
   - Merge idempotence: the second run gives a byte-identical `.htaccess`, and the cPanel section is byte-identical before and after
   - Malformed markers: the merge refuses and the file is unchanged
   - Rollback: with a deliberately broken block that 301s `/releases/`, the R20 check restores the backup and exits non-zero

   If no Apache container can be built, Shakaal reports that criterion as **not verified**. It doesn't pass on reading the rules.
8. `bash -n scripts/deploy-site.sh` is clean. A local-source dry run (`SG_SITE_SRC=website`) in a container stages every manifest file with no "missing from source" error, and ownership is the account user for every published file, including `status.html`.
9. Prod verification happens after Gabbar's release, not before: the R20 check output from the real deploy run.

## Open questions

None of these block the spec. Each has a decided default.

- **OQ1. Does `www.serverscrub.com` have a DNS record pointing at the server, and does the AutoSSL certificate cover it?** Only the user can confirm this on the server. *Default:* R19 probes it at deploy time and stays on the apex if it fails, so nothing breaks either way. The user should check `dig +short www.serverscrub.com` and the SSL/TLS Status page in cPanel for `serversc`.
- **OQ2. Does cPanel's ea-nginx on prod proxy to Apache over HTTPS (so `%{HTTPS}=on`) or over plain HTTP with `X-Forwarded-Proto`?** *Default:* R14f accepts either, and R20 catches loops with automatic rollback.
- **OQ3. Did "the logo which was uploaded is horrible" also mean the plugin's own logo** (`frontend/images/logo.png`, shown in WHM/cPanel)? *Default:* website only, per "This is section for serverscrub website". If the user wants the plugin updated to match, that becomes a separate Z spec reusing `logo.svg`. It touches `frontend/`, `tests/run-tests.sh:235,505` and the colour sampling in `index.live.php:179`.
- **OQ4. Does any external party (old emails, WHMCS product page, forum signatures) hotlink `serverscrub.com/assets/img/logo.png`?** Not checkable from the repo. *Default:* the file is left on the server (D3), so any hotlink keeps working with the old image.

## Wasooli implementation notes (2026-11-23)

**Design direction** (also at the top of `site.css`): the front of a rack
server. Brushed-aluminium page (`--alu`), one graphite faceplate per page with
screw heads, vent perforations and indicator lights, headings in a DIN-style
condensed face (Bahnschrift / DIN Alternate / Roboto Condensed fallbacks).
System font stacks only, so D1 is met with zero font bytes. The one motion is
the four channel lights in the home-page vent coming on in order, once,
disabled under `prefers-reduced-motion`. The mark is a squared S built from
three stacked bars like rack units, whose top terminal is a status light.

**Files**
- `website/index.html`, `features.html`, `pricing.html`, `install.html`,
  `status.html` rewritten; identical header/footer/closing CTA.
- `website/assets/css/site.css` rewritten (tokens in `:root`, no hex outside).
- New: `assets/img/logo.svg` (1.4 KB, wordmark is stroked paths),
  `mark.svg`, `favicon.svg` (copy of mark), `website/favicon.ico` (16+32),
  `robots.txt`, `sitemap.xml`, `htaccess.site`.
- Regenerated: `favicon.png` (32, 1.5 KB), `mark-64.png` (3.0 KB),
  `icon-180.png` (180, RGB opaque, 6.1 KB).
- Removed from the repo: `assets/img/logo.png`, `assets/img/hero.svg`
  (no longer referenced; left on the server per D3).
- `scripts/render-site-icons.py` (new): regenerates every PNG/ICO from
  `mark.svg`: `python/python.exe scripts/render-site-icons.py`. Headless
  Chrome rasterises once at 512 px, Pillow downsamples.
- `scripts/deploy-site.sh`: new manifest, `STAGE_ONLY=(htaccess.site)`,
  ownership by manifest loop, www probe + `SG_FORCE_WWW`, marked-block merge,
  R20 verification with rollback. Two no-root helper modes for testing:
  `render-block <0|1> <htaccess.site>` and `merge-htaccess <file> <block>`.
- `website/check-site.py` extended per R21 (`SS_DEPLOY_SCRIPT` env override).
- `.gitattributes`: `website/htaccess.site` forced LF.
- Tests: new `tests/test_site_redesign.py` (136 assertions, incl. 12 seeded
  defects and the merge executed for real); `tests/test_cpanel_menu_entry.php`
  site block REPLACED (see below).

**Deviations and judgement calls Shakaal should look at**
1. `tests/test_cpanel_menu_entry.php` asserted the OLD site (logo.png present,
   logo.svg absent, logo green/navy in site.css). This spec supersedes that
   decision, so I replaced that block rather than leave it failing; the
   plugin-logo assertions above it are untouched. Please confirm that is the
   right reading and not "editing a test to pass".
2. `status.html` script: beyond the `CDN` constant (D5) and moving banner
   colours to classes (R1), I added "could not tell" handling. Without it, an
   unreadable CDN fell through to "manifest is current but the archive is
   missing", and unreachable readings showed red. Status-0 reads are now
   "Could not tell" in the neutral colour. Verified in preview: from
   localhost every CDN read is CORS-blocked and the page shows the
   could-not-tell banner, not a placeholder.
3. Module count: dropped all numbers rather than pick 16 vs 17 (the per-user
   page is its own section, not a module card).
4. `htaccess.site` uses negated `RewriteCond` exemptions on each rule rather
   than an early `[L]` pass-through, so cPanel's own rewrite rules in the same
   file still run for `/releases/`. HSTS and CORS use `Header ... "expr=..."`
   (needs httpd >= 2.4.10). HSTS is additionally limited to our two hosts.
5. R20 `/releases/latest.json` check: a 404 with no Location is a warning,
   not a rollback, only when `releases/latest.json` does not exist on disk
   (empty download directory). A `000` (no answer) on that check rolls back.
6. `SG_DOMAIN` still exists but `htaccess.site` hardcodes serverscrub.com.

**Not done / not verified by me**
- No Apache run of the rules (acceptance 7) and no container deploy dry run
  (acceptance 8): that is Shakaal's docker work. Only the merge logic was
  executed (Git Bash, Windows).
- `python scripts/preflight.py` PASSED (5689 assertions, mock-env and docker
  suites). One earlier standalone `tests/run.php` run had
  `test_update_corroboration.py` crash; it passed standalone and in preflight,
  and this change does not touch it. It looks flaky, possibly network-related.
- No browser check outside Chromium; Bahnschrift is Windows-only, so macOS
  and Linux render the fallbacks.

## Wasooli, 2026-11-26: fixes for Shakaal's findings (docs/findings/2026-11-26-website-redesign.md)

1. **R20 http probe (major).** `verify_exempt()` in `deploy-site.sh` now probes
   `/releases/latest.json` (200 or no-manifest 404, never a Location) plus
   `/.well-known/ss-deploy-probe` and `/serverscrub/ss-deploy-probe` (fail only
   on a 3xx to our own host + same path) on https AND http, on the apex, and on
   www when `WWW=1`. A `000` on www is a warning; on the apex it rolls back, as
   before. New helper mode `verify-exempt <www> <have_manifest>` (network, no
   root, no writes). Test: fake `curl` reproduces each break; mutating the
   script back to https-only fails 6 assertions.
2. **status.html latest/VERSION row:** "not published" only on a real 404,
   otherwise `unread(treeR)` / `unreadCls(treeR)`.
3. **test_site_redesign.py under PowerShell:** `find_bash()` skips WSL's
   System32 stub, looks for Git Bash via `git` and Program Files, and checks it
   runs; if none, prints a SKIP saying the merge was not exercised. Passes from
   PowerShell and Git Bash.
4. **Mobile hero command:** one line, `overflow-x: auto`, `tabindex="0"`.
5. **Backup names:** step to the next free epoch name; test pre-occupies the
   next four seconds' names.

**Design pass** (rack-panel direction kept): wordmark redrawn at a 5-unit
stroke with wider spacing (254x32; header 222x28, footer 254x32); hero channels
fill the vent as racked units with a handle grille and brighter LEDs, vent sized
to content; section heads get a 6px rail and t-xl bold headings; every `.row`
gets a small rack-unit chip (status light + vent), not numbered; one dark
`.band` with a perforated top edge per page (index install, features Blocking,
install steps); status panels share the rail. No new copy or claims.

**Not verified by me:** docker Apache harness not re-run (Shakaal's);
contrast pairs reasoned from the existing token ratios, not re-measured;
Chromium on Windows only.

## Wasooli, 2026-11-26 (second pass): Shakaal R1 and R2

- **R1:** backup name is `max(now, newest existing + 1)`, so names strictly
  increase and the newest is always the one just written; pruning also skips
  that file explicitly. Test: five backups seeded ahead of the clock, then
  eight alternating merges; each must leave its own backup as the newest of
  at most five, holding the pre-merge bytes. On the previous logic all 8
  runs fail; on the fix 169/169 pass.
- **R2:** `run_suite` and the `run.php` call decode as UTF-8 with
  `errors="replace"`. That exposed a second fault: printing the suite's `✔`
  to cp1252 stdout aborted preflight, so stdout/stderr are reconfigured to
  UTF-8. No dedicated test (preflight is the harness); verified by running
  preflight with output redirected to a file.

## Wasooli, 2026-11-27 (third pass): preflight on the current tree

- **Rebrand / mogambo.md:** line 21 reworded to "internally cP-Defender, the
  repository name" (user's decision: "Reword mogambo.md"). The other five
  agent files from 27 Nov (dang, gogo, kancha, lotiya, teja) had no match.
  test_rebrand.php passes.
- **The four "flaky" update/CDN tests: root cause found, not a flake.** They
  took `shutil.which('bash')`, which from PowerShell is WSL's empty
  `System32ash.exe`, so they failed every time preflight was started from
  PowerShell and passed every time it was started from Git Bash. Reproduced
  deterministically: all four failed when run from PowerShell. Fix: a shared
  `tests/_bash.py` locator (skips the WSL stub, finds Git Bash, checks that it runs),
  used by all five Python tests that run shell. New
  `tests/test_bash_locator.py` fails if any of them goes back to
  `shutil.which`. All six pass from PowerShell.
- **3 preflight runs back to back from PowerShell:** runs 1 and 2 PASSED.
  Run 3 failed only on the rebrand test, against `marketing/FACTS.md:38`
  ("The Sentinel Gate CSF include cleanup"). That file was written at 13:53,
  during the run, by other work that is still adding files under `marketing/`.
  It is not mine and outside the user's mogambo decision, so I did not edit
  it. The four update/CDN tests passed in all three runs.

**Status:** ready-for-shakaal
