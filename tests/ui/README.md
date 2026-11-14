# UI test pass

Driven by **Shakaal** against the test container on `http://localhost:8777`.

```bash
docker compose -f docker/compose.yml up -d panel
```

Prefer `read_page` and `get_page_text` over screenshots: they assert on text
and structure, they work while the pane is hidden, and a diff in them means
something changed rather than that a font rendered differently.

For every panel, three things, in this order:

1. **Load it** and read it. Is the content there?
2. **Click every control.** Does it respond within a moment, and did what it
   claims to change actually change?
3. **Check `read_console_messages` and `read_network_requests`.** A page that
   looks right with a 500 in the network log is a finding, not a pass.

## Must be absent

The absence tests matter more than the presence ones here, because every one
of these has shipped.

| Panel | Must NOT show |
|---|---|
| WP Databases | A green result on zero installs. "Read 0 of 0 installs — 0 new finding(s)" was displayed as success while the sweep scanned nothing. |
| WAF — mode | Two controls disagreeing. The header select and the engine card wrote different files; one could not fail. Set the mode in one, confirm the other follows. |
| WAF — events | `blocked` on every row. The action was the literal string `'block'` for 148,551 events while the engine was in DetectionOnly. With the seeded fixtures, rows must differ. |
| WAF — events | An attacker list led by `127.0.0.1` or the server's own address. |
| Dashboard | MODE reading `On` regardless of the engine. It was a hardcoded string. |
| Malware scanner | A refresh button with no feedback. It appeared dead because nothing indicated it was working. |
| Any panel | A count rendered where the query failed. Zero and "could not read" must look different. |
| WAF — mode | A mode tile reading `on` while no Apache include exists. `WAFInstaller::currentMode()` parses `SecRuleEngine` out of our own config file and never checks that the include which makes Apache *read* that file is present. Delete `/etc/apache2/conf.d/zz-serverscrub-waf.conf` and reload the panel: if it still says the WAF is blocking, that is protection the product is not delivering. |
| WAF — mode | "Rolled back" after a failed mode change, without the panel having checked the disk. See finding 1 — the claim is unconditional. |
| WAF — exclusions | An empty exclusions list styled as a healthy/green state. No exclusions is the *default*, and it is also what a failed read looks like. |
| WAF — exclusions | A row claiming to be applied when `setMode()` returned a failure. `waf exclude add` writes the row first and re-applies the config second; the row exists even when Apache was never updated. |
| Any panel | A plain-text PHP fatal or a stack trace. When the database cannot be opened, every route returns an uncaught `PDOException` as text with absolute paths, not the JSON envelope. See finding 6. |

## Must be present

| Panel | Expect |
|---|---|
| Dashboard | Account count matching `/var/cpanel/users` (8 seeded), and the engine mode matching `SecRuleEngine` in the vendor config. |
| WAF — events | Pagination like Bot Shield's, page sizes 50/100/200/500, and an Action column. |
| WAF — events | For the seeded fixtures: `20.46.43.126` as `blocked`/`direct`; `20.218.73.251` from `x-forwarded-for`, **not** `127.0.0.1`; `52.242.194.83` — not `8.8.8.8`, which was the forged header; `203.0.113.77` via `cf-connecting-ip`. |
| WAF — triage | `shopfront.test` rule 420047 flagged as a false-positive risk — one site, one address, `/shop/checkout`. Arming that rule is somebody's shop refusing orders. |
| Mail queue | Four of five stubbed messages at or over 72 hours; the 71-hour one must survive. |
| Malware scanner | The EICAR file under `acct3`, and nothing else. |
| CMS / WP | 8 main installs plus 3 addon domains under `addons` and the non-`public_html` docroot under `deepnest`. |

## Responsive and theme

`resize_window` to `mobile` (375×812) and `tablet`, then back to `desktop`.
No horizontal page scroll; tables must not overflow the viewport. Check both
`colorScheme` values — the CSS defines tokens on `:root` and redefines them
under `prefers-color-scheme: dark`, so a hardcoded colour shows up as
unreadable text in one of the two.

## Added 2026-11-13 (run against 386bca0 + the mass-detection rework)

Every panel below was loaded, read with `get_page_text`, had its controls
clicked, and then had `read_console_messages` and `read_network_requests`
checked. **A clean-looking page with an error in either log is a finding** —
the firewall case below looked perfect and was throwing on every load.

### Must be absent

| Panel | Must NOT appear |
|---|---|
| Firewall | `ReferenceError: Database is not defined` in the console. `renderGeoGrid()` calls `Database?.setting?.(...)`; `Database` is a PHP class and does not exist in the browser, and `?.` does not guard an **undeclared** identifier. The page renders fine and the country grid is silently empty. |
| Firewall — geo | An empty country grid with an enabled **Save Geo Rules** button. `State.geoSelected` is empty on every load, so saving posts `[]`, and `Firewall::setGeoBlock([])` rewrites `CC_DENY = ""` — the toast says "Geo block saved (0 countries)" while every existing country block is removed. |
| Firewall | `ACTIVE RULES` counting database rows while the header reads `iptables: 0 rule(s)`. Those are two different facts and only one of them is protection. |
| WAF — engine | A version field containing the words "is not installed". `WAFInstaller::modsecVersion()` runs `rpm -q --qf ... 2>/dev/null`; rpm prints `package <name> is not installed` on **stdout** and exits 1, the exit code is never checked, so the message is returned as the version. |
| WAF — engine | "ModSecurity is installed and logging matches" while OWASP CRS reads `vunknown` and the categories panel says the CRS directory holds no readable rule files. `crs_installed` is `crsPath() !== null`, which only tests that the directory exists. |
| Scanner | A mass-detection trip that appears nowhere. `MassDetection::lastTrip()` and `clearLastTrip()` are read by no API route, CLI command or frontend file — the only operator-visible trace is the `mass_detection` security event. |
| Dashboard | `Protected` + green badge + ✅ while `Last scan: —`. This is the *static markup* in `frontend/index.html:458,464`; the topbar pill was given a truthful initial state and the card it was copied from was not. `app.js` overwrites it on both the data and the API-failure paths, so it is only visible in the gap after login. |

### Must be present

| Panel | Expect |
|---|---|
| Scanner | `No signatures are suppressed. Every signature is reported.` as a *distinct* string from an unreadable list — both states exist and both were checked. |
| Scanner | `No scans have run yet`, `No threats found. Run a scan to check your server.`, `Nothing marked yet.` — three honest empty states, none of them green. |
| Scanner | `Updated <time>` next to the threats table after clicking Refresh. The scanner-log Refresh also responds within a second. |
| Dashboard | On a fresh install: `No scan yet` / `Not yet scanned` / `Last scan: never`, and `⛔ Real-time monitoring is not running` in ALERTS. |
| WAF | MODE tile reading `Unknown`, not `On`, before any mode is applied. |
| Any panel | Only `/config.js` and `/serverscrub.cgi?r=auth/status` may 404 — both have working fallbacks in standalone mode. Any other non-200 is a finding. |
