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
