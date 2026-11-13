<?php
/**
 * ONE PAGE VISIT AND ONE CLICK REMOVED A SERVER'S ENTIRE COUNTRY BLOCK LIST,
 * AND THE TOAST WAS GREEN.
 *
 * `renderGeoGrid()` read the saved country list with
 * `Database?.setting?.('geo_block_countries')` — a PHP class, called in the
 * browser. `?.` does not guard an UNDECLARED identifier, so this threw
 * `ReferenceError: Database is not defined` on every load of the Firewall
 * page. The exception escaped `loadFirewallStages()`, the grid rendered with
 * every country unselected, and `State.geoSelected` stayed empty.
 *
 * "Nothing is selected" and "this server blocks no countries" look identical
 * on screen. So **Save Geo Rules** then posted `[]`, `setGeoBlock([])` wrote
 * `CC_DENY = ""`, ran `csf -r`, and returned `['success' => true]` — which it
 * returned unconditionally, having checked neither the write nor the reload —
 * and the operator was told `Geo block saved (0 countries)`.
 *
 * This code is in the v4.35.1 release commit (8552261) and dates back to the
 * initial commit of 3.1.2. It is live on a production server with 132 accounts
 * and it destroys state on sight of the page plus one click.
 *
 * Two separate defects, and both halves are fixed here:
 *   1. the panel could not read the current list back at all — there was no
 *      endpoint for it, so the grid had no source of truth;
 *   2. an empty payload meant "delete everything" and an unverified write
 *      meant "success".
 */

require_once __DIR__ . '/assert.php';
$ctx     = require __DIR__ . '/bootstrap.php';
$repo    = $ctx['repo'];

$fw = new Firewall();

// ── Reading it back at all ─────────────────────────────────────────────────

Database::setSetting('geo_block_countries', 'CN,RU,KP');
$g = $fw->getGeoBlock();
t_eq(['CN', 'RU', 'KP'], $g['countries'],
     'THERE IS NOW A WAY TO READ THE LIST BACK. Nothing in the product read '
   . 'this setting — the panel tried to read it by calling a PHP class in the '
   . 'browser — so the page that writes it had no idea what it was about to '
   . 'overwrite');
t_ok(array_key_exists('csf_countries', $g),
     'and CSF\'s own CC_DENY is reported alongside it, separately, never '
   . 'merged: if the two disagree then something outside this product changed '
   . 'one of them, and a single reconciled list would be true of neither');

// ── The empty payload ──────────────────────────────────────────────────────

$r = $fw->setGeoBlock([]);
t_ok(empty($r['success']),
     'AN EMPTY SELECTION NO LONGER MEANS "DELETE EVERYTHING". That payload is '
   . 'identical on the wire to "the page failed to load the list", and the page '
   . 'was failing to load it on every single visit');
t_ok(!empty($r['needs_confirm']),
     'it is refused as something to confirm rather than as an error, because '
   . 'deselecting every country is a legitimate thing to want');
t_contains((string) $r['error'], 'all 3 blocked',
     'and the refusal says how many countries it would have removed. "Are you '
   . 'sure" with a number is a different question from "Are you sure"');
t_eq('CN,RU,KP', (string) Database::setting('geo_block_countries', ''),
     'AND NOTHING WAS WRITTEN. A refused destructive write leaves the state it '
   . 'refused to destroy exactly where it was');

$r = $fw->setGeoBlock([], true);
t_ok(!empty($r['success']),
     'and with the clear confirmed explicitly, it goes through: the operator '
   . 'may still empty the list, they just cannot do it by accident');
t_eq('', (string) Database::setting('geo_block_countries', ''),
     'the list is empty afterwards');

$r = $fw->setGeoBlock([]);
t_ok(!empty($r['success']),
     'and emptying an ALREADY empty list needs no confirmation, because there '
   . 'is nothing to destroy — the refusal is about losing state, not about the '
   . 'shape of the payload');

// ── What goes in the list ──────────────────────────────────────────────────

$r = $fw->setGeoBlock(['ru', 'RU', ' cn ']);
t_eq(['RU', 'CN'], $r['countries'],
     'codes are upper-cased, trimmed and de-duplicated before anything is '
   . 'compared or written, so "ru" and "RU" cannot produce a list that '
   . 'disagrees with itself');

$r = $fw->setGeoBlock(['USA']);
t_ok(empty($r['success']),
     'and something that is not a two-letter country code is refused outright '
   . 'rather than written into CC_DENY, where CSF would reject the whole '
   . 'directive and silently stop blocking everything else in it');
t_eq(['RU', 'CN'], $fw->getGeoBlock()['countries'],
     'with the previous list left intact');

// ── "Saved" is not "in force" ──────────────────────────────────────────────

$r = $fw->setGeoBlock(['RU']);
t_ok(!empty($r['success']) && $r['enforced'] === false,
     'ON A SERVER WITHOUT CSF, SAVING SAYS SO. The setting is stored and '
   . 'nothing is blocked, and those are two different facts; the old version '
   . 'returned a bare success and let the operator believe the second one');
t_contains((string) $r['warning'], 'not installed',
     'and the warning names the reason, so a geo block that is not actually '
   . 'blocking anything does not look like protection');

$ev = Database::fetchOne("SELECT description FROM security_events "
    . "WHERE type='geo_block_changed' ORDER BY id DESC LIMIT 1");
t_ok(is_array($ev),
     'and the change is on the security timeline. A list that can be rewritten '
   . 'by one click needs a record of who rewrote it and when');

// ── The verification the old version did not do ────────────────────────────

$src  = t_code($repo . '/backend/lib/Firewall.php');
$body = t_fn_body($src, 'setGeoBlock', 'php');

t_contains($body, 'file_put_contents',
     'the write to csf.conf happens here');
t_ok(strpos($body, '$wrote === false || $wrote !== strlen($new)') !== false,
     'AND ITS RETURN IS CHECKED, including a short write. A read-only '
   . 'csf.conf, a full disk or a half-written directive all reported "saved" '
   . 'before this');
t_ok(strpos($body, '$rc !== 0') !== false,
     'and `csf -r` has its exit status checked, because CC_DENY written into a '
   . 'file that CSF never reloads is not a country that is blocked');
t_ok(strpos($body, 'preg_replace') !== false && strpos($body, '$count < 1') !== false,
     'and a csf.conf with no CC_DENY line at all is a failure rather than a '
   . 'silent no-op: preg_replace() returning the string unchanged used to read '
   . 'as success');

$api = t_code($repo . '/backend/api/index.php');
t_contains($api, "\$fw->getGeoBlock()",
     'the panel has an endpoint to read the list from, which is the thing it '
   . 'never had');
t_contains($api, "!empty(\$body['clear_all'])",
     'and the confirmation crosses the API rather than being a frontend-only '
   . 'nicety, so the CLI, a script and the panel are all held to it');

// ── The browser half ───────────────────────────────────────────────────────

$app = t_js($repo . '/frontend/js/app.js');

t_ok(strpos($app, 'Database?.setting') === false
     && strpos($app, 'Database.setting') === false,
     'NO PHP CLASS IS CALLED IN THE BROWSER. This is the whole first half of '
   . 'the defect: `Database?.setting?.(...)` threw ReferenceError on every '
   . 'load of the Firewall page, because optional chaining does not guard an '
   . 'identifier that was never declared');

$save = t_fn_body($app, 'saveGeoBlock', 'js');
t_contains($save, "GeoLoaded !== 'loaded'",
     'AND SAVE REFUSES TO WRITE A LIST THE PAGE NEVER MANAGED TO READ. That '
   . 'is the state the page was in every time, and it is the state in which '
   . 'posting the selection erases the server\'s blocks');
t_contains($save, 'confirm(',
     'an intentional "block no countries" is confirmed by a human, since it '
   . 'is indistinguishable from the failure above by inspection of the '
   . 'payload alone');
t_ok(strpos($save, 'res?.error') !== false,
     'and a failed save shows the error the backend gave rather than a '
   . 'generic one, which is how "saved in the panel but NOT applied" reaches '
   . 'the person who needs to know it');

$grid = t_fn_body($app, 'renderGeoGrid', 'js');
t_contains($grid, 'API.fwGeoGet',
     'the grid gets its selection from the API');
t_contains($grid, 'Could not load the current country block list',
     'and when that fails it SAYS SO instead of rendering an empty grid. An '
   . 'empty grid is a factual claim — "nothing is blocked" — and it was false');

t_contains($app, 'await renderGeoGrid()',
     'and the loader awaits it, so a failure in here cannot escape as an '
   . 'unhandled rejection the way the original ReferenceError escaped '
   . 'loadFirewallStages()');
