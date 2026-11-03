<?php
/**
 * Our Apache alias must not claim /serverscrub on other people's websites.
 *
 * install.sh writes /etc/apache2/conf.d/serverscrub.conf. conf.d applies to
 * EVERY vhost on the machine, so
 *
 *     Alias /serverscrub  ${SG_WEB_DIR}
 *
 * captured that URL path on every hosted site. Any account with a directory
 * of that name in its docroot had those URLs silently served out of our
 * directory instead of theirs, and nothing on their side could explain it.
 *
 * This is not hypothetical and it was not found by reading. It is how
 * serverscrub.com/serverscrub/code/latest.json returned 404 for six releases
 * while the file sat on disk with correct ownership and permissions, under a
 * vhost with the correct DocumentRoot, on a connection proved by fingerprint
 * to be reaching that vhost. Every check of the file, the directory, the
 * permissions and the config came back clean, because none of them was
 * wrong. The product was shadowing its own download URL.
 *
 * The CDN moved to /releases/ in 4.28.8. This is the other half: stop
 * claiming more of the URL space than the install mode actually needs.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$ins    = t_shell($repo . '/install.sh');
$insRaw = (string) file_get_contents($repo . '/install.sh');

// ── cPanel: the exact path, and nothing under it ───────────────────────────
//
// On cPanel /serverscrub/ serves ONE static signpost that redirects to the
// WHM plugin. It makes no API calls, and the dashboard's API candidates are
// all page-relative -- from /cgi/serverscrub/ they resolve under cpsrvd and
// never reach this alias at all. So the subtree was never needed here.
t_contains($ins, 'AliasMatch "^/serverscrub/?\$" "${SG_WEB_DIR}/index.html"',
     'THE SHADOWED SUBTREE: on cPanel the alias matches the exact path only, '
   . 'so /serverscrub/<anything> falls through to whatever site was asked');
t_contains($ins, 'if [[ "${INSTALL_MODE}" == "cpanel" ]]; then
    read -r -d \'\' SG_ALIAS_SECTION',
     'and the choice is made on the install mode');

// The behavioural claim, tested as behaviour rather than as a string. Apache
// uses POSIX ERE here; the anchors are what matter and they behave alike.
$pattern = '#^/serverscrub/?$#';
foreach ([
    '/serverscrub'                  => true,
    '/serverscrub/'                 => true,
] as $url => $want) {
    t_eq($want, (bool) preg_match($pattern, $url),
         'the signpost still answers ' . $url);
}
foreach ([
    '/serverscrub/code/latest.json' => 'the download path that this broke',
    '/serverscrub/backend/api'      => 'an API path on a customer vhost',
    '/serverscrub/anything/at/all'  => 'any other path a customer may own',
    '/serverscrubbed'               => 'a longer name that merely starts the same',
] as $url => $why) {
    t_ok(!preg_match($pattern, $url),
         'and NOT ' . $url . ' — ' . $why);
}

// ── Standalone is the opposite case, and must keep working ─────────────────
//
// There is no cpsrvd there: Apache IS the application server, the dashboard
// is served from this alias, and the subtree genuinely belongs to us.
t_contains($ins, 'Alias /serverscrub/backend/api ${INSTALL_DIR}/backend/api',
     'standalone keeps the API alias, because that is how its dashboard '
   . 'reaches the API at all');
t_contains($ins, 'Alias /serverscrub             ${SG_WEB_DIR}',
     'and the subtree alias, because Apache is the app server there');

// Ordering is load-bearing: mod_alias takes the first match, so the more
// specific path has to be written first.
$api = strpos($ins, 'Alias /serverscrub/backend/api');
$web = strpos($ins, 'Alias /serverscrub             ');
t_ok($api !== false && $web !== false && $api < $web,
     'with the API alias FIRST — mod_alias takes the first match, so the '
   . 'broader path written first would swallow it');

// The API Directory block belongs with the API alias and nowhere else.
t_contains($ins, 'SG_API_SECTION=""',
     'and cPanel emits no API Directory block, since it emits no API alias — '
   . 'a <Directory> for a path nothing routes to is dead config');

// ── The deny block survives in both modes ──────────────────────────────────
//
// It is what stops the rest of backend/ being served if anything ever does
// route into it, and it sits outside the per-mode sections.
t_contains($ins, '<Directory "${INSTALL_DIR}/backend">
  Options -Indexes
  AllowOverride None
  Require all denied
</Directory>',
     'the backend deny block is emitted in both modes');

// ── The reason is on the record, in the file someone will open ─────────────
t_contains($insRaw, 'This file is in conf.d and so applies to every vhost on this machine.',
     'the generated config says why it claims so little, because the next '
   . 'person to widen it will be reading that file and not this test');
t_contains($insRaw, 'returned 404 for six releases while the files sat on disk',
     'and install.sh records what the broad alias actually cost, since the '
   . 'symptom appears nowhere near the cause');

// ── Existing installs must actually receive this ───────────────────────────
//
// A fix that only lands on fresh installs leaves every current server
// shadowing its customers' URLs indefinitely.
$upd = t_shell($repo . '/update.sh');
t_contains($upd, 'bash "${INSTALL_DIR}/install.sh" --register-only',
     'THE UPGRADE PATH: update.sh re-runs the registration, which is what '
   . 'rewrites this config — otherwise the narrowing would never reach a '
   . 'server that is already installed');

// And that section must not be one --register-only skips.
$pos  = strpos($insRaw, 'section "cPanel / WHM Plugin Registration"');
t_ok($pos !== false, 'the registration section exists');
$head = substr($insRaw, 0, (int) $pos);
$opens = substr_count($head, 'if ! $REGISTER_ONLY; then');
$closes = preg_match_all('/^\s*fi\s*$/m', $head);
t_ok($opens > 0 && $closes >= $opens,
     'and every --register-only skip opened before it has been closed, so '
   . 'the Apache config is rewritten on an upgrade and not only on a fresh '
   . 'install');

// ── The self-test has to know which mode it is checking ────────────────────
//
// It did not, and so it failed on a healthy install. test.sh demanded
// RewriteRule and SetHandler in the generated Apache config regardless of
// mode; both live in the <Directory> block for the aliased API, which cPanel
// installs stopped emitting here -- correctly, because the dashboard runs
// under cpsrvd there and nothing routes to an aliased PHP directory.
//
// Result on a live server: "PASS: 47 FAIL: 2", a verification failure, and
// advice to re-run install.sh -- which would have written exactly the same
// file again. A check that cannot be satisfied is worse than no check: it
// teaches the operator to ignore the suite.
$tsh = t_shell($repo . '/test.sh');

t_contains($tsh, 'if [[ "${INSTALL_MODE}" == "cpanel" ]]; then',
     'THE UNSATISFIABLE CHECK: the Apache config test branches on the '
   . 'install mode, instead of demanding of cPanel what only standalone has');
t_contains($tsh, 'grep -q \'AliasMatch "\^/serverscrub/?\$"\' "$CANDIDATE"',
     'cPanel is checked for the exact-path alias it actually gets');
t_contains($tsh, 'fail "  SUBTREE alias present',
     'AND FOR THE REGRESSION: a subtree alias reappearing is a FAILURE, '
   . 'because that is what shadowed /serverscrub/* on every hosted site');
t_contains($tsh, 'grep -q "RewriteRule" "$CANDIDATE"',
     'standalone still requires the rewrite rules, which it genuinely needs');

// Ordering: the standalone demands must sit in the else branch, or they run
// for cPanel too and nothing has been fixed.
$blk = substr($tsh, (int) strpos($tsh, 'Apache config: $CANDIDATE'), 1800);
$ifPos  = strpos($blk, 'if [[ "${INSTALL_MODE}" == "cpanel" ]]');
$elsPos = strpos($blk, 'else');
$rwPos  = strpos($blk, 'grep -q "RewriteRule"');
t_ok($ifPos !== false && $elsPos !== false && $rwPos !== false
     && $ifPos < $elsPos && $elsPos < $rwPos,
     'and they are inside the else branch, not left running for both');

// The API .htaccess warning had the same problem, one severity down.
t_contains($tsh, 'pass ".htaccess in API dir not required (cpsrvd serves the dashboard)"',
     'the API .htaccess check is mode-aware too — warning about a file that '
   . 'is deliberately absent trains people to ignore warnings');
