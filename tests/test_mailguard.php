<?php
/**
 * Outbound mail monitoring.
 *
 * The incident this exists for: on 2026-10-18 one Contact Form 7 autoresponder
 * relayed 92,954 messages off a live server in about a day. No file was
 * modified, so the malware scanner had nothing to find, and no tool noticed —
 * it was found by hand, afterwards, by reading exim_mainlog.
 *
 * So the test that matters is the replay: feed this module the log lines that
 * incident actually produced and check it names the account AND the site,
 * which is the part that took hours to work out manually.
 */

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/assert.php';

MailGuard::ensureSchema();

// ── Parsing real exim lines ─────────────────────────────────────────────────

// The relay. Locally injected by PHP, so U= is the cPanel account and cwd=
// names the site — the field that turns "this account sends a lot" into
// "this site is the relay".
$relay = '2026-10-18 09:30:01 1aBcDe-0001-AB <= wordpress@caiteyefilm.com '
       . 'U=inditdel P=local S=4211 id=x@caiteyefilm.com T="Thank you" '
       . 'cwd=/home/inditdel/caiteyefilm.com for victim@example.net';

$p = MailGuard::parseLine($relay);
t_eq('arrival', $p['kind'], 'an accepted message is recognised');
t_eq('inditdel', $p['account'], 'and attributed to the cPanel account via U=');
t_eq('script', $p['source'], 'as a script-injected send');
t_eq('/home/inditdel/caiteyefilm.com', $p['script'],
     'and cwd= names the site that sent it — the finding that took hours by hand');
t_eq(4211, $p['bytes'], 'with the message size');
t_eq(1, $p['recipients'], 'and its recipient count');

// An authenticated send is a DIFFERENT incident: a real mailbox password is in
// use, so credentials leaked rather than a script being exploited.
$auth = '2026-10-18 09:31:02 1aBcDf-0002-CD <= sales@example.com H=(x) '
      . '[45.33.32.156] P=esmtpa A=dovecot_login:sales@example.com S=900 '
      . 'for a@b.com c@d.com e@f.com';
$p = MailGuard::parseLine($auth);
t_eq('smtp_auth', $p['source'], 'an authenticated send is marked as such');
t_eq(3, $p['recipients'],
     'and all three envelope recipients are counted — one message to many '
   . 'recipients is one arrival but a lot of mail');

t_eq('failed', MailGuard::parseLine(
     '2026-10-18 09:31:05 1aBcDf-0002-CD ** bad@nowhere.invalid: Unrouteable address'
     )['kind'], 'a permanent failure is recognised');
t_eq('frozen', MailGuard::parseLine(
     '2026-10-18 09:31:09 1aBcDg-0003-EF Frozen (delivery error message)'
     )['kind'], 'a frozen message is recognised');

// Lines that are neither must be ignored rather than guessed at.
t_eq(null, MailGuard::parseLine(
     '2026-10-18 09:31:10 1aBcDh-0004-GH => real@customer.com R=dnslookup'),
     'a successful delivery line is not counted as a new message');
t_eq(null, MailGuard::parseLine('2026-10-18 09:31:11 1aBcDh-0004-GH Completed'),
     'nor a Completed line');
t_eq(null, MailGuard::parseLine(''), 'nor an empty line');
t_eq(null, MailGuard::parseLine('total nonsense with no markers'),
     'nor unrelated text');

// ── Attribution helpers ─────────────────────────────────────────────────────

t_eq('inditdel', MailGuard::accountForPath('/home/inditdel/caiteyefilm.com'),
     'an account is read from a /home path');
t_eq('bob', MailGuard::accountForPath('/home2/bob/public_html'),
     'including /home2, which large servers use');
t_eq(null, MailGuard::accountForPath('/tmp/whatever'),
     'and a path outside /home yields nothing rather than a guess');

$map = sys_get_temp_dir() . '/sg-mg-' . getmypid() . '-tud';
file_put_contents($map, "caiteyefilm.com: inditdel\nexample.com: alice\n");
t_eq('inditdel', MailGuard::accountForDomain('caiteyefilm.com', $map),
     'a domain maps to its account');
t_eq('inditdel', MailGuard::accountForDomain('mail.caiteyefilm.com', $map),
     'and so does a subdomain, via its parent');
t_eq(null, MailGuard::accountForDomain('somebodyelse.net', $map),
     'an unknown domain maps to nothing');
@unlink($map);

// ── Replaying the incident end to end ───────────────────────────────────────
//
// 1,690 messages in an hour from one form, which is the rate that actually
// occurred. Recorded into the hour bucket, then judged.

Database::setSetting('mg_enabled', '1');
Database::setSetting('mg_hourly', '500');
Database::query("DELETE FROM mail_activity");

$bucket = (int)(floor(time() / 3600) * 3600);
$db = Database::get();
$db->prepare("INSERT INTO mail_activity
                (bucket, account, source, script, sent, recipients, failed, frozen, bytes)
              VALUES (?,?,?,?,?,?,?,?,?)")
   ->execute([$bucket, 'inditdel', 'script', '/home/inditdel/caiteyefilm.com',
              1690, 1690, 240, 0, 7100000]);

$f = MailGuard::evaluate();
$burst = array_values(array_filter($f, fn($x) => $x['type'] === 'account_send_burst'));
t_eq(1, count($burst), 'the relay is reported');
t_eq('critical', $burst[0]['severity'],
     'as critical — 1,690/hour is more than three times the threshold');
t_contains($burst[0]['what'], 'inditdel', 'naming the account');
t_contains($burst[0]['what'], 'caiteyefilm.com',
     'and the site, which is what makes the finding actionable');
t_contains($burst[0]['what'], '1,690', 'with the actual rate');
t_contains($burst[0]['action'], 'Contact Form 7',
     'and the advice points at contact forms, which is what it turned out to be');
t_contains($burst[0]['action'], '92,954',
     'and says what it cost last time, so the number is not abstract');

// An account under the threshold is left alone — most sites legitimately send.
Database::query("DELETE FROM mail_activity");
$db->prepare("INSERT INTO mail_activity
                (bucket, account, source, script, sent, recipients, failed, frozen, bytes)
              VALUES (?,?,?,?,?,?,?,?,?)")
   ->execute([$bucket, 'quietsite', 'script', '/home/quietsite/public_html',
              40, 40, 0, 0, 90000]);
$f = MailGuard::evaluate();
t_eq(0, count(array_filter($f, fn($x) => $x['type'] === 'account_send_burst')),
     'a normal sender is not reported');

// A genuine bulk sender can be exempted, so the alert stays meaningful.
Database::query("DELETE FROM mail_activity");
$db->prepare("INSERT INTO mail_activity
                (bucket, account, source, script, sent, recipients, failed, frozen, bytes)
              VALUES (?,?,?,?,?,?,?,?,?)")
   ->execute([$bucket, 'newsletter', 'script', '/home/newsletter/public_html',
              5000, 5000, 10, 0, 1000000]);
Database::setSetting('mg_exempt', 'newsletter');
t_eq(0, count(array_filter(MailGuard::evaluate(),
     fn($x) => $x['type'] === 'account_send_burst')),
     'an exempted bulk sender is not reported');
Database::setSetting('mg_exempt', '');
t_ok(count(array_filter(MailGuard::evaluate(),
     fn($x) => $x['type'] === 'account_send_burst')) > 0,
     'and is reported again once the exemption is removed');

// The authenticated case must get DIFFERENT advice: changing a password fixes
// stolen credentials, and does nothing about an exploited form.
Database::query("DELETE FROM mail_activity");
$db->prepare("INSERT INTO mail_activity
                (bucket, account, source, script, sent, recipients, failed, frozen, bytes)
              VALUES (?,?,?,?,?,?,?,?,?)")
   ->execute([$bucket, 'alice', 'smtp_auth', null, 2000, 2000, 50, 0, 500000]);
$f = MailGuard::evaluate();
$a = array_values(array_filter($f, fn($x) => $x['type'] === 'auth_send_burst'));
t_eq(1, count($a), 'an authenticated burst is reported under its own type');
t_contains($a[0]['action'], 'password',
     'and the advice is to change the password, not to hunt for a script');
t_contains($a[0]['action'], 'compromised',
     'naming it as compromised credentials');

Database::query("DELETE FROM mail_activity");

// ── Switched off means off, and says so ─────────────────────────────────────

Database::setSetting('mg_enabled', '0');
$c = MailGuard::collect();
t_ok(isset($c['skipped']), 'a disabled monitor reports that it is disabled');
t_contains($c['skipped'], 'switched off',
     'rather than returning a silent zero that reads as "no spam"');
Database::setSetting('mg_enabled', '1');

// No exim log here, which must be reported rather than read as a clean server.
$c = MailGuard::collect();
if (MailGuard::logPath() === null) {
    t_contains($c['skipped'] ?? '', 'no readable exim log',
         'a missing exim log is reported, not treated as "nothing is sending"');
}

// An unreadable queue is -1, never 0. Those mean opposite things.
$q = MailGuard::queueDepth();
t_ok($q === -1 || $q >= 0, 'queue depth is a count or -1 for unreadable');
$st = MailGuard::status();
t_eq($q >= 0, $st['queue_readable'],
     'and the panel is told whether the queue could be read at all');

// ── Thresholds are clamped ──────────────────────────────────────────────────

Database::setSetting('mg_hourly', '1');
t_ok(MailGuard::hourlyThreshold() >= 50,
     'an hourly threshold below 50 is clamped — a busy shop sends more than '
   . 'that legitimately and the alert would fire constantly');
Database::setSetting('mg_hourly', '500');
t_eq(500, MailGuard::hourlyThreshold(), 'a sane threshold is kept');

Database::setSetting('mg_queue', '1');
t_ok(MailGuard::queueThreshold() >= 100, 'a queue threshold of 1 is clamped');
Database::setSetting('mg_queue', '2000');

// ── Throttling: explicit, validated, reversible ─────────────────────────────

$r = MailGuard::throttle('not a valid name!', 1000);
t_eq(false, $r['success'], 'an invalid account name is refused');
t_contains($r['error'], 'valid account', 'with a reason');

$r = MailGuard::throttle('alice', 0);
t_eq(false, $r['success'], 'a limit of zero is refused');
$r = MailGuard::throttle('alice', 99999999);
t_eq(false, $r['success'], 'and an absurd one');

// Never automatic. Capping a real business's mail has a customer on the other
// end of it, and the right cap for a newsletter is not the right cap for a
// contact form.
$mg = t_code(dirname(__DIR__) . '/backend/lib/MailGuard.php');
t_eq(1, substr_count($mg, 'function throttle'),
     'there is exactly one throttle path');
t_ok(strpos($mg, 'self::throttle(') === false,
     'and nothing in the module calls it by itself');

// It must never delete mail or suspend an account. The queue holds real
// customer mail alongside the spam.
foreach (['exim -Mrm', 'exim -bpru', 'suspendacct', 'removeacct'] as $danger) {
    t_ok(strpos($mg, $danger) === false,
         "MailGuard never runs $danger — the queue holds real customer mail too");
}

// ── Outbound only ───────────────────────────────────────────────────────────
//
// MagicSpam owns inbound on this server. Two tools fighting over inbound
// policy is worse than one, and nothing here reads a message body.

$raw = (string)file_get_contents(dirname(__DIR__) . '/backend/lib/MailGuard.php');
t_contains($raw, 'OUTBOUND ONLY',
     'the module records that it is outbound only');
t_ok(strpos($mg, 'spam_score') === false && strpos($mg, 'bayes') === false,
     'it makes no spam/ham judgement — it counts and attributes');

// ── Cost control ────────────────────────────────────────────────────────────
//
// The log grew by hundreds of megabytes during the incident. A monitor that
// reads "everything new" would read all of it in one pass on a server already
// in trouble, making the monitor a second incident.

t_contains($mg, 'MAX_READ', 'the log read is capped per pass');
t_contains($mg, 'mg_offset',
     'and is incremental, so a cap defers work rather than losing it');
t_contains($mg, 'if ($size < $offset)',
     'with rotation handled — a smaller file means it rotated, so start again');

// ── Scheduled, or it does nothing at all ───────────────────────────────────

$sched = t_code(dirname(__DIR__) . '/backend/cron/scheduler.php');
t_contains($sched, "'mailguard' => [", 'the scheduler has a mailguard task');
t_contains($sched, 'MailGuard::run', 'which runs it');
t_ok(preg_match("/'mailguard'.*?setting\('mailguard_schedule', '(\w+)'\)/s",
                $sched, $m) === 1, 'with a readable default schedule');
t_eq('every', $m[1],
     'running every tick — mail reputation is lost in hours, not days');
t_contains($sched, "require_once SG_ROOT . '/backend/lib/MailGuard.php';",
     'and the class is required');

// ── Settings the operator sets ──────────────────────────────────────────────
//
// The rule throughout: what the panel shows afterwards must be what the
// detector actually uses. Storing a raw value and letting the getter clamp it
// later means the panel displays a threshold that is not in force — and an
// operator who sets 10/hour, sees 10/hour, and never gets an alert has been
// misled by their own security tool.

$r = MailGuard::saveSettings(['enabled' => 1, 'hourly' => 750, 'queue' => 5000,
                              'frozen' => 300, 'retain_days' => 30]);
t_eq(true, $r['success'], 'sane settings save');
t_eq([], $r['rejected'], 'with nothing adjusted');
$s = MailGuard::settings();
t_eq(750,  $s['hourly'],      'the hourly threshold is stored');
t_eq(5000, $s['queue'],       'and the queue threshold');
t_eq(300,  $s['frozen'],      'and the frozen threshold');
t_eq(30,   $s['retain_days'], 'and the retention');
t_eq(true, $s['enabled'],     'and the on switch');

// Out-of-range values are clamped AND the operator is told, rather than the
// panel quietly disagreeing with the detector.
$r = MailGuard::saveSettings(['hourly' => 10, 'queue' => 5, 'frozen' => 1,
                              'retain_days' => 2]);
t_eq(50,  MailGuard::hourlyThreshold(), 'a too-low hourly threshold is raised');
t_eq(100, MailGuard::queueThreshold(),  'and a too-low queue threshold');
t_eq(10,  MailGuard::frozenThreshold(), 'and a too-low frozen threshold');
foreach (['hourly', 'queue', 'frozen', 'retain_days'] as $k) {
    t_ok(isset($r['rejected'][$k]), "the adjustment to $k is reported");
    t_contains($r['rejected'][$k], 'adjusted', 'in as many words');
}
// And what is stored equals what is used, so a later read cannot disagree.
t_eq((string)MailGuard::hourlyThreshold(), Database::setting('mg_hourly', ''),
     'the stored value IS the effective value — not a raw number clamped later');

$r = MailGuard::saveSettings(['hourly' => 'not a number']);
t_contains($r['rejected']['hourly'] ?? '', 'not a number',
     'a non-numeric threshold is refused rather than cast to zero');

// Exempt accounts. THE DANGEROUS FIELD: an exemption silently stops reporting
// for that account, so anything that lands in it by accident disables the
// alert this module exists for.
$r = MailGuard::saveSettings(['exempt' => 'newsletter, bulkmail']);
t_eq('newsletter,bulkmail', $r['saved']['exempt'], 'valid account names are kept');

// Split on commas, never on spaces. Splitting on whitespace turned
// "bad name!" into "bad" plus "name!" — the second was rejected and the first,
// which looks like a valid account, was silently exempted.
$r = MailGuard::saveSettings(['exempt' => 'newsletter, bad name!, ok2']);
t_eq('newsletter,ok2', $r['saved']['exempt'],
     'an invalid entry is rejected WHOLE, not split into a valid-looking half');
t_ok(!in_array('bad', explode(',', $r['saved']['exempt']), true),
     'so "bad name!" cannot exempt an account called "bad"');
t_contains($r['rejected']['exempt'], 'bad name!',
     'and the whole rejected entry is named back');

$r = MailGuard::saveSettings(['exempt' => '']);
t_eq('', $r['saved']['exempt'], 'the exemption list can be cleared');
t_eq([], MailGuard::exemptAccounts(), 'leaving nothing exempt');

// Ranges are published so the panel can show them BEFORE a value is rejected.
$s = MailGuard::settings();
t_ok(isset($s['ranges']['hourly'], $s['ranges']['queue'],
           $s['ranges']['frozen'], $s['ranges']['retain_days']),
     'every numeric setting publishes its range');
foreach ($s['ranges'] as $k => $rg) {
    t_ok(is_array($rg) && count($rg) === 2 && $rg[0] < $rg[1],
         "the $k range is a sane low/high pair");
}

// Only the keys sent are touched: saving one field must not reset the others.
MailGuard::saveSettings(['hourly' => 900, 'exempt' => 'keepme']);
MailGuard::saveSettings(['queue' => 7000]);
t_eq(900, MailGuard::hourlyThreshold(),
     'saving one field leaves the others alone');
t_eq('keepme', implode(',', MailGuard::exemptAccounts()),
     'including the exemption list');

// Turning it off is honoured.
MailGuard::saveSettings(['enabled' => 0]);
t_eq(false, MailGuard::enabled(), 'the monitor can be switched off');
MailGuard::saveSettings(['enabled' => 1]);

// Restore the defaults this suite assumed earlier.
MailGuard::saveSettings(['hourly' => 500, 'queue' => 2000, 'frozen' => 250,
                         'retain_days' => 60, 'exempt' => '']);

// ── The page is reachable and wired ─────────────────────────────────────────

$html = (string)file_get_contents(dirname(__DIR__) . '/frontend/index.html');
t_contains($html, 'data-page="mailguard"',
     'Spam Monitor has its own left-navigation entry');
t_contains($html, 'Spam Monitor', 'labelled as such');
t_contains($html, 'id="page-mailguard"', 'and its own page');
// The direction has to be unmistakable: this server runs a separate product
// for incoming mail, and an operator must not have to guess which this is.
t_contains($html, 'Outgoing mail', 'which says plainly that it is outgoing');

foreach (['mg-set-enabled', 'mg-set-hourly', 'mg-set-queue', 'mg-set-frozen',
          'mg-set-retain', 'mg-set-exempt'] as $id) {
    t_contains($html, 'id="' . $id . '"', "the settings form has $id");
}
t_contains($html, 'saveMailSettings()', 'with a save button wired to a handler');

$app = (string)file_get_contents(dirname(__DIR__) . '/frontend/js/app.js');
// The dispatch is a table now, not a switch. Asserting the property --
// "this page has a loader that fills both halves" -- instead of the spelling,
// because pinning the spelling is what made a correct refactor fail.
t_contains($app, 'mailguard:', 'Spam Monitor has a page loader');
// Checked within the dispatch table rather than as one contiguous string:
// the entry wraps across two lines, and asserting on exact whitespace is the
// same brittleness that just broke six tests.
preg_match('/mailguard:.*?\],/s', $app, $mgEntry);
t_contains($mgEntry[0] ?? '', 'loadMailGuard()',
     'the Spam Monitor loader fetches the data');
t_contains($mgEntry[0] ?? '', 'loadMailSettings()',
     'and the settings form, so the page is complete on open');
t_contains($app, 'async function loadMailSettings',
     'the settings loader exists');
t_contains($app, 'async function saveMailSettings',
     'and the saver');
// The form is refilled from the server after saving, so a clamped value is
// visibly corrected instead of leaving the typed number on screen.
t_contains($app, 'await loadMailSettings();',
     'and the form is reloaded from the server after a save');

// ── System accounts are not customers ───────────────────────────────────────
//
// FROM A LIVE SERVER. This module reported `mailnull` as the top sender at
// 3,114 messages an hour and labelled it CRITICAL, above a real customer
// account — and offered a "Cap rate" button beside it. mailnull is the user
// exim itself runs as: that traffic is exim processing mail, overwhelmingly
// bounces. The finding was wrong, it buried the real one, and capping it would
// have run whmapi1 against a user that is not a cPanel account.

foreach (['mailnull', 'magicspam', 'nobody', 'root', 'cpanel', 'dovecot',
          '(unattributed)', ''] as $sys) {
    t_ok(MailGuard::isSystemAccount($sys), "\"$sys\" is a system account");
}
foreach (['inditdel', 'blubuys', 'alice', 'shop1'] as $cust) {
    t_ok(!MailGuard::isSystemAccount($cust), "\"$cust\" is a customer account");
}
t_ok(MailGuard::isSystemAccount('MailNull'),
     'the check is case-insensitive — MailNull is the same user');

// The live numbers from that screenshot, replayed.
Database::query("DELETE FROM mail_activity");
$bk = (int)(floor(time() / 3600) * 3600);
$ins = Database::get()->prepare(
    "INSERT INTO mail_activity
       (bucket, account, source, script, sent, recipients, failed, frozen, bytes)
     VALUES (?,?,?,?,?,?,?,?,?)");
$ins->execute([$bk, 'mailnull', 'script', null, 3114, 3114, 0, 0, 1000]);
$ins->execute([$bk, 'inditdel', 'script', null, 1273, 1273, 0, 0, 1000]);
$ins->execute([$bk, 'magicspam', 'script', null, 900, 900, 0, 0, 1000]);

$f = MailGuard::evaluate();
$bursts = array_values(array_filter($f, fn($x) => $x['type'] === 'account_send_burst'));
t_eq(1, count($bursts),
     'only the real customer account is reported as a sending burst');
t_contains($bursts[0]['what'], 'inditdel', 'and it is the right one');
t_ok(!str_contains($bursts[0]['what'], 'mailnull'),
     'mailnull is NOT reported as an account sending spam');

// But its volume is not thrown away: 3,114/hour through exim's own user is
// almost always bounces, which means spam has already left and is being
// rejected elsewhere. That is a real signal, pointing somewhere else.
$sysf = array_values(array_filter($f, fn($x) => $x['type'] === 'system_mail_volume'));
t_ok(count($sysf) >= 1, 'system-account volume is still reported');
$all = implode(' || ', array_column($sysf, 'what'));
t_contains($all, 'mailnull', 'naming the account');
t_contains($all, '3,114', 'with the volume');
$mn = array_values(array_filter($sysf, fn($x) => str_contains($x['what'], 'mailnull')));
t_eq('medium', $mn[0]['severity'],
     'at medium — it is a pointer, not the thing to act on');
t_contains($mn[0]['action'], 'bounces',
     'and the advice explains it is usually bounces');
t_contains($mn[0]['action'], 'not an account to cap',
     'and says plainly not to cap it');

Database::query("DELETE FROM mail_activity");

// ── Message ids: these reach a root command ─────────────────────────────────

foreach (['1aBcDe-0001AB-XY', '1abcde-0000000000aB-1234'] as $ok) {
    t_ok(MailGuard::isMessageId($ok), "a real exim id is accepted: $ok");
}
foreach (['../../etc/passwd', '1aBcDe-0001AB-XY; rm -rf /', 'short', '',
          '$(whoami)-000000-00', '1aBcDe-0001AB-XY/../x'] as $bad) {
    t_ok(!MailGuard::isMessageId($bad),
         'a malformed or hostile id is rejected: ' . substr($bad, 0, 24));
}

// Nothing hostile may reach the shell even if it gets as far as delete.
$r = MailGuard::deleteMessages(['1aBcDe-0001AB-XY; rm -rf /', '../../x']);
t_eq(false, $r['success'], 'a delete of only-invalid ids fails');
t_eq(0, $r['deleted'], 'and deletes nothing');
t_eq(2, count($r['failed']), 'reporting each rejected id');

t_eq(false, MailGuard::deleteMessages([])['success'],
     'an empty id list deletes nothing');

// Capped per call, so one click cannot clear a queue of 93,000.
$many = [];
for ($i = 0; $i < 501; $i++) { $many[] = sprintf('1aBcD%01d-0001AB-XY', $i % 10); }
$r = MailGuard::deleteMessages($many);
t_eq(false, $r['success'], 'more than 500 messages in one call is refused');
t_contains($r['error'], 'batches',
     'and the operator is told to work in batches so the action stays reviewable');

// ── There is no "empty the queue" ───────────────────────────────────────────
//
// 92,954 of 93,255 queued messages were the relay. That still left 301 a real
// customer was waiting for, and a flush button destroys those with no record.

$mg  = t_code(dirname(__DIR__) . '/backend/lib/MailGuard.php');
$api = t_code(dirname(__DIR__) . '/backend/api/index.php');
$app = (string)file_get_contents(dirname(__DIR__) . '/frontend/js/app.js');

t_ok(strpos($mg, 'exim -bpru') === false && strpos($mg, "-Mrm '*'") === false,
     'no wildcard queue flush exists');
t_contains($api, 'empty the queue',
     'and the API says there is no such action when asked to delete nothing');
t_contains($mg, 'deleteMessages', 'deletion is per message id');
t_contains($app, 'cannot be undone',
     'and the operator is warned before it happens');

// Deletion is logged BEFORE it happens, because afterwards there is nothing
// left to log.
$pos  = strpos($mg, 'Deleting %d queued message');
$exec = strpos($mg, '-Mrm');
t_ok($pos !== false && $exec !== false && $pos < $exec,
     'what is being destroyed is recorded before it is destroyed');

// The body rule, narrowed rather than dropped.
//
// Until 4.18.0 this module never read a body at all, deliberately: "the body
// is a customer's private mail and nothing here needs it to tell a relay from
// a receipt". That is still true of everything AUTOMATIC, and the detector
// below is still header-only.
//
// What changed is that an operator can now open one specific message. The
// safeguards are that it is capped at 1,000 characters, admin only, logged to
// the security timeline, and bounded at the pipe so a 50 MB message costs 2 MB
// of I/O rather than loading whole.
t_contains($mg, '-Mvh', 'message inspection reads headers');

$auto = t_fn_body($mg, 'collect', 'php');
t_ok($auto === '' || strpos($auto, '-Mvb') === false,
     'the automatic log collector still never reads a message body');

$view = t_fn_body($mg, 'messageView', 'php');
t_contains($view, '-Mvb', 'the operator-initiated view does read the body');
t_contains($view, 'head -c',
     'bounded AT THE PIPE, so a 50MB message costs 2MB of I/O rather than '
   . 'being read whole to show 1,000 characters');
t_contains($view, 'MAX_BODY_BYTES', 'against an explicit cap');
t_contains($view, 'mail_body_viewed',
     'and every view is written to the security timeline — reading a '
   . "customer's mail should leave a mark");
t_contains($view, 'BODY_PREVIEW_CHARS', 'with the preview length a named constant');
t_eq(1000, MailGuard::BODY_PREVIEW_CHARS, 'which is the 1,000 characters asked for');

// ── The cards open the viewer ───────────────────────────────────────────────

$html = (string)file_get_contents(dirname(__DIR__) . '/frontend/index.html');
t_contains($html, 'onclick="openMailQueue(false)"', 'the Queue card is clickable');
t_contains($html, 'onclick="openMailQueue(true)"',  'and the Frozen card');
t_contains($html, 'id="mg-queue-body"', 'with a table to list into');
t_contains($html, 'deleteSelectedQueue()', 'and a delete action');
t_contains($app, 'function openMailQueue', 'the viewer opens');
t_contains($app, 'Showing ',
     'and says when the list is only a page of a larger queue — a table showing '
   . '200 of 93,000 with nothing saying so invites a delete that looks complete');

// ── Lines are dated by THEMSELVES, not by the clock ─────────────────────────
//
// FROM A LIVE SERVER. collect() computed one hour bucket from time() and filed
// every line it read into it. A first run reads up to 8 MB of HISTORY, so days
// of mail were recorded as having happened in the last sixty minutes. The panel
// reported a customer account at 5,036 messages in the last hour, CRITICAL, and
// 19,862 through exim's own user. The real figure was 22 messages across
// 300,000 log lines -- a normal multi-site reseller doing nothing wrong.
//
// The operator went hunting for a backdoor and capped a 25-domain account to
// 100 messages an hour, which broke that customer's password resets and contact
// forms. All of it caused by a number this module invented.
//
// A monitor that cannot say WHEN something happened cannot say how fast it is
// happening, and a rate is the only thing this module reports.

$nowB = (int)(floor(time() / 3600) * 3600);

$old  = date('Y-m-d H:i:s', time() - 86400 * 3)
      . ' 1xJFfR-00000008NEJ-2fc1 <= a@b U=inditdel P=local S=1208 for c@d.com';
$b = MailGuard::lineBucket($old);
t_ok($b !== null, 'a dated log line yields a bucket');
t_ok($b < $nowB - 3600,
     'a line from three days ago is NOT bucketed into the current hour');
t_eq((int)(floor((time() - 86400 * 3) / 3600) * 3600), $b,
     'it is bucketed into its own hour');

$recent = date('Y-m-d H:i:s') . ' 1x-00000000000-01 <= a@b U=x P=local S=1 for c@d';
t_eq($nowB, MailGuard::lineBucket($recent),
     'and a line from this hour lands in this hour');

// Unusable timestamps return null so the caller decides, rather than the
// parser silently guessing "now" -- which is the mistake that caused all this.
t_eq(null, MailGuard::lineBucket('no timestamp here at all'),
     'a line with no timestamp yields null, not a guess');
t_eq(null, MailGuard::lineBucket('2099-01-01 00:00:00 x <= y'),
     'and a timestamp from the future is refused');
t_eq(null, MailGuard::lineBucket(''), 'and an empty line');

// The bucket must come from the line inside the read loop, never from a single
// value computed once before it.
$mgRaw = (string)file_get_contents(dirname(__DIR__) . '/backend/lib/MailGuard.php');
t_contains($mgRaw, 'self::lineBucket($line)',
     'collect() dates each line from the line itself');
t_ok(substr_count($mgRaw, 'floor(time() / 3600)') <= 2,
     'and time() survives only as the fallback for an undated line');
t_contains($mgRaw, '$undated',
     'undated lines are counted so the operator can be told the rates are soft');

// ── Sender attribution: the local part, not the hostname's owner ────────────
//
// FROM A LIVE SERVER. The queue viewer labelled every `bgkgvs@host.lws-s1.com`
// row with the account `lwss1`, because it resolved the DOMAIN -- and
// host.lws-s1.com is owned by lwss1. Technically correct, materially useless:
// it pointed the operator at the wrong customer for seventy messages.
//
// WordPress sends as <account>@<server hostname> whenever a site has no From
// address configured, which is most of them.

t_ok(MailGuard::isServerHostname(gethostname()),
     "the server's own hostname is recognised");
t_ok(!MailGuard::isServerHostname('example.com'),
     'a customer domain is not');
t_ok(!MailGuard::isServerHostname(''), 'and neither is nothing');

t_eq(null, MailGuard::senderAccount('<>'),
     'a null sender yields no account');
t_eq(null, MailGuard::senderAccount('nonsense'),
     'and an address with no domain');

// accountExists() gates the local-part shortcut, so a hostile or system local
// part cannot become an "account".
t_ok(!MailGuard::accountExists('mailnull'),
     'a system user is never treated as a customer account');
t_ok(!MailGuard::accountExists('../../etc'),
     'and a path traversal is rejected outright');
t_ok(!MailGuard::accountExists(''), 'and an empty name');

// ── Delivery outcomes: the half the panel was missing ───────────────────────
//
// A queue sat undelivered for four days while the dashboard said nothing,
// because it counted only ARRIVALS. These are the real lines from that server.

$routing = '2026-10-20 20:12:46 1xIDrJ-00000003IyZ-0Kvz == furkan131993@gmail.com '
         . '<Furkan131993@gmail.com> routing defer: retry time not reached';
$rate    = '2026-10-19 01:58:57 1xIgCl-00000001IUJ-47QB == a@b.com R=dnslookup '
         . 'T=remote_smtp defer (-46): SMTP error from remote mail server after end '
         . 'of data: 421-4.7.0 [51.68.163.24 21] Gmail has detected an unusual rate '
         . 'of unsolicited mail';
$full    = '2026-10-16 20:30:51 1xAbCd-00000001AAA-1234 == furkan131993@gmail.com '
         . 'R=dnslookup defer (-44): SMTP error from remote mail server after '
         . 'RCPT TO:<Furkan131993@gmail.com>: 452-4.2.2 The recipient is out of '
         . 'storage space';

foreach ([$routing, $rate, $full] as $l) {
    t_eq('deferred', MailGuard::parseLine($l)['kind'],
         'a temporary failure is recognised -- these lines used to be ignored '
       . 'entirely, and they are where the answer lives');
}

t_eq('421', MailGuard::parseLine($rate)['code'], 'the 421 rate limit is read');
t_eq('452', MailGuard::parseLine($full)['code'], 'and the 452 full mailbox');
t_eq('',    MailGuard::parseLine($routing)['code'],
     'a routing defer carries no SMTP code, and none is invented');

// Three failures that all look like "mail is stuck" need three different fixes.
$e = MailGuard::explainCode('421', MailGuard::parseLine($rate)['reason']);
t_eq('high', $e['severity'], 'a rate limit is high severity');
t_contains($e['what'], 'rate-limiting', 'and named as such');
// The operator ran exim -qff during the incident. Against a 421 that sends the
// provider exactly the burst it is objecting to.
t_contains($e['action'], 'exim -qff',
     'and the advice warns against forcing the queue, which makes it worse');

$e = MailGuard::explainCode('452', MailGuard::parseLine($full)['reason']);
t_eq('medium', $e['severity'], 'a full mailbox is medium');
t_contains($e['what'], 'full', 'and named');
t_contains($e['action'], 'Nothing is wrong with this server',
     'and says plainly that the server is not at fault');

$e = MailGuard::explainCode('', MailGuard::parseLine($routing)['reason']);
t_eq('low', $e['severity'], 'a routing defer is low');
t_contains($e['action'], 'exinext',
     'and points at the retry database, where the real error is');

// Reasons are normalised so identical failures aggregate. Without this a
// thousand rate limits are a thousand distinct strings and count as one each.
$a = MailGuard::failureReason(str_replace('51.68.163.24', '1.2.3.4', $rate));
$b = MailGuard::failureReason($rate);
t_eq($b['reason'], $a['reason'],
     'the same failure from a different IP normalises to the same reason');
t_ok(!str_contains($b['reason'], '51.68.163.24'),
     'the IP is stripped');
t_ok(!str_contains($b['reason'], '1xIgCl'),
     'and the message id');
t_contains(strtolower($b['reason']), 'unusual rate',
     'while the sentence that identifies the problem survives');

// A 421 at volume becomes a finding, because it means reputation damage.
Database::query("DELETE FROM mail_delivery");
$bk2 = (int)(floor(time() / 3600) * 3600);
Database::get()->prepare(
    "INSERT INTO mail_delivery (bucket, kind, code, reason, n) VALUES (?,?,?,?,?)")
    ->execute([$bk2, 'deferred', '421',
               MailGuard::parseLine($rate)['reason'], 1240]);
$df = array_values(array_filter(MailGuard::evaluate(),
      fn($x) => $x['type'] === 'delivery_failure'));
t_eq(1, count($df), 'a rate limit at volume is reported as a finding');
t_eq('high', $df[0]['severity'], 'at high');
t_contains($df[0]['what'], '1,240', 'with the count');
t_contains($df[0]['what'], '421', 'and the SMTP code');

// A handful of deferrals is normal on any server and must not alarm.
Database::query("DELETE FROM mail_delivery");
Database::get()->prepare(
    "INSERT INTO mail_delivery (bucket, kind, code, reason, n) VALUES (?,?,?,?,?)")
    ->execute([$bk2, 'deferred', '421', 'x unusual rate y', 3]);
t_eq(0, count(array_filter(MailGuard::evaluate(),
     fn($x) => $x['type'] === 'delivery_failure')),
     'three deferrals is noise, not a finding');
Database::query("DELETE FROM mail_delivery");

// Both tables are pruned. The delivery table grows the same way and was
// being left behind.
$mgSrc = t_code(dirname(__DIR__) . '/backend/lib/MailGuard.php');
t_contains($mgSrc, 'DELETE FROM mail_delivery WHERE bucket',
     'the delivery table is pruned too, not just mail_activity');

// And the panel shows it.
$html2 = (string)file_get_contents(dirname(__DIR__) . '/frontend/index.html');
t_contains($html2, 'id="mg-delivery-body"',
     'the panel has a delivery-problems table');
t_contains($html2, 'Delivery problems', 'labelled for what it is');
$app2 = (string)file_get_contents(dirname(__DIR__) . '/frontend/js/app.js');
t_contains($app2, "g('mg-delivery-card')", 'which the loader fills');



// ── Forcing delivery of queued mail ─────────────────────────────────────────
//
// cPanel's Mail Queue Manager calls this "Deliver"; underneath it is
// `exim -M`, which attempts delivery immediately and ignores the retry
// schedule. The usual reason real mail sits in this queue is a timer that has
// not expired — a Gmail 421 rate limit, a full recipient mailbox — so this is
// the action an operator actually needs most of the time.
//
// It is also the only route in this module that SENDS. On a server that once
// relayed 92,954 messages in a single incident, these guards are the feature.

// The id check runs BEFORE exim is located, so a hostile id is rejected as
// hostile rather than as "exim not found". This is the one check that keeps
// shell metacharacters away from a root command, and it must not depend on a
// binary being installed — the suite runs on Windows, where it is not.
$evil = MailGuard::deliverMessages(['1aBcDe-0001Xy-Zz; rm -rf /']);
t_ok(empty($evil['success']), 'a shell-injecting message id is refused');
t_contains(strtolower((string)($evil['error'] ?? '')), 'no valid message ids',
     'and refused as INVALID, not as "exim not found"');
t_eq(0, (int)($evil['attempted'] ?? -1), 'nothing was attempted for it');
t_eq(1, count($evil['failed'] ?? []), 'and the bad id is reported back');

foreach (['`id`', '$(whoami)', 'a b', '../../etc/passwd', '', '*'] as $bad) {
    $r = MailGuard::deliverMessages([$bad]);
    t_ok(empty($r['success']), 'refused as a message id: ' . ($bad ?: '(empty)'));
}

t_ok(empty(MailGuard::deliverMessages([])['success']),
     'delivering nothing is refused rather than treated as "deliver all"');

// Bounded far lower than deletion. Deletion is a local unlink; each of these
// is a live SMTP conversation with a remote server.
$many = [];
for ($i = 0; $i < 101; $i++) {
    $many[] = sprintf('1aBcD%01d-00%04d-Zz', $i % 10, $i);
}
$cap = MailGuard::deliverMessages($many);
t_ok(empty($cap['success']), 'more than 100 at once is refused');
t_contains(strtolower((string)($cap['error'] ?? '')), 'batches',
     'and says to do it in batches');
t_eq(0, (int)($cap['attempted'] ?? -1), 'with nothing attempted');

// The cap must be STRICTER than deletion's, because the cost per item is a
// network round trip rather than an unlink.
$src = (string)file_get_contents(dirname(__DIR__) . '/backend/lib/MailGuard.php');
$dl  = t_fn_body($src, 'deliverMessages', 'php');
$dd  = t_fn_body($src, 'deleteMessages', 'php');
t_ok($dl !== '' && $dd !== '', 'both queue functions were located for inspection');
preg_match('/count\(\$clean\) > (\d+)/', $dl, $mDeliver);
preg_match('/count\(\$clean\) > (\d+)/', $dd, $mDelete);
t_ok((int)($mDeliver[1] ?? 0) > 0 && (int)($mDelete[1] ?? 0) > 0,
     'both paths carry an explicit cap');
t_ok((int)$mDeliver[1] < (int)$mDelete[1],
     'and delivery is capped lower than deletion ('
   . ($mDeliver[1] ?? '?') . ' vs ' . ($mDelete[1] ?? '?')
   . '), because each one is a network round trip');

// THE THING EXIT STATUS CANNOT TELL YOU.
//
// `exim -M` exits 0 for an attempt that DEFERRED — the message is still
// queued and exim is perfectly happy. Reporting that as "delivered" would be
// a lie the operator then acts on, so success is defined as LEFT THE QUEUE
// and the queue is re-read to establish it.
t_contains($dl, 'queuedIdSet',
     'delivery confirms success by re-reading the queue, not by exit status');
t_ok(strpos($dl, "rc === 0") === false || strpos($dl, 'queuedIdSet') !== false,
     'a zero exit alone is never treated as delivered');

// A hung remote MTA must not hang the request.
t_contains($dl, 'timeout', 'each attempt is bounded by a timeout');
t_contains($dl, 'deadline', 'and the batch has an overall wall-clock budget');
t_contains($dl, "'skipped'",
     'messages dropped for lack of budget are reported, not silently skipped');
t_contains($dl, '124',
     'and a timeout kill is distinguished from a delivery failure');

// It runs nice, like every other shell-out in this module. The box is usually
// already in trouble when somebody opens this page.
t_contains($dl, 'nice -n 19', 'the delivery runs at low priority');

// What is being sent is recorded BEFORE it is sent.
t_contains($dl, 'Logger::warn', 'the ids are logged before delivery is forced');
t_contains($dl, 'mail_queue_deliver', 'and the outcome lands on the timeline');

// ── The route ───────────────────────────────────────────────────────────────

$api = (string)file_get_contents(dirname(__DIR__) . '/backend/api/index.php');
// Sliced to routeMailGuard specifically. Mail Queue has a 'deliver' route of
// its own now, and a bare strpos() found whichever appeared first in the file
// -- a test passing or failing on the ORDER of two functions is not a test.
$mgRoute = t_fn_body($api, 'routeMailGuard', 'php');
$rt  = substr($mgRoute, (int)strpos($mgRoute, "'deliver' => \$method === 'POST'"), 1400);
t_ok($rt !== '', 'there is a mailguard/deliver route');
t_contains($rt, "Auth::requireRole('admin'", 'restricted to admins');
t_contains($rt, "empty(\$body['confirm'])",
     'and refuses an unconfirmed request — this route SENDS');
t_contains($rt, 'no "flush the whole queue" action',
     'there is still no flush-everything action, by design');

// ── The UI ──────────────────────────────────────────────────────────────────

$html3 = (string)file_get_contents(dirname(__DIR__) . '/frontend/index.html');
$app3  = (string)file_get_contents(dirname(__DIR__) . '/frontend/js/app.js');

t_contains($html3, 'onclick="deliverSelectedQueue()"',
     'the queue bar has a Deliver selected button');
t_contains($app3, 'async function deliverSelectedQueue',
     'with a handler behind it');
t_contains($app3, 'API.mgDeliver', 'that calls the deliver route');

// NO NATIVE DIALOGS in the queue handlers.
//
// This is why two controls shipped dead: a browser that has suppressed
// dialogs makes confirm() return false and alert() a no-op, silently, so
// `if (!confirm(...)) return;` becomes a button that does nothing. Checked
// over these handlers specifically so an unrelated confirm() elsewhere
// neither fails this nor hides a regression here.
foreach (['deliverSelectedQueue', 'deleteSelectedQueue', 'inspectMessage'] as $fn) {
    $body = t_fn_body($app3, $fn);
    t_ok($body !== '', $fn . '() exists');
    // Strip comments first. The first version of this failed on the comments
    // explaining why confirm() was removed -- a check that cannot tell code
    // from a remark ABOUT the code reports a bug that is not there, and the
    // natural response is to delete the explanation to appease it.
    $code = preg_replace('~/\*.*?\*/~s', '', $body);
    $code = preg_replace('~^\s*//.*$~m', '', (string)$code);
    t_ok(preg_match('/(?<![\w.])(?:confirm|alert|prompt)\s*\(/', (string)$code) === 0,
         $fn . '() uses an in-app dialog, not confirm()/alert() which a '
       . 'browser can suppress without telling anyone');
}

// Delivering a frozen message THAWS it. The Exim spec is explicit about this,
// and "retry" does not sound like "unfreeze", so the dialog has to say so.
$dsq = t_fn_body($app3, 'deliverSelectedQueue');
t_contains($dsq, 'frozen', 'the deliver dialog knows about frozen messages');
t_contains($dsq, 'unfreeze', 'and warns that delivering one unfreezes it');
t_contains($app3, "data-frozen",
     'which it can only know because the row carries the frozen flag');

// Honest reporting in the toast.
t_contains($dsq, 'still queued',
     'a deferred message is reported as still queued, never as delivered');

// ── Message view: attachments, flagging, tabs ───────────────────────────────

// Risky-type detection is a HINT that moves the operator's eye, never a
// verdict. The flag is theirs to set.
foreach (['invoice.exe', 'a.scr', 'x.js', 'payload.PhP', 'setup.msi',
          'report.pdf.exe', 'photo.jpg.scr'] as $bad) {
    t_ok(MailGuard::riskyAttachment($bad, 'application/octet-stream'),
         "flagged as a risky type: $bad");
}
foreach (['invoice.pdf', 'photo.jpg', 'notes.txt', 'sheet.xlsx', 'archive.zip'] as $ok) {
    t_ok(!MailGuard::riskyAttachment($ok, 'application/pdf'),
         "not flagged as risky: $ok");
}
t_ok(MailGuard::riskyAttachment('x.bin', 'application/x-msdownload'),
     'and an executable content-type counts even with a dull filename');

// Flagging records the hash, because that is the part the malware scanner can
// act on later when the same bytes land on disk.
MailGuard::ensureSchema();
Database::query('DELETE FROM mail_flagged_attachments');

$mid  = '1aBcDe-0001Xy-Zz';
$hash = hash('sha256', 'malicious bytes');

$r = MailGuard::flagAttachment($mid, 'invoice.exe', $hash,
                               'application/x-msdownload', 94208, 'dropper', 'root');
t_ok(!empty($r['success']), 'an attachment can be flagged');
$flags = MailGuard::flagsFor($mid);
t_ok(isset($flags['invoice.exe']), 'and is listed against its message');
t_eq($hash, $flags['invoice.exe']['sha256'],
     'with the sha256 kept, which is what the scanner can match on disk');

// Flagging twice is an update, not a duplicate or an error.
MailGuard::flagAttachment($mid, 'invoice.exe', $hash, '', 0, 'second look', 'root');
t_eq(1, count(MailGuard::flagsFor($mid)), 'flagging twice does not duplicate the row');

// Refusals.
t_ok(empty(MailGuard::flagAttachment('not-an-id', 'x.exe')['success']),
     'a bad message id is refused');
t_ok(empty(MailGuard::flagAttachment($mid, '')['success']),
     'an unnamed attachment is refused');
t_ok(empty(MailGuard::flagAttachment($mid, 'x.exe', 'nonsense')['success']),
     'and something that is not a sha256 is refused rather than stored');

t_ok(!empty(MailGuard::unflagAttachment($mid, 'invoice.exe')['success']),
     'a flag can be withdrawn');
t_eq(0, count(MailGuard::flagsFor($mid)), 'and is then gone');

// ── MIME parsing ────────────────────────────────────────────────────────────
//
// Exercised through the private parser via the public view is impossible
// without exim, so the shape is asserted on the source and the behaviour on
// the pieces that are reachable.
$mgSrc = t_code(dirname(__DIR__) . '/backend/lib/MailGuard.php');
$mime  = t_fn_body($mgSrc, 'mimeParts', 'php');
t_contains($mime, 'base64_decode', 'base64 parts are decoded');
t_contains($mgSrc, 'quoted_printable_decode',
     'and quoted-printable, in the shared text decoder');
t_contains($mime, 'depth < 1',
     'multipart/mixed wrapping multipart/alternative is walked one level, '
   . 'which is the shape of nearly every real message with an attachment');
t_contains($mime, 'truncated',
     'a part running past the read cap is marked incomplete');
t_ok(strpos($mime, "'sha256'      => (\$truncated") !== false
     || strpos($mime, '$truncated || $decoded') !== false,
     'and a truncated attachment is NOT given a hash — a hash of part of a '
   . 'file is not that file\'s hash, and acting on it later would be acting '
   . 'on a fiction');

$dec = t_fn_body($mgSrc, 'decodeText', 'php');
t_contains($dec, 'mb_check_encoding',
     'decoded text is forced to valid UTF-8, or json_encode would fail and '
   . 'take the whole response with it');

// Headers come from exim -Mvh, which prefixes every line with a byte count,
// so the output is NOT an RFC822 header block.
$ph = t_fn_body($mgSrc, 'parseHeaders', 'php');
t_contains($ph, "preg_replace('/^\d+[A-Za-z]?\s/'",
     'exim\'s line-length prefixes are stripped before parsing');
t_contains($ph, 'decodeWords', 'and RFC 2047 encoded subjects are decoded');

// ── The UI ──────────────────────────────────────────────────────────────────
$mgHtml = (string)file_get_contents(dirname(__DIR__) . '/frontend/index.html');
$mgApp  = (string)file_get_contents(dirname(__DIR__) . '/frontend/js/app.js');

foreach (['mail', 'settings', 'logs'] as $tab) {
    t_contains($mgHtml, 'onclick="mgTab(\'' . $tab . '\')"', "there is a $tab tab");
    t_contains($mgHtml, 'data-mgtab="' . $tab . '"', "with at least one $tab card");
}
t_contains($mgApp, 'function mgTab', 'with a handler behind them');

// A card that hides itself must not be forced open by a tab switch — that is
// how an empty card comes to look like a broken one.
$tabFn = t_fn_body($mgApp, 'mgTab');
t_contains($tabFn, 'mgHidden',
     'a self-hiding card keeps its own state across a tab switch');

t_contains($mgApp, 'function viewMessage', 'a message can be opened');
// The row is built in JS, not in the markup.
t_contains($mgApp, 'onclick="viewMessage(', 'from the queue row');
t_contains($mgHtml, 'id="msgview-modal"', 'into a dedicated view');
t_contains($mgHtml, 'id="mv-attachments"', 'which lists attachments');
t_contains($mgHtml, 'id="mv-body"', 'and shows the body');

// An attachment is addressed by INDEX in the markup, never by filename: a
// filename can contain a quote, and interpolating one into an onclick is
// exactly what killed the exclude button in 4.13.
t_contains($mgApp, 'onclick="toggleAttachmentFlag(\' + i + \')"',
     'attachments are addressed by index in the attribute');
t_ok(preg_match('/onclick="toggleAttachmentFlag\(\s*\x27?\s*\+\s*esc\(/', $mgApp) === 0,
     'and never by a filename interpolated into it');

// ── The queue listing must carry subjects ───────────────────────────────────
//
// `exim -bp` does not report a Subject, so the listing was a wall of message
// ids and addresses with no way to tell a receipt from a relay at a glance.
// ConfigServer Mail Manage showed the subject and that is most of why it was
// pleasant to use.
$qsrc = t_fn_body($mgSrc, 'addSubjects', 'php');
t_ok($qsrc !== '', 'subjects are filled in for the listing');
t_contains($qsrc, 'MAX_SUBJECT_READS',
     'capped at a number of files per listing, because a 93,000-message queue '
   . 'must not become 93,000 reads');
t_contains($qsrc, 'MAX_HEADER_BYTES', 'and each read is itself capped');
t_contains($qsrc, "substr(\$id, 5, 1)",
     'split_spool_directory is handled — the subdirectory is the sixth '
   . 'character of the message id');
t_ok(strpos($qsrc, '-Mvh') === false && strpos($qsrc, 'shell_exec') === false,
     'and it reads the spool file directly rather than forking exim per '
   . 'message, which is the difference between 200 reads and 200 forks');
t_contains($qsrc, 'decodeWords',
     'an RFC 2047 encoded subject is decoded rather than shown raw');

$queueFn = t_fn_body($mgSrc, 'queueList', 'php');
t_contains($queueFn, 'addSubjects', 'queueList fills them in');

// The filter runs BEFORE subjects are read, so it matches sender and
// recipient only. The placeholder must not promise otherwise.
$mgHtml2 = (string)file_get_contents(dirname(__DIR__) . '/frontend/index.html');
t_contains($mgHtml2, 'placeholder="filter sender or recipient"',
     'and the search box promises only what it actually matches');

// ── Mail view shows mail ────────────────────────────────────────────────────
//
// The queue card hid itself until somebody clicked the QUEUE stat card, so the
// Mail view tab looked empty. Worse, because the card declared no hidden
// state, switching tabs revealed it with nothing loaded — a permanent
// "Loading…".
t_ok(strpos($mgHtml2, 'id="mg-queue-card" data-mgtab="mail" data-mg-hidden="1"') === false,
     'THE REPORTED BUG: the queue card no longer hides itself on Mail view');
t_contains($mgHtml2, 'id="mg-queue-card" data-mgtab="mail">',
     'it is simply part of the tab');

$mgApp2 = (string)file_get_contents(dirname(__DIR__) . '/frontend/js/app.js');
t_contains($mgApp2, 'reloadMailQueue(),',
     'and the page loader fetches the queue, so Mail view has mail in it');

// Every card that DOES hide itself must declare that in the markup, or a tab
// switch reveals it empty.
foreach (['mg-findings-card', 'mg-delivery-card'] as $id) {
    t_ok(preg_match('/id="' . $id . '"[^>]*data-mg-hidden="1"/', $mgHtml2) === 1,
         $id . ' declares that it starts hidden');
}

// Senders is history, so it belongs with the logs.
t_ok(preg_match('/data-mgtab="logs">\s*<div class="card-header">\s*<div class="card-title">Senders, last 24 hours/', $mgHtml2) === 1,
     'the senders table is on the Logs tab, not Mail view');

// "Close" hid the only content on the tab. It resets the filter instead.
t_ok(strpos($mgApp2, 'function closeMailQueue') === false,
     'the Close button that emptied the tab is gone');
t_contains($mgApp2, 'function showAllQueue', 'replaced by a filter reset');
t_contains($mgHtml2, 'onclick="showAllQueue()"', 'which the button calls');

// ── Mail Queue, as its own section ──────────────────────────────────────────
//
// Prior art: ConfigServer Mail Queue, discontinued and GPL-3.0. No code from
// it is used here — this product is not GPL, and copying would make it so.
// What IS reused is knowledge nobody owns: which exim command does what, and
// which questions an operator needs to ask of a queue.

// Parsing `exim -bp`. The sample covers the three things a naive parser gets
// wrong: a frozen marker, an empty envelope sender, and the "D " prefix.
$bp = implode("\n", [
  ' 25m  2.5K 1abcDe-0001AB-XY <sender@example.com>',
  '          recipient@elsewhere.com',
  '        D already@elsewhere.com',
  '',
  '  3h  14K 1abcDf-0002AB-XY <> frozen',
  '          bounced@example.com',
  '',
  '  2d 1.1M 1abcDg-0003AB-XY <shop@mydomain.test>',
  '          customer@mydomain.test',
  '',
]);
$parsed = MailQueue::parseQueue($bp);
t_eq(3, $parsed['total'], 'three messages parsed from exim -bp');

$m = $parsed['messages'][0];
t_eq('1abcDe-0001AB-XY', $m['id'], 'the message id is read');
t_eq('sender@example.com', $m['sender'], 'and the envelope sender');
t_eq(2, count($m['recipients']), 'both recipients are kept');
t_ok(empty($m['recipients'][0]['delivered']), 'a pending recipient is pending');
t_ok(!empty($m['recipients'][1]['delivered']),
     'THE "D " PREFIX: a recipient already delivered to is marked, not listed '
   . 'as pending — showing it as pending tells the operator the opposite of '
   . 'the truth');

$f = $parsed['messages'][1];
t_ok(!empty($f['frozen']), 'a frozen message is recognised');
t_ok(!empty($f['bounce']),
     'and an empty envelope sender is recognised as a bounce, which is a '
   . 'different problem from a queue full of outbound mail');
t_eq('<>', $f['sender'], 'with the sender shown as <>');

// Ages, so "older than" means something.
t_eq(25,   MailQueue::ageMinutes('25m'), 'minutes');
t_eq(180,  MailQueue::ageMinutes('3h'),  'hours');
t_eq(2880, MailQueue::ageMinutes('2d'),  'days');
t_eq(0,    MailQueue::ageMinutes(''),    'and nothing unparseable becomes a number');

// Sizes, for "largest first".
t_eq(2560,    MailQueue::sizeBytes('2.5K'), 'K');
t_eq(1153433, MailQueue::sizeBytes('1.1M'), 'M');
t_eq(0,       MailQueue::sizeBytes('junk'), 'and junk is zero, not a crash');

// Direction. Without /etc/localdomains we cannot tell, and guessing would be
// worse than saying so.
$dir = MailQueue::directionOf([['address' => 'a@nowhere.invalid']]);
t_ok(in_array($dir, ['outbound', 'unknown'], true),
     'direction is outbound or honestly unknown, never a guess');

// Everything that touches the queue is bounded.
$mqSrc = t_code(dirname(__DIR__) . '/backend/lib/MailQueue.php');
t_contains($mqSrc, 'CACHE_TTL',
     'the snapshot is cached, so refining a search does not re-run exim -bp '
   . 'on a large queue');
t_contains($mqSrc, 'MAX_MESSAGES',  'parsing is capped');
t_contains($mqSrc, 'MAX_DEEP_READS', 'and subject search is capped');
t_contains($mqSrc, 'deep_truncated',
     'with the cap REPORTED — a search that quietly examined only part of the '
   . 'queue would be worse than one that refuses');
t_contains($mqSrc, 'timeout ',
     'exigrep runs under a timeout, because it scans the whole main log');
t_contains($mqSrc, 'nice -n 19', 'and everything runs at low priority');

// Actions reuse MailGuard rather than reimplementing the caps and the
// "did it actually leave the queue" check. Two copies of a destructive path
// is one too many.
$mqRoute = t_fn_body((string)file_get_contents(dirname(__DIR__) . '/backend/api/index.php'),
                     'routeMailQueue', 'php');
t_ok($mqRoute !== '', 'there is a mailqueue route');
t_contains($mqRoute, "Auth::requireRole('admin'", 'admin only');
t_contains($mqRoute, 'MailGuard::deliverMessages',
     'delivery reuses the bounded implementation');
t_contains($mqRoute, 'MailGuard::deleteMessages', 'and so does deletion');
t_contains($mqRoute, "empty(\$body['confirm'])", 'both are confirmed');
t_contains($mqRoute, 'MailQueue::invalidate',
     'and the cached snapshot is dropped afterwards, so the listing does not '
   . 'show messages that are no longer there');

// It is a SECTION, not a tab on Spam Monitor.
$mqHtml = (string)file_get_contents(dirname(__DIR__) . '/frontend/index.html');
$mqApp  = (string)file_get_contents(dirname(__DIR__) . '/frontend/js/app.js');
t_contains($mqHtml, 'data-page="mailqueue"', 'Mail Queue has its own nav entry');
t_contains($mqHtml, 'id="page-mailqueue"', 'and its own page');
t_ok(strpos($mqHtml, 'data-mgtab="mailqueue"') === false,
     'and is NOT a tab inside Spam Monitor');
t_contains($mqApp, "mailqueue:  ['Loading mail queue…'",
     'with a page loader, so it fills on open');
t_contains($mqApp, 'function loadMailQueue', 'behind a real function');

// Bulk buttons enable BY CLASS, the lesson from the dead bulk button in 4.13.
$bar = t_fn_body($mqApp, 'mqUpdateBar');
t_contains($bar, "querySelectorAll('.mq-action')",
     'bulk actions enable by class, so one added later works without anybody '
   . 'editing a list');
t_contains($bar, 'ids.length === 0', 'driven by the selection');
