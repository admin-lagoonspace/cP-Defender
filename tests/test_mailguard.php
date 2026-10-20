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
t_contains($app, "case 'mailguard': loadMailGuard(); loadMailSettings();",
     'opening the page loads both the data and the settings form');
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

// Headers only — never the body.
t_contains($mg, '-Mvh', 'message inspection reads headers');
t_ok(strpos($mg, '-Mvb') === false,
     "and never the body, which is a customer's private mail");

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
