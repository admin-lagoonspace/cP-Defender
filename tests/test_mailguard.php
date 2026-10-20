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
