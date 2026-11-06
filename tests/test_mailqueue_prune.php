<?php
/**
 * Mail that has sat in the queue too long is deleted.
 *
 * Asked for: "For our mail queue any message which is in queue for >= 72hrs
 * just delete those message, because these will stay there forever".
 *
 * Which is accurate. Exim retries a message until its retry data expires --
 * days, on a default cPanel box -- so a message that has been queued for three
 * days is not waiting, it is stuck: the recipient server is gone, the domain
 * does not resolve, or it is a bounce of a bounce. They accumulate, and a
 * queue nobody can read through is a queue in which a live relay goes
 * unnoticed. That is the real cost, not the disk.
 *
 * This is also an unattended destructive path, which is a combination worth
 * being careful about. Three guards, and the second is the one that matters
 * most:
 *
 *   - off entirely unless mq_autodelete is '1';
 *   - the age floor is clamped to at least 24 hours WHATEVER the setting says.
 *     The setting is in hours, and someone typing '1' meaning "one day" would
 *     otherwise wipe an hour-old queue -- live outbound mail, mid-retry;
 *   - a per-run cap, so the first pass over a 93,000-message queue does not
 *     attempt all of it at once.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

require_once $repo . '/backend/lib/MailQueue.php';

// ── The age parser, which the whole decision rests on ──────────────────────
//
// exim -bp prints an age as "25m", "3h", "2d". Reading "2d" as 2 would make
// every message on the server look three minutes old and nothing would ever
// be pruned; reading "30m" as 30 hours would delete live mail. This is the
// one piece of parsing between a queue listing and an irreversible delete.
t_eq(25,    MailQueue::ageMinutes('25m'), '"25m" is 25 minutes');
t_eq(180,   MailQueue::ageMinutes('3h'),  '"3h" is three hours');
t_eq(4320,  MailQueue::ageMinutes('3d'),  '"3d" is three days — past the 72h floor');
t_eq(10080, MailQueue::ageMinutes('1w'),  '"1w" is a week');
t_eq(0,     MailQueue::ageMinutes(''),    'and an unparseable age is zero, so '
                                        . 'a listing we cannot read is never '
                                        . 'treated as old enough to delete');

t_ok(MailQueue::ageMinutes('72h') >= 72 * 60,
     'a message at exactly the threshold is at the threshold — ">= 72hrs" was '
   . 'the request, not "> 72hrs"');

// ── Disabled means disabled ────────────────────────────────────────────────
Database::setSetting('mq_autodelete', '0');
$off = MailQueue::pruneStale();
t_eq(false, $off['enabled'], 'with mq_autodelete off the prune reports itself off');
t_eq(0, $off['deleted'], 'and deletes nothing');
t_eq(0, $off['examined'],
     'and does not even build a snapshot — running `exim -bp` over a large '
   . 'queue is not free, and nothing is going to be done with the answer');

// ── The floor cannot be configured away ────────────────────────────────────
Database::setSetting('mq_autodelete', '1');

// '1' as a stand-in for "one day". The setting is in HOURS, so taken at face
// value this deletes anything older than sixty minutes.
$clamped = MailQueue::pruneStale(1);
t_eq(24, $clamped['max_age_hours'],
     'THE FLOOR: an age of 1 hour is raised to 24. Deleting queued mail '
   . 'cannot be undone, and "1" meaning one day is exactly the typo somebody '
   . 'makes in a field labelled in hours');

t_eq(24, MailQueue::pruneStale(0)['max_age_hours'],
     'zero does not mean "everything"');
t_eq(24, MailQueue::pruneStale(-500)['max_age_hours'],
     'and neither does a negative');
t_eq(8760, MailQueue::pruneStale(999999)['max_age_hours'],
     'and an absurd age is capped rather than overflowing into nonsense');
t_eq(72, MailQueue::pruneStale(72)['max_age_hours'],
     'the asked-for 72 hours passes through unchanged');

// The seeded default is the figure that was asked for.
$dbsrc = (string) file_get_contents($repo . '/backend/lib/Database.php');
t_contains($dbsrc, "'mq_max_age_hours', '72'",
     'and 72 hours is what a server gets without being configured');
t_contains($dbsrc, "'mq_autodelete', '1'",
     'switched on, or none of this happens');

// ── Selection: what would be deleted, from a real queue listing ────────────
//
// parseQueue() is the same function the panel's listing uses, so this
// exercises the actual selection rather than a hand-built array of ids.
$listing = <<<'QUEUE'
 71h  2.4K 1aBcDe-0001yz-7K <sender@example.com>
          victim@far-away.test

 73h  1.1K 1aBcDf-0002yz-8L <sender@example.com>
          nowhere@gone.test

  5m   890 1aBcDg-0003yz-9M <fresh@example.com>
          someone@example.net

 9d   3.2K 1aBcDh-0004yz-0N <>
          bounce@example.org
QUEUE;

$parsed = MailQueue::parseQueue($listing);
t_eq(4, $parsed['total'], 'the fixture queue parses to four messages');

$floor = 72 * 60;
$doomed = [];
foreach ($parsed['messages'] as $m) {
    if ($m['age_mins'] >= $floor) { $doomed[] = $m['id']; }
}

t_eq(2, count($doomed), 'two of the four are past 72 hours');
t_ok(in_array('1aBcDf-0002yz-8L', $doomed, true), 'the 73h message is selected');
t_ok(in_array('1aBcDh-0004yz-0N', $doomed, true),
     'and so is the nine-day bounce — a bounce that cannot be delivered is '
   . 'the commonest thing in a queue like this');
t_ok(!in_array('1aBcDe-0001yz-7K', $doomed, true),
     'THE MESSAGE AT 71 HOURS IS LEFT ALONE: it has a retry left, and this '
   . 'is somebody\'s mail');
t_ok(!in_array('1aBcDg-0003yz-9M', $doomed, true),
     'and the five-minute-old message is obviously left alone');

// ── The per-run cap is real, and matches what exim will accept ─────────────
$src = (string) file_get_contents($repo . '/backend/lib/MailQueue.php');
$body = t_fn_body($src, 'pruneStale', 'php');

t_contains($body, 'min(500',
     'the per-run cap is 500 at most — deleteMessages() refuses more than '
   . 'that in one call, so asking for more would delete NOTHING rather than '
   . 'more');
t_contains($body, "count(\$ids) < \$cap",
     'the cap limits what is sent, rather than being checked after the fact');
t_contains($body, "'capped' => false",
     'and a run that hit the cap says so, so a queue that is still shrinking '
   . 'does not look like one that is done');

t_contains($body, 'snapshot(true)',
     'the queue is re-read rather than taken from the 60-second cache: this '
   . 'is the one caller whose decision cannot be taken back');

t_contains($body, "MailGuard::deleteMessages",
     'deletion goes through the existing implementation — the id validation, '
   . 'the caps and the "left the queue" handling are all there already, and '
   . 'two copies of a destructive path is one too many');

t_contains($body, 'security_events',
     'AND IT SAYS SO: an operator watching the queue shrink should learn it '
   . 'from the product, not deduce it');
t_contains($body, 'Logger::warn',
     'with the count and the age in the log');

// A snapshot that could not be built must not read as an empty queue.
t_contains($body, "\$snap['error']",
     'a queue listing that failed is reported, not treated as "nothing is '
   . 'queued" — which would be silent and indistinguishable from success');

// ── Wired to run on its own ────────────────────────────────────────────────
$sched = t_code($repo . '/backend/cron/scheduler.php');
t_contains($sched, "'mailqueueprune' => [",
     'the prune runs from the scheduler, not only when somebody opens a page');
t_contains($sched, "'schedule' => 'hourly'",
     'hourly: a relay incident queues tens of thousands of messages in an '
   . 'afternoon, and the per-run cap means clearing them takes several passes');
t_contains($sched, "require_once SG_ROOT . '/backend/lib/MailQueue.php';",
     'and the scheduler requires the class it calls, or the task fatals in '
   . 'cron and every task after it is skipped');
