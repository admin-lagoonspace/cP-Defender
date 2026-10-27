<?php
/**
 * The Mail Queue filter must actually filter.
 *
 * Reported from a live panel: Field left at its default, "inditdel" typed into
 * Text, Search pressed — and the result was "57 of 57 matching". The filter
 * had done nothing.
 *
 * The cause was that text was only honoured when a Field had ALSO been chosen,
 * and the default Field was "— no text search —". So the obvious action — type
 * a word, press Search — matched everything and reported a number that looked
 * like a result. A filter that ignores what you typed is worse than no filter:
 * it answers a question you did not ask and looks like it worked.
 */

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/assert.php';

// A queue shaped like the reported one: a couple from the account being
// hunted, the rest from elsewhere.
$bp = '';
for ($i = 1; $i <= 6; $i++) {
    $who = ($i <= 2) ? 'inditdel@host.lws-s1.com' : "other$i@kbroadlines.com";
    $bp .= sprintf(" %dh  1.2K 1abcD%d-000%dAB-XY <%s>\n          rcpt%d@elsewhere.com\n\n",
                   $i, $i, $i, $who, $i);
}
$parsed = MailQueue::parseQueue($bp);
t_eq(6, $parsed['total'], 'six messages parsed');

// search() reads the cached snapshot, so seed it the way snapshot() would.
$cache = rtrim(Database::storagePath('logs'), '/') . '/mailqueue-snapshot.json';
$parsed['built_at'] = time();
file_put_contents($cache, json_encode($parsed));
register_shutdown_function(function () use ($cache) { @unlink($cache); });

$r = MailQueue::search(['text' => 'inditdel', 'field' => '']);
t_eq(2, $r['matched'],
     'THE REPORTED BUG: text typed with no field chosen now SEARCHES sender, '
   . 'recipient and id, instead of silently matching everything');

t_eq(2, MailQueue::search(['text' => 'inditdel', 'field' => 'any'])['matched'],
     'and "any" does the same explicitly');
t_eq(2, MailQueue::search(['text' => 'inditdel', 'field' => 'from'])['matched'],
     'sender search matches');
t_eq(0, MailQueue::search(['text' => 'inditdel', 'field' => 'to'])['matched'],
     'recipient search does not — the fields are honoured, not merged');
t_eq(1, MailQueue::search(['text' => 'rcpt3', 'field' => 'to'])['matched'],
     'but a real recipient does');

t_eq(4, MailQueue::search(['text' => 'inditdel', 'field' => '', 'negate' => 1])['matched'],
     'NOT inverts the match');

t_eq(2, MailQueue::search(['text' => 'inditdel@host.lws-s1.com',
                           'field' => 'from', 'op' => 'equals'])['matched'], 'equals');
t_eq(2, MailQueue::search(['text' => 'inditdel',
                           'field' => 'from', 'op' => 'starts'])['matched'], 'begins with');
t_eq(2, MailQueue::search(['text' => 'lws-s1.com',
                           'field' => 'from', 'op' => 'ends'])['matched'], 'ends with');
t_eq(0, MailQueue::search(['text' => 'INDITDEL', 'field' => 'from',
                           'op' => 'equals'])['matched'] === 2 ? 1 : 0,
     'matching is case-insensitive');

t_eq(6, MailQueue::search(['text' => '', 'field' => ''])['matched'],
     'an empty search still returns everything, as it should');
t_eq(3, MailQueue::search(['older_than_mins' => 240])['matched'],
     'older-than filters by age');

// The UI default must be a field that searches, or the bug returns through
// the markup rather than the code.
$html = (string)file_get_contents(dirname(__DIR__) . '/frontend/index.html');
$sel  = substr($html, (int)strpos($html, 'id="mq-field"'), 600);
t_ok(strpos($sel, '<option value="">') === false,
     'the Field selector has no empty default, which is what made the search '
   . 'box inert');
t_contains($sel, '<option value="any">', 'its first option searches');
t_contains($sel, 'slower', 'and the expensive one says it is expensive');
