<?php
/**
 * DNSBL interpretation.
 *
 * A DNSBL answers with a 127.0.0.x address whose last octet encodes WHY an
 * address is listed. But 127.255.255.x means the query was REFUSED — usually
 * rate-limiting or an unregistered resolver — and is not a listing at all.
 *
 * Treating a refusal as a hit would mark every address on the internet as
 * blacklisted, including the customer's own server, and the UI would show a
 * server in perfect standing as listed on a dozen blocklists. That is a
 * confidence-destroying false positive in the panel a customer is most likely
 * to check against a known-good address.
 */

require_once __DIR__ . '/assert.php';
require __DIR__ . '/bootstrap.php';

$lists = BlocklistRegistry::LISTS;
t_ok(is_array($lists) && count($lists) > 0, 'the registry defines blocklists');

// Every entry needs the fields the UI renders, or the panel shows blanks.
$missing = [];
foreach ($lists as $key => $l) {
    foreach (['zone', 'name', 'category'] as $field) {
        if (!isset($l[$field]) || $l[$field] === '') {
            $missing[] = "{$key}.{$field}";
        }
    }
}
t_eq(0, count($missing), 'every blocklist entry is fully described'
    . ($missing ? ' — missing: ' . implode(', ', array_slice($missing, 0, 5)) : ''));

// ── Refusals are not listings ────────────────────────────────────────────────
// REFUSAL_PREFIXES is private, so assert on the source: if this guard is ever
// dropped, the product begins reporting every address on the internet as
// blacklisted -- including the customer's own server.
$src = t_code(dirname(__DIR__) . '/backend/lib/BlocklistRegistry.php');
t_contains($src, '127.255.255.', 'refusal responses (127.255.255.x) are handled explicitly');
t_contains($src, 'REFUSAL_PREFIXES', 'the refusal guard is a named concept, not an inline literal');

// The guard must be consulted where answers are interpreted, not merely defined.
$checkAll = substr($src, strpos($src, 'function checkAll'));
t_contains($checkAll, 'REFUSAL_PREFIXES', 'checkAll() consults the refusal list');

// ── Categories drive the weighting, so they must be known values ─────────────
// A typo'd category silently falls out of the weighting and the list stops
// influencing the reputation score, with nothing visible to say so.
$known = ['composite', 'exploit', 'policy', 'spam'];
$unknown = [];
foreach ($lists as $key => $l) {
    if (isset($l['category']) && !in_array($l['category'], $known, true)) {
        $unknown[] = $key . '=' . $l['category'];
    }
}
t_eq(0, count($unknown), 'every category is a known weighting bucket'
    . ($unknown ? ' — ' . implode(', ', $unknown) : ''));
