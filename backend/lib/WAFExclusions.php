<?php

require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/Logger.php';

/**
 * ServerScrub — WAF rule exclusions
 *
 * ── WHY THIS EXISTS ──────────────────────────────────────────────────────────
 *
 * `waf triage` could say "arming this rule may break that site" and the
 * operator had nothing to do about it. The only two choices were to leave the
 * whole engine in DetectionOnly, or arm it and find out. On the live server
 * that meant rule 420047 firing on six real POST /shop/checkout requests from
 * one visitor on one site: arming it would have made that shop refuse orders.
 *
 * So exclusions are per rule, and optionally narrowed to one domain and one
 * URI prefix. Switching rule 420047 off everywhere to protect one shop leaves
 * the other 131 accounts unprotected against what it catches.
 *
 * ── WHY THE DATABASE AND NOT THE CONFIG FILE ─────────────────────────────────
 *
 * WAFInstaller::writeConfig() regenerates serverscrub-waf.conf from scratch on
 * every mode change. Exclusions hand-written into that file would be erased by
 * the next `waf mode on` — silently, and at the moment they matter most. They
 * live in the database and are re-rendered into the config each time it is
 * written, so there is one source of truth and arming the engine cannot lose
 * them.
 *
 * ── HOW AN EXCLUSION IS EXPRESSED ────────────────────────────────────────────
 *
 * A global exclusion is SecRuleRemoveById, which drops the rule at startup.
 * A narrowed one cannot use that directive — it has no notion of host — so it
 * becomes a rule matching the host (and URI) that disables the target rule for
 * that request only, via ctl:ruleRemoveById. This is the exclusion form the
 * CRS documentation itself prescribes.
 *
 * The ctl runs in phase 1, ahead of the phase-2 rules nearly every false
 * positive comes from. A phase-1 target rule has already been evaluated and
 * cannot be removed this way; it needs a global exclusion. The CLI says so
 * rather than leaving the operator to discover it.
 */
class WAFExclusions
{
    /**
     * ── THE RULE ID MAP ──────────────────────────────────────────────────────
     *
     * ModSecurity ids 1–99,999 are reserved for local use and CRS owns
     * 900,000+, so nothing here can collide with CRS. What it CAN collide with
     * is the product's other rule writer. A duplicate id is not a warning:
     *
     *     ModSecurity: Found another rule with the same id
     *
     * is Apache refusing the entire configuration, and on 7 Nov that was every
     * one of 132 accounts returning 502 for ten hours. It was reproduced
     * deliberately by planting a custom rule at id:15001 — the id this class
     * generates for exclusion row 1 — because the band below 15,000 was
     * documented as "for addCustomRule()" and addCustomRule() validated
     * nothing at all.
     *
     * So the two writers get DISJOINT bands, enforced at both ends:
     *
     *   below 15,000    hand-written rules an operator may already have. We
     *                   never generate into it.
     *   15,000–19,999   the generated host/path exclusion rules in this class:
     *                   ID_BASE + the exclusion's row id, so 5,000 of them.
     *   20,000–29,999   WAF::addCustomRule(), where the operator picks the id.
     *                   Enforced there against CUSTOM_ID_MIN/MAX and against
     *                   generatedIds() — the ids this class has actually
     *                   emitted — so neither band can be entered from the
     *                   other side.
     */
    const ID_BASE = 15000;
    const ID_CEIL = 19999;

    /** The band WAF::addCustomRule() must stay inside. Disjoint from the above. */
    const CUSTOM_ID_MIN = 20000;
    const CUSTOM_ID_MAX = 29999;

    /**
     * The generated rule id for one exclusion row, or null when that row needs
     * no rule of its own (a server-wide exclusion is SecRuleRemoveById, which
     * defines nothing and so cannot clash with anything).
     */
    public static function generatedId(array $row): ?int
    {
        if ((string) ($row['domain'] ?? '') === '' && (string) ($row['uri_prefix'] ?? '') === '') {
            return null;
        }
        return self::ID_BASE + (int) $row['id'];
    }

    /**
     * Every rule id this class currently renders into the Apache config.
     *
     * Read by WAF::addCustomRule() before it writes, so a custom rule cannot
     * be given an id an exclusion is already using. Bands alone would almost
     * do it; this is the check that holds when a band is widened later.
     *
     * @return array<int,int>
     */
    public static function generatedIds(): array
    {
        $ids = [];
        foreach (self::all() as $row) {
            $id = self::generatedId($row);
            if ($id !== null) { $ids[] = $id; }
        }
        return $ids;
    }

    /** @return array<int,array<string,mixed>> newest first */
    public static function all(): array
    {
        return Database::fetchAll('SELECT * FROM waf_exclusions ORDER BY id DESC');
    }

    public static function get(int $id): ?array
    {
        return Database::fetchOne('SELECT * FROM waf_exclusions WHERE id = ?', [$id]);
    }

    /**
     * Add one exclusion.
     *
     * Every field here is interpolated into an Apache config file, so each is
     * validated against what it is allowed to be rather than escaped after the
     * fact. A rejected input is an error the operator sees; a quoted one would
     * be a directive nobody can read.
     *
     * @param string $ruleId    ModSecurity rule id, digits only
     * @param string $domain    '' for every site
     * @param string $uriPrefix '' for every path; otherwise must start with /
     * @param string $reason    free text, recorded for whoever reads this later
     */
    public static function add(string $ruleId, string $domain = '',
                               string $uriPrefix = '', string $reason = ''): array
    {
        $ruleId    = trim($ruleId);
        $domain    = strtolower(trim($domain));
        $uriPrefix = trim($uriPrefix);

        if (!preg_match('/^[0-9]{1,12}$/', $ruleId)) {
            return ['success' => false, 'error' => 'Rule id must be digits only'];
        }
        if ($domain !== '' && !preg_match('/^[a-z0-9]([a-z0-9.\-]{0,252}[a-z0-9])?$/', $domain)) {
            return ['success' => false, 'error' => 'Not a hostname: ' . $domain];
        }
        if ($uriPrefix !== '') {
            if ($uriPrefix[0] !== '/') {
                return ['success' => false, 'error' => 'URI prefix must start with /'];
            }
            // Anything that could end the quoted directive or begin a new one.
            if (preg_match('/["\'\\\\\r\n]/', $uriPrefix)) {
                return ['success' => false,
                        'error' => 'URI prefix contains a quote, backslash or newline'];
            }
            if (strlen($uriPrefix) > 255) {
                return ['success' => false, 'error' => 'URI prefix is too long'];
            }
        }
        $reason = (string) preg_replace('/[\r\n]+/', ' ', mb_substr($reason, 0, 300));

        $dupe = Database::fetchOne(
            'SELECT id FROM waf_exclusions WHERE rule_id = ? AND domain = ? AND uri_prefix = ?',
            [$ruleId, $domain, $uriPrefix]
        );
        if ($dupe) {
            return ['success'  => false,
                    'error'    => 'Already excluded (id ' . $dupe['id'] . ')',
                    'existing' => (int) $dupe['id']];
        }

        $id = Database::insert('waf_exclusions', [
            'rule_id'    => $ruleId,
            'domain'     => $domain,
            'uri_prefix' => $uriPrefix,
            'reason'     => $reason,
        ]);

        Logger::info('WAF exclusion added: ' . self::describe([
            'id' => $id, 'rule_id' => $ruleId, 'domain' => $domain,
            'uri_prefix' => $uriPrefix, 'reason' => $reason,
        ]));

        return ['success' => true, 'id' => $id,
                'scoped'  => $domain !== '' || $uriPrefix !== ''];
    }

    public static function remove(int $id): array
    {
        $row = self::get($id);
        if (!$row) {
            return ['success' => false, 'error' => 'No exclusion with id ' . $id];
        }
        Database::query('DELETE FROM waf_exclusions WHERE id = ?', [$id]);
        Logger::info('WAF exclusion removed: ' . self::describe($row));
        return ['success' => true, 'removed' => $row];
    }

    /** One line a human can read, for logs, the CLI and the panel. */
    public static function describe(array $row): string
    {
        $scope = [];
        if ((string) ($row['domain'] ?? '') !== '') {
            $scope[] = 'host ' . $row['domain'];
        }
        if ((string) ($row['uri_prefix'] ?? '') !== '') {
            $scope[] = 'path ' . $row['uri_prefix'] . '*';
        }
        $where = $scope ? implode(', ', $scope) : 'EVERY site and path';
        $s = 'rule ' . ($row['rule_id'] ?? '?') . ' disabled for ' . $where;
        if ((string) ($row['reason'] ?? '') !== '') { $s .= ' — ' . $row['reason']; }
        return $s;
    }

    /**
     * The config fragment, for inclusion after the CRS rules.
     *
     * Returns '' when there is nothing to exclude, so a server with no
     * exclusions gets a config byte-identical to the one it had before this
     * feature existed.
     *
     * @throws RuntimeException when an exclusion cannot be rendered. The
     *         caller must fail rather than write a config without it: a
     *         dropped exclusion means a rule the operator switched off is
     *         armed against a live site, which is the one outcome this
     *         mechanism exists to prevent.
     */
    public static function render(): string
    {
        $rows = self::all();
        if (!$rows) { return ''; }

        $out = [
            '',
            '    # ── Rule exclusions ──────────────────────────────────────────',
            '    # Generated from the serverscrub database. Do not edit here:',
            '    # this file is rewritten whenever the WAF mode changes. Use',
            '    #   serverscrub waf exclude add|list|rm',
            '',
        ];

        foreach ($rows as $row) {
            $rid    = (string) $row['rule_id'];
            $domain = (string) $row['domain'];
            $uri    = (string) $row['uri_prefix'];
            $out[]  = '    # [' . $row['id'] . '] ' . self::describe($row);

            if ($domain === '' && $uri === '') {
                $out[] = '    SecRuleRemoveById ' . $rid;
                $out[] = '';
                continue;
            }

            $genId = (int) self::generatedId($row);
            if ($genId > self::ID_CEIL) {
                throw new RuntimeException(
                    'Exclusion ' . $row['id'] . ' needs generated rule id ' . $genId
                    . ', outside the band ' . self::ID_BASE . '-' . self::ID_CEIL
                    . ' reserved for generated exclusions. ' . self::CUSTOM_ID_MIN . ' and above '
                    . 'belongs to custom rules, and reusing an id there is the duplicate-id '
                    . 'failure that stops Apache starting'
                );
            }

            if ($domain !== '' && $uri !== '') {
                $out[] = '    SecRule REQUEST_HEADERS:Host "@streq ' . $domain . '" \\';
                $out[] = '        "id:' . $genId . ',phase:1,pass,nolog,chain"';
                $out[] = '        SecRule REQUEST_URI "@beginsWith ' . $uri . '" \\';
                $out[] = '            "ctl:ruleRemoveById=' . $rid . '"';
            } elseif ($domain !== '') {
                $out[] = '    SecRule REQUEST_HEADERS:Host "@streq ' . $domain . '" \\';
                $out[] = '        "id:' . $genId
                       . ',phase:1,pass,nolog,ctl:ruleRemoveById=' . $rid . '"';
            } else {
                $out[] = '    SecRule REQUEST_URI "@beginsWith ' . $uri . '" \\';
                $out[] = '        "id:' . $genId
                       . ',phase:1,pass,nolog,ctl:ruleRemoveById=' . $rid . '"';
            }
            $out[] = '';
        }

        return implode("\n", $out) . "\n";
    }
}
