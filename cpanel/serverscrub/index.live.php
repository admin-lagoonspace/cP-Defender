<?php
/**
 * ServerScrub - cPanel user page.
 *
 * Runs as the cPanel user, under cpsrvd, inside the user's own session. It
 * reads ONE file: ~/.serverscrub/report.json, written by the privileged side
 * after each scan.
 *
 * It deliberately does not talk to the ServerScrub API or database. Both are
 * root-owned (the database directory is 0700) and server-wide; reaching them
 * from a page every hosting customer can load would mean either a setuid
 * helper or loosening those permissions, and each would hand every customer on
 * the box a route to the whole server's security data. Reading a file that
 * lives in the caller's own home makes cross-account disclosure impossible by
 * construction rather than by a filter someone has to maintain.
 *
 * The previous version of this file was a bare redirect to the WHM dashboard,
 * which a cPanel user cannot authenticate to -- so the menu entry, where it
 * appeared at all, led to a login screen the user could never pass.
 */

$user = $_SERVER['REMOTE_USER'] ?? '';
if ($user === '' && function_exists('posix_getpwuid') && function_exists('posix_geteuid')) {
    $pw   = @posix_getpwuid(@posix_geteuid());
    $user = is_array($pw) ? ($pw['name'] ?? '') : '';
}

$home = $_SERVER['HOME'] ?? '';
if ($home === '' && function_exists('posix_getpwnam') && $user !== '') {
    $pw   = @posix_getpwnam($user);
    $home = is_array($pw) ? ($pw['dir'] ?? '') : '';
}

/**
 * "Scan my account now".
 *
 * All this does is leave a timestamp in the caller's own home. The privileged
 * side reads it on its next tick, decides whether to honour it, and starts the
 * scan itself -- this page cannot start one, and must not be able to.
 *
 * The cooldown is displayed here but enforced there. A customer who edits this
 * file by hand gains nothing except a request that is declined slightly later.
 *
 * No CSRF token of our own: cpsrvd rejects a request that does not carry the
 * session token it put in the URL, so a cross-site POST never reaches this
 * code. And the worst a forged one could achieve is a scan of the victim's own
 * account, rate-limited, which is what the button does anyway.
 */
$requested = false;
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST'
    && isset($_POST['scan_now']) && $home !== '') {
    $dir = rtrim($home, '/') . '/.serverscrub';
    if (!is_dir($dir)) { @mkdir($dir, 0700, true); }
    if (is_dir($dir) && !is_link($dir)) {
        $tmp = $dir . '/.scan-request.' . getmypid();
        $ok  = @file_put_contents($tmp, json_encode([
            'requested_at' => time(),
            'source'       => 'cpanel-plugin',
        ]));
        // Written aside and moved into place, so the privileged side never
        // reads a half-written file and discards the request as malformed.
        if ($ok !== false) {
            @chmod($tmp, 0600);
            @rename($tmp, $dir . '/scan-request.json');
            $requested = true;
        } else {
            @unlink($tmp);
        }
    }
}

$report = null;
$error  = '';
if ($home === '') {
    $error = 'Could not determine your home directory.';
} else {
    $path = rtrim($home, '/') . '/.serverscrub/report.json';
    if (!is_file($path)) {
        $error = 'No security report has been generated for your account yet.';
    } else {
        $raw = @file_get_contents($path);
        $decoded = $raw === false ? null : json_decode($raw, true);
        if (!is_array($decoded)) {
            $error = 'Your security report could not be read.';
        } else {
            $report = $decoded;
        }
    }
}

/** Everything below is rendered through this. */
function e($v): string {
    return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function ago(int $ts): string {
    if ($ts <= 0) { return 'never'; }
    $d = time() - $ts;
    if ($d < 60)    { return $d . 's ago'; }
    if ($d < 3600)  { return intdiv($d, 60) . 'm ago'; }
    if ($d < 86400) { return intdiv($d, 3600) . 'h ago'; }
    return intdiv($d, 86400) . 'd ago';
}

$s = $report['summary'] ?? [];
?>
<?php
/**
 * Rendered inside cPanel's own frame, not as a page of its own.
 *
 * This used to emit a complete HTML document, so clicking the menu entry
 * replaced cPanel with a bare page -- no left-hand menu, no way back except
 * the browser's Back button. A plugin that throws the customer out of the
 * control panel does not look like part of it.
 *
 * cPanel's LiveAPI supplies the surrounding chrome: $cpanel->header() emits
 * everything up to the content area and ->footer() closes it. The page body
 * therefore carries no doctype, <html>, <head> or <body> of its own -- it is
 * buffered here and handed to whichever wrapper applies.
 *
 * The standalone wrapper is kept as a fallback for when the LiveAPI class is
 * not loadable (a theme that does not provide it, or this file opened
 * directly during development). Rendering nothing at all because the chrome
 * is unavailable would be worse than rendering without it.
 */
ob_start();
?>
<style>
  /* Everything is scoped to .sscrub.
   *
   * This block used to define its variables on :root and style `body` and `*`
   * directly, which was fine while the page was a document of its own. Inside
   * cPanel's frame those selectors reach cPanel's markup: --bg, --fg and
   * --line are generic enough to collide with the theme's own, and `*` would
   * reset box-sizing for the whole control panel.
   *
   * The container takes no background and inherits its colour, so the panel
   * sits on whatever cPanel is using rather than painting a rectangle of a
   * different shade in the middle of it. */
  .sscrub {
    /* cPanel's palette, not ours. These values are taken from Jupiter's own
     * panels and buttons so the page reads as part of the control panel
     * rather than as something embedded in it. */
    --dim:#687079; --line:#dfe3e8; --chip:#f6f7f9;
    --blue:#1976b6; --red:#c0392b; --amber:#b9770e; --green:#1d7a46;
    background:transparent; color:inherit;
    /* No font stack. cPanel sets one on its own body and inheriting it is the
     * single biggest thing that makes an embedded page look native. */
  }

  /* NO dark-mode block.
   *
   * There was one, keyed on prefers-color-scheme, and it is why the page
   * rendered dark inside cPanel's light panel: the customer's OS said dark,
   * cPanel said light, and we sided with the OS. A plugin does not get a
   * vote on the control panel's theme -- cPanel owns it, and if it gains a
   * dark mode this page follows it for free by inheriting. */
  .sscrub *, .sscrub *::before, .sscrub *::after { box-sizing:border-box; }

  .sscrub h1 { font-size:1.35rem; margin:0 0 2px; font-weight:600; }
  .sscrub .sub { color:var(--dim); font-size:.82rem; margin-bottom:18px; }
  .sscrub .tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:22px; }
  .sscrub .tile { border:1px solid var(--line); border-radius:4px; padding:12px 14px; background:#fff; }
  .sscrub .tile .n { font-size:1.6rem; font-weight:600; line-height:1.15; }
  .sscrub .tile .l { color:var(--dim); font-size:.75rem; text-transform:uppercase; letter-spacing:.03em; }
  .sscrub .card { border:1px solid var(--line); border-radius:4px; margin-bottom:18px;
                  overflow:hidden; background:#fff; }
  .sscrub .card > h2 { font-size:.92rem; margin:0; padding:11px 14px; border-bottom:1px solid var(--line);
               font-weight:600; background:var(--chip); }
  .sscrub table { width:100%; border-collapse:collapse; }
  .sscrub th, td { text-align:left; padding:9px 14px; border-bottom:1px solid var(--line); font-size:.82rem;
           vertical-align:top; }
  .sscrub th { color:var(--dim); font-weight:600; font-size:.74rem; text-transform:uppercase; letter-spacing:.03em; }
  .sscrub tr:last-child td { border-bottom:0; }
  .sscrub .mono { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:.78rem;
          word-break:break-all; }
  .sscrub .tag { display:inline-block; padding:1px 7px; border-radius:10px; font-size:.7rem; font-weight:600;
         border:1px solid currentColor; }
  .sscrub .red{color:var(--red)} .sscrub .amber{color:var(--amber)} .sscrub .green{color:var(--green)} .sscrub .dimc{color:var(--dim)}
  .sscrub .ok { padding:22px 14px; color:var(--dim); text-align:center; }
  .sscrub .note { border:1px solid var(--line); border-radius:8px; padding:16px; color:var(--dim); }
  .sscrub .foot { color:var(--dim); font-size:.74rem; margin-top:8px; }
  .sscrub .btn { font:inherit; font-weight:400; font-size:.9rem; padding:6px 14px; border-radius:3px;
         border:1px solid var(--blue); background:var(--blue); color:#fff; cursor:pointer; }
  .sscrub .btn:hover:not(:disabled) { filter:brightness(1.08); }
  .sscrub .btn:disabled { background:var(--chip); color:var(--dim); border-color:var(--line); cursor:default; }
  @media (max-width:560px) { .sscrub .hide-sm{display:none} }
</style>

<div class="sscrub">
<h1>ServerScrub</h1>
<div class="sub">
  Security findings for <strong><?= e($user !== '' ? $user : 'your account') ?></strong>
</div>

<?php if ($report === null): ?>
  <div class="note">
    <?= e($error) ?>
    <div class="foot">
      Reports are produced by the server-wide scan. If your hosting provider has
      only just enabled ServerScrub, one will appear after the next scheduled
      scan. Nothing is wrong with your account.
    </div>
  </div>
<?php else: ?>

  <div class="tiles">
    <div class="tile">
      <div class="n <?= ((int)($s['threats_active'] ?? 0)) ? 'red' : 'green' ?>">
        <?= (int)($s['threats_active'] ?? 0) ?>
      </div>
      <div class="l">Active threats</div>
    </div>
    <div class="tile">
      <div class="n <?= ((int)($s['cms_outdated'] ?? 0)) ? 'amber' : 'green' ?>">
        <?= (int)($s['cms_outdated'] ?? 0) ?>
      </div>
      <div class="l">Outdated apps</div>
    </div>
    <div class="tile">
      <div class="n"><?= (int)($s['cms_installs'] ?? 0) ?></div>
      <div class="l">Applications</div>
    </div>
    <div class="tile">
      <div class="n <?= ((int)($s['file_changes'] ?? 0)) ? 'amber' : 'green' ?>">
        <?= (int)($s['file_changes'] ?? 0) ?>
      </div>
      <div class="l">Changed files</div>
    </div>
  </div>

  <?php
    $sr       = $report['scan_request'] ?? [];
    $srOn     = !empty($sr['enabled']);
    $srWait   = (int)($sr['retry_in'] ?? 0);
    $srQueued = $requested || !empty($sr['pending']);
    function hms(int $s): string {
        if ($s <= 0)    { return 'now'; }
        if ($s < 3600)  { return 'in ' . max(1, intdiv($s, 60)) . ' minute(s)'; }
        return 'in ' . intdiv($s, 3600) . ' hour(s)';
    }
  ?>
  <?php if ($srOn): ?>
  <div class="card">
    <h2>Scan my account</h2>
    <div style="padding:14px">
      <?php if ($srQueued): ?>
        <div class="tag green">Queued</div>
        <div class="foot" style="margin-top:7px">
          Your scan is waiting to run. Scans are started a few at a time so they
          do not slow the server down for everyone, so this can take a little
          while. This page will show the results once it has finished.
        </div>
      <?php elseif ($srWait > 0): ?>
        <button class="btn" disabled>Scan my account</button>
        <div class="foot" style="margin-top:7px">
          You can request another scan <?= e(hms($srWait)) ?>.
          Last scan of your account: <?= e(ago((int)($sr['last_run_at'] ?? 0))) ?>.
        </div>
      <?php else: ?>
        <form method="post" style="margin:0">
          <button class="btn" type="submit" name="scan_now" value="1">Scan my account</button>
        </form>
        <div class="foot" style="margin-top:7px">
          Checks the files in your home directory for malware. It runs in the
          background; you do not need to keep this page open.
        </div>
      <?php endif; ?>
    </div>
  </div>
  <?php endif; ?>

  <?php $threats = $report['threats'] ?? []; ?>
  <div class="card">
    <h2>Detected threats</h2>
    <?php if (!$threats): ?>
      <div class="ok">No threats have been found in your account.</div>
    <?php else: ?>
      <table>
        <thead><tr>
          <th>File</th><th>Detected as</th><th>Severity</th>
          <th class="hide-sm">Status</th><th class="hide-sm">Found</th>
        </tr></thead>
        <tbody>
        <?php foreach ($threats as $t):
          $sev = strtolower((string)($t['severity'] ?? ''));
          $cls = $sev === 'critical' || $sev === 'high' ? 'red' : ($sev === 'medium' ? 'amber' : 'dimc');
        ?>
          <tr>
            <td class="mono"><?= e($t['relative_path'] ?? $t['file_path'] ?? '') ?></td>
            <td><?= e($t['threat_name'] ?? $t['threat_type'] ?? 'unknown') ?></td>
            <td><span class="tag <?= $cls ?>"><?= e($t['severity'] ?? '?') ?></span></td>
            <td class="hide-sm"><?= e($t['status'] ?? '') ?></td>
            <td class="hide-sm dimc"><?= e(ago((int)($t['detected_at'] ?? 0))) ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>
  </div>

  <?php $cms = $report['cms'] ?? []; ?>
  <div class="card">
    <h2>Applications</h2>
    <?php if (!$cms): ?>
      <div class="ok">No WordPress, Joomla or Drupal installations were found in your account.</div>
    <?php else: ?>
      <table>
        <thead><tr>
          <th>Application</th><th>Version</th><th>Location</th><th class="hide-sm">Notes</th>
        </tr></thead>
        <tbody>
        <?php foreach ($cms as $c):
          $names = ['wordpress' => 'WordPress', 'joomla' => 'Joomla', 'drupal' => 'Drupal'];
          $type  = (string)($c['cms_type'] ?? '');
          $out   = (int)($c['outdated'] ?? 0) === 1;
        ?>
          <tr>
            <td><?= e($names[$type] ?? $type) ?></td>
            <td class="<?= $out ? 'amber' : 'green' ?>">
              <?= e($c['version'] ?? 'unknown') ?><?= $out ? ' (update available)' : '' ?>
            </td>
            <td class="mono"><?= e($c['relative_path'] ?? $c['install_path'] ?? '') ?></td>
            <td class="hide-sm dimc">
              <?php $iss = is_array($c['issues'] ?? null) ? $c['issues'] : [];
                    echo $iss ? e(implode(', ', array_map(fn($i) => str_replace('_', ' ', $i), $iss))) : '—'; ?>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>
  </div>

  <?php $changes = $report['file_changes'] ?? []; ?>
  <?php if ($changes): ?>
  <div class="card">
    <h2>Changed files</h2>
    <table>
      <thead><tr><th>File</th><th>Change</th><th class="hide-sm">Noticed</th></tr></thead>
      <tbody>
      <?php foreach ($changes as $ch): ?>
        <tr>
          <td class="mono"><?= e($ch['relative_path'] ?? $ch['file_path'] ?? '') ?></td>
          <td><?= e($ch['status'] ?? '') ?></td>
          <td class="hide-sm dimc"><?= e(ago((int)($ch['last_check'] ?? 0))) ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
  <?php endif; ?>

  <div class="foot">
    Report generated <?= e(ago((int)($report['generated_at'] ?? 0))) ?>
    from the server scan that ran <?= e(ago((int)($report['last_scan_at'] ?? 0))) ?>.
    Scans are scheduled by your hosting provider. Contact them to act on anything
    listed here.
  </div>

<?php endif; ?>

</div>
<?php
$content = ob_get_clean();

// LiveAPI if it is there. require_once is guarded because this file is also
// linted and read by the test suite on machines that have no cPanel at all.
$cp = null;
if (@is_readable('/usr/local/cpanel/php/cpanel.php')) {
    require_once '/usr/local/cpanel/php/cpanel.php';
    if (class_exists('CPANEL')) {
        try { $cp = new CPANEL(); } catch (Throwable $e) { $cp = null; }
    }
}

if ($cp !== null) {
    echo $cp->header('ServerScrub Security');
    echo $content;
    echo $cp->footer();
    $cp->end();
} else {
    echo "<!DOCTYPE html>
<html lang=\"en\">
<head>
"
       . "<meta charset=\"utf-8\">
"
       . "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
"
       . "<title>ServerScrub</title>
</head>
<body>
"
       . $content
       . "
</body>
</html>
";
}
