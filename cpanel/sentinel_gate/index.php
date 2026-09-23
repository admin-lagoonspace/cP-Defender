<?php
/**
 * Sentinel Gate - cPanel user page.
 *
 * Runs as the cPanel user, under cpsrvd, inside the user's own session. It
 * reads ONE file: ~/.sentinel-gate/report.json, written by the privileged side
 * after each scan.
 *
 * It deliberately does not talk to the Sentinel Gate API or database. Both are
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

$report = null;
$error  = '';
if ($home === '') {
    $error = 'Could not determine your home directory.';
} else {
    $path = rtrim($home, '/') . '/.sentinel-gate/report.json';
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
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel Gate</title>
<style>
  :root {
    --bg:#fff; --fg:#33383c; --dim:#7d8792; --line:#e3e7ea;
    --blue:#1178b3; --red:#c0392b; --amber:#c87f0a; --green:#1d7a46;
    --chip:#f5f7f8;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg:#1b1f23; --fg:#e6e9ec; --dim:#98a2ad; --line:#2d333a;
      --chip:#22272c;
    }
  }
  * { box-sizing:border-box; }
  body { margin:0; padding:16px; background:var(--bg); color:var(--fg);
         font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  h1 { font-size:1.35rem; margin:0 0 2px; font-weight:600; }
  .sub { color:var(--dim); font-size:.82rem; margin-bottom:18px; }
  .tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:22px; }
  .tile { border:1px solid var(--line); border-radius:8px; padding:12px 14px; background:var(--chip); }
  .tile .n { font-size:1.6rem; font-weight:600; line-height:1.15; }
  .tile .l { color:var(--dim); font-size:.75rem; text-transform:uppercase; letter-spacing:.03em; }
  .card { border:1px solid var(--line); border-radius:8px; margin-bottom:20px; overflow:hidden; }
  .card > h2 { font-size:.92rem; margin:0; padding:11px 14px; border-bottom:1px solid var(--line);
               font-weight:600; background:var(--chip); }
  table { width:100%; border-collapse:collapse; }
  th, td { text-align:left; padding:9px 14px; border-bottom:1px solid var(--line); font-size:.82rem;
           vertical-align:top; }
  th { color:var(--dim); font-weight:600; font-size:.74rem; text-transform:uppercase; letter-spacing:.03em; }
  tr:last-child td { border-bottom:0; }
  .mono { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:.78rem;
          word-break:break-all; }
  .tag { display:inline-block; padding:1px 7px; border-radius:10px; font-size:.7rem; font-weight:600;
         border:1px solid currentColor; }
  .red{color:var(--red)} .amber{color:var(--amber)} .green{color:var(--green)} .dimc{color:var(--dim)}
  .ok { padding:22px 14px; color:var(--dim); text-align:center; }
  .note { border:1px solid var(--line); border-radius:8px; padding:16px; color:var(--dim); }
  .foot { color:var(--dim); font-size:.74rem; margin-top:8px; }
  @media (max-width:560px) { body{padding:12px} .hide-sm{display:none} }
</style>
</head>
<body>

<h1>Sentinel Gate</h1>
<div class="sub">
  Security findings for <strong><?= e($user !== '' ? $user : 'your account') ?></strong>
</div>

<?php if ($report === null): ?>
  <div class="note">
    <?= e($error) ?>
    <div class="foot">
      Reports are produced by the server-wide scan. If your hosting provider has
      only just enabled Sentinel Gate, one will appear after the next scheduled
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
    Scans are scheduled by your hosting provider; contact them to have one run sooner,
    or to act on anything listed here.
  </div>

<?php endif; ?>

</body>
</html>
