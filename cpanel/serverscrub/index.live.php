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
 * The allowance is displayed here but enforced there. A customer who edits this
 * file by hand gains nothing except a request that is declined slightly later.
 *
 * No CSRF token of our own: cpsrvd rejects a request that does not carry the
 * session token it put in the URL, so a cross-site POST never reaches this
 * code. And the worst a forged one could achieve is a scan of the victim's own
 * account, rate-limited, which is what the button does anyway.
 */

/**
 * Leave a file in this account's own ~/.serverscrub.
 *
 * Written aside and moved into place, so the privileged side never reads a
 * half-written file and discards it as malformed.
 */
function sg_leave(string $home, string $name, array $data): bool {
    $dir = rtrim($home, '/') . '/.serverscrub';
    if (!is_dir($dir)) { @mkdir($dir, 0700, true); }
    if (!is_dir($dir) || is_link($dir)) { return false; }

    $tmp = $dir . '/.' . $name . '.' . getmypid();
    if (@file_put_contents($tmp, json_encode($data)) === false) {
        @unlink($tmp);
        return false;
    }
    @chmod($tmp, 0600);
    return @rename($tmp, $dir . '/' . $name);
}

$requested  = false;
$cancelling = false;
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && $home !== '') {
    if (isset($_POST['scan_now'])) {
        $requested = sg_leave($home, 'scan-request.json', [
            'requested_at' => time(),
            'source'       => 'cpanel-plugin',
        ]);
    } elseif (isset($_POST['cancel_scan'])) {
        /**
         * Stopping a scan takes two steps, because there are two things it
         * could be.
         *
         * A request that has not been picked up yet is cancelled by deleting
         * it, which this page can do itself -- the file is in this account's
         * home and owned by this account. That is instant, and it is the
         * common case: most cancels happen in the first seconds.
         *
         * A scan already RUNNING belongs to a root process this page cannot
         * touch. All it can do is leave the ask, which the privileged side
         * picks up within the minute and checks against the job row before
         * acting -- a customer may stop the scan they started and nothing
         * else.
         *
         * Both, every time, in that order: between the click and this code
         * the request may have become a running scan, and doing only one of
         * the two would leave it running.
         */
        $cancelling = sg_leave($home, 'scan-cancel.json', [
            'requested_at' => time(),
            'source'       => 'cpanel-plugin',
        ]);
        $rq = rtrim($home, '/') . '/.serverscrub/scan-request.json';
        if (!is_link($rq) && is_file($rq)) { @unlink($rq); }
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
    /* Sampled from the product logo (frontend/images/logo.png), not chosen:
     * navy #001a3d is the shield body, #0090f0 its highlight, and #00b03c the
     * green of the word "Scrub". An earlier version used #1976b6 and #1d7a46,
     * which appear nowhere in the artwork. */
    --dim:#687079; --line:#dfe3e8; --chip:#f6f7f9;
    --navy:#001a3d;
    --blue:#0090f0; --red:#d93a2b; --amber:#b9770e; --green:#00b03c;
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
  /* Cancel is not the action we want someone to take by accident, so it does
   * not get the filled primary treatment the Scan button has. */
  .sscrub .btn-stop { background:#fff; color:var(--red); border-color:var(--red); }
  @media (max-width:560px) { .sscrub .hide-sm{display:none} }

  /* ── Branded header and tabs ──────────────────────────────────────────
   * The nav is server-side: each tab is a real link to ?tab=<name>, so it
   * survives a reload, a bookmark and the back button, and works with
   * scripting off. There is nothing here for JavaScript to do. */
  .sscrub .ss-head {
    display:flex; align-items:center; gap:22px; flex-wrap:wrap;
    padding:0 0 14px; border-bottom:2px solid var(--line); margin-bottom:18px;
  }
  .sscrub .ss-brand { display:flex; align-items:center; gap:9px;
                      font-size:1.22rem; letter-spacing:-.02em; color:var(--navy); }
  .sscrub .ss-brand img { width:30px; height:30px; flex:none; display:block; }
  .sscrub .ss-brand strong { font-weight:700; color:var(--green); }

  .sscrub .ss-tabs { display:flex; align-items:center; gap:4px;
                     margin-left:auto; flex-wrap:wrap; }
  .sscrub .ss-tabs > a, .sscrub .ss-drop > a {
    display:inline-block; padding:8px 14px; border-radius:4px;
    font-size:.84rem; font-weight:600; letter-spacing:.02em;
    text-transform:uppercase; color:var(--dim); text-decoration:none;
    border:1px solid transparent; white-space:nowrap;
  }
  .sscrub .ss-tabs > a:hover, .sscrub .ss-drop > a:hover { color:var(--blue); }
  .sscrub .ss-tabs > a.on, .sscrub .ss-drop.on > a {
    color:var(--navy); border-color:var(--navy);
  }

  /* Hover/focus dropdown, no script. focus-within keeps it reachable by
   * keyboard; on a touch device the parent link itself still goes to the
   * scanner page, so the menu is a shortcut and never the only way in. */
  .sscrub .ss-drop { position:relative; display:inline-block; }
  .sscrub .ss-drop i { font-style:normal; font-size:.8em; opacity:.7; }
  .sscrub .ss-menu {
    display:none; position:absolute; top:100%; left:0; z-index:30;
    min-width:190px; background:#fff; border:1px solid var(--line);
    border-radius:4px; box-shadow:0 6px 20px rgba(15,23,32,.14); padding:5px 0;
  }
  .sscrub .ss-drop:hover .ss-menu, .sscrub .ss-drop:focus-within .ss-menu { display:block; }
  .sscrub .ss-menu a {
    display:block; padding:9px 16px; font-size:.82rem; font-weight:600;
    text-transform:uppercase; letter-spacing:.02em; color:var(--dim);
    text-decoration:none; white-space:nowrap;
  }
  .sscrub .ss-menu a:hover { background:var(--chip); color:var(--blue); }

  .sscrub .ss-title { display:flex; align-items:baseline; gap:12px; margin-bottom:18px; }
  .sscrub .ss-title h1 { margin:0; }
  .sscrub .ss-title .sub { margin:0; }

  .sscrub .tile .t { color:var(--dim); font-size:.68rem; margin-top:2px; }

  @media (max-width:760px) {
    .sscrub .ss-head { gap:10px; }
    .sscrub .ss-tabs { margin-left:0; width:100%; }
    .sscrub .ss-tabs > a, .sscrub .ss-drop > a { padding:7px 10px; font-size:.78rem; }
  }
</style>

<div class="sscrub">
<?php
  // ── Which panel ─────────────────────────────────────────────────────────
  //
  // Server-side, not JavaScript. The page already runs PHP, the panels are
  // already rendered by it, and a ?tab= link survives a reload, a bookmark,
  // the back button and a browser with scripting disabled. Client-side tabs
  // would buy nothing and could only fail.
  //
  // Whitelisted, because this value picks a template branch and is echoed
  // into the nav as the current item.
  $TABS = [
      'home'    => 'Home',
      'scanner' => 'Virus scanner',
      'logs'    => 'Scanner logs',
      'cms'     => 'CMS threats',
      'waf'     => 'WAF',
      'attacks' => 'Attacks',
      'files'   => 'File changes',
  ];
  $tab = (string) ($_GET['tab'] ?? 'home');
  if (!isset($TABS[$tab])) { $tab = 'home'; }

  // Keep cPanel's session path. The links are relative so the /cpsessNNN/
  // prefix is preserved automatically; only the query is replaced.
  $self = basename((string) ($_SERVER['SCRIPT_NAME'] ?? 'index.live.php'));
  $link = static function (string $t) use ($self): string {
      return $self . '?tab=' . rawurlencode($t);
  };

  $s        = $report['summary'] ?? [];
  $st30     = $report['stats30'] ?? [];
  $threats  = $report['threats'] ?? [];
  $cmsList  = $report['cms'] ?? [];
  $changes  = $report['file_changes'] ?? [];
  $wafRows  = $report['waf'] ?? [];
  $atkRows  = $report['attacks'] ?? [];
  $scanRows = $report['scans'] ?? [];
?>

<div class="ss-head">
  <div class="ss-brand">
    <!-- The real mark, which the installer already places beside this page.
         It was a hand-drawn SVG shield that resembled the product's logo
         without being it. -->
    <img src="serverscrub.png" alt="" width="48" height="48">
    <span>Server<strong>Scrub</strong></span>
  </div>

  <nav class="ss-tabs">
    <a class="<?= $tab === 'home' ? 'on' : '' ?>" href="<?= e($link('home')) ?>">Home</a>

    <span class="ss-drop<?= in_array($tab, ['scanner', 'logs'], true) ? ' on' : '' ?>">
      <a href="<?= e($link('scanner')) ?>">Virus scanner <i>&#9662;</i></a>
      <span class="ss-menu">
        <a href="<?= e($link('scanner')) ?>">Manual scan</a>
        <a href="<?= e($link('logs')) ?>">Scanner logs</a>
      </span>
    </span>

    <a class="<?= $tab === 'cms' ? 'on' : '' ?>" href="<?= e($link('cms')) ?>">CMS threats</a>
    <a class="<?= $tab === 'waf' ? 'on' : '' ?>" href="<?= e($link('waf')) ?>">WAF</a>
    <a class="<?= $tab === 'attacks' ? 'on' : '' ?>" href="<?= e($link('attacks')) ?>">Attacks</a>
    <a class="<?= $tab === 'files' ? 'on' : '' ?>" href="<?= e($link('files')) ?>">File changes</a>
  </nav>
</div>

<div class="ss-title">
  <h1><?= e($TABS[$tab]) ?></h1>
  <span class="sub"><?= e($user !== '' ? $user : 'your account') ?></span>
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

<?php
  // The scan-request state is needed on more than one panel.
  $sr       = $report['scan_request'] ?? [];
  $srOn     = !empty($sr['enabled']);
  $srWait   = (int)($sr['retry_in'] ?? 0);
  $srQueued = $requested || !empty($sr['pending']);
  $srPer    = max(1, (int)($sr['per_window'] ?? 2));
  $srHours  = max(1, (int)($sr['window_hours'] ?? 12));
  $srUsed   = min($srPer, (int)($sr['used'] ?? 0));
  $srLeft   = max(0, $srPer - $srUsed);
  function hms(int $s): string {
      if ($s <= 0)    { return 'now'; }
      if ($s < 3600)  { return 'in ' . max(1, intdiv($s, 60)) . ' minute(s)'; }
      return 'in ' . intdiv($s, 3600) . ' hour(s)';
  }

  // When this account asked, read from its OWN request file.
  //
  // The report is rewritten by the privileged side every quarter of an hour,
  // so anything carried in it is up to that stale -- including whether a
  // request exists at all. Somebody who clicks the button and reloads would
  // otherwise be told nothing has been requested. The file is in this
  // customer's home and this page runs as them, so the one fact that has to
  // be fresh can be read directly.
  $reqAt = 0;
  if ($home !== '') {
      $rp = rtrim($home, '/') . '/.serverscrub/scan-request.json';
      if (is_file($rp)) {
          $rj = json_decode((string) @file_get_contents($rp), true);
          $reqAt = is_array($rj) ? (int) ($rj['requested_at'] ?? 0) : 0;
      }
  }

  $note      = is_array($sr['note'] ?? null) ? $sr['note'] : [];
  $noteState = (string) ($note['state'] ?? '');
  if ($reqAt > 0 && (int) ($note['at'] ?? 0) < $reqAt) { $noteState = ''; }

  $lastCheck = (int) ($sr['last_check_at'] ?? 0);

  // ── The live scan, read fresh ─────────────────────────────────────────────
  //
  // Reported as: press the button, the card says "Queued", and it goes on
  // saying that while the scan runs and finishes. It was true of every number
  // on this page -- report.json is rebuilt hourly, so the card was showing an
  // answer from before the click.
  //
  // scan-status.json is different: the privileged side rewrites it as the scan
  // progresses, into this account's own home. It is the only thing here that
  // is current, and it is what the poller below re-reads.
  $live = [];
  if ($home !== '') {
      $lp = rtrim($home, '/') . '/.serverscrub/scan-status.json';
      if (!is_link($lp) && is_file($lp)) {
          $lj = json_decode((string) @file_get_contents($lp), true);
          if (is_array($lj)) { $live = $lj; }
      }
  }

  $liveStatus = (string) ($live['status'] ?? '');
  $liveAt     = (int) ($live['updated_at'] ?? 0);
  $liveStart  = (int) ($live['started_at'] ?? 0);

  // A status file describing a scan that ended before this request was made is
  // the PREVIOUS scan, and showing its result next to a fresh "Queued" would
  // read as though the new one had already finished.
  if ($reqAt > 0 && $liveStart > 0 && $liveStart < $reqAt) { $liveStatus = ''; }

  $isRunning  = in_array($liveStatus, ['running', 'pending'], true);
  $isStopping = $liveStatus === 'cancelling' || ($cancelling && $isRunning);

  // A worker killed outright never writes a final state. The reaper marks the
  // job interrupted and the minute cron carries that over, so anything older
  // than a few minutes means neither is running -- and claiming a scan is in
  // progress when nothing is working on it is the failure this card exists to
  // prevent.
  if ($isRunning && $liveAt > 0 && (time() - $liveAt) > 600) {
      $isRunning  = false;
      $liveStatus = 'stalled';
  }

  // Finished recently enough that the customer is still looking at the page
  // they started it from.
  $justDone = !$isRunning && !$isStopping
           && in_array($liveStatus, ['done', 'cancelled', 'error', 'interrupted', 'skipped'], true)
           && (int) ($live['finished_at'] ?? 0) > time() - 1800;

  $srQueued = $srQueued && !$isRunning && !$isStopping && !$justDone;

  // Anything moving is worth re-reading. Nothing moving is not.
  //
  // A stalled scan is explicitly NOT moving. Its request file may still be on
  // disk, which would otherwise read as "queued" and have the page re-read a
  // dead job every five seconds for as long as the customer leaves the tab
  // open.
  $polling = ($isRunning || $isStopping || $srQueued) && $liveStatus !== 'stalled';

  $elapsed = function (int $from): string {
      $d = max(0, time() - $from);
      if ($d < 60) { return $d . 's'; }
      return intdiv($d, 60) . 'm ' . ($d % 60) . 's';
  };
?>

<?php
// ── The scan panel, shown on Home and on Virus scanner ──────────────────────
$renderScanCard = function () use ($srOn, $srQueued, $srWait, $sr, $reqAt,
                                   $noteState, $note, $lastCheck,
                                   $srPer, $srHours, $srUsed, $srLeft,
                                   $live, $liveStatus, $isRunning, $isStopping,
                                   $justDone, $polling, $elapsed, $cancelling) {
    if (!$srOn) { return; }
?>
  <div class="card" id="ss-scan" data-poll="<?= $polling ? '1' : '0' ?>">
    <h2>Scan my account</h2>
    <div style="padding:14px">
      <?php if ($isStopping): ?>
        <div class="tag amber">Stopping</div>
        <button class="btn" disabled style="margin-left:10px">Cancelling…</button>
        <div class="foot" style="margin-top:7px">
          Your scan is being stopped. This takes up to a minute — the files
          already checked are kept, and anything found in them is listed below.
        </div>

      <?php elseif ($isRunning): ?>
        <div class="tag green">Scanning now</div>
        <form method="post" style="display:inline;margin:0 0 0 10px">
          <button class="btn btn-stop" type="submit" name="cancel_scan" value="1">Cancel scan</button>
        </form>
        <div class="foot" style="margin-top:9px">
          <strong><?= number_format((int) ($live['files_scanned'] ?? 0)) ?></strong>
          file(s) checked
          <?php if ((int) ($live['threats_found'] ?? 0) > 0): ?>
            · <strong class="red"><?= (int) $live['threats_found'] ?></strong> threat(s) so far
          <?php else: ?>
            · nothing found so far
          <?php endif; ?>
          <?php if ((int) ($live['started_at'] ?? 0) > 0): ?>
            · running for <?= e($elapsed((int) $live['started_at'])) ?>
          <?php endif; ?>
          <br>This updates on its own. You can close the page; it keeps going.
        </div>

      <?php elseif ($justDone): ?>
        <?php
          $fin  = (int) ($live['finished_at'] ?? 0);
          $hits = (int) ($live['threats_found'] ?? 0);
        ?>
        <?php if ($liveStatus === 'done'): ?>
          <div class="tag <?= $hits > 0 ? 'red' : 'green' ?>">
            <?= $hits > 0 ? 'Threats found' : 'Clean' ?></div>
          <div class="foot" style="margin-top:7px">
            Scan finished <?= e(ago($fin)) ?> after checking
            <strong><?= number_format((int) ($live['files_scanned'] ?? 0)) ?></strong> file(s).
            <?php if ($hits > 0): ?>
              <strong class="red"><?= $hits ?></strong> threat(s) found — they are listed below.
            <?php else: ?>
              Nothing harmful was found in your account.
            <?php endif; ?>
          </div>
        <?php elseif ($liveStatus === 'cancelled'): ?>
          <div class="tag dimc">Cancelled</div>
          <div class="foot" style="margin-top:7px">
            You stopped this scan <?= e(ago($fin)) ?>, after
            <strong><?= number_format((int) ($live['files_scanned'] ?? 0)) ?></strong>
            file(s). Anything found in those is listed below; the rest of your
            account was not checked.
          </div>
        <?php elseif ($liveStatus === 'skipped'): ?>
          <div class="tag amber">Not started</div>
          <div class="foot" style="margin-top:7px">
            The server was already running another scan, so yours did not
            start. You can ask again below.
          </div>
        <?php else: ?>
          <div class="tag amber">Did not finish</div>
          <div class="foot" style="margin-top:7px">
            This scan stopped before it was done (<?= e($liveStatus) ?>)
            <?= e(ago($fin)) ?>. Anything it had found is listed below. If this
            keeps happening it is worth telling your hosting provider.
          </div>
        <?php endif; ?>
        <?php if ($srWait <= 0): ?>
          <form method="post" style="margin:11px 0 0">
            <button class="btn" type="submit" name="scan_now" value="1">Scan again</button>
          </form>
        <?php endif; ?>

      <?php elseif ($liveStatus === 'stalled'): ?>
        <div class="tag amber">Stopped responding</div>
        <form method="post" style="display:inline;margin:0 0 0 10px">
          <button class="btn" type="submit" name="scan_now" value="1">Try again</button>
        </form>
        <div class="foot" style="margin-top:9px">
          Your scan has not reported progress for over ten minutes, so it is no
          longer running. Please tell your hosting provider if this keeps
          happening.
        </div>

      <?php elseif ($srQueued): ?>
        <div class="tag green">Queued</div>
        <form method="post" style="display:inline;margin:0 0 0 10px">
          <button class="btn btn-stop" type="submit" name="cancel_scan" value="1">Cancel scan</button>
        </form>
        <div class="foot" style="margin-top:9px">
          <?php if ($reqAt > 0): ?>
            <strong>Requested <?= e(ago($reqAt)) ?>.</strong>
          <?php else: ?>
            <strong>Your request has been received.</strong>
          <?php endif; ?>

          <?php if ($noteState === 'blocked' && !empty($note['detail'])): ?>
            The server could not start it yet: <?= e(rtrim($note['detail'], '.')) ?>.
            It will start automatically once that clears — you do not need to ask again.
          <?php elseif ($noteState === 'at_limit'): ?>
            This account has already used its <?= (int) $srPer ?> scans for the
            last <?= (int) $srHours ?> hours, so this request is held until the next
            one is allowed.
          <?php else: ?>
            It usually starts within a minute.
          <?php endif; ?>

          <?php
            // If the pickup is not running, "within a minute" is a lie and the
            // customer waits with no clue why. It runs every minute, so
            // anything past five is a signal rather than noise -- and the
            // customer can act on it, by telling their host.
            $checkAge = $lastCheck > 0 ? (time() - $lastCheck) : -1;
          ?>
          <?php if ($lastCheck <= 0 || $checkAge > 300): ?>
            <br><strong>Note:</strong> the server has not checked for scan requests
            <?= $lastCheck > 0 ? 'since ' . e(ago($lastCheck)) : 'at all yet' ?>.
            Your request is saved, but it may not start until your hosting provider
            looks at this — it is worth telling them.
          <?php endif; ?>

          Your scan runs in the background. You can close this page; the results
          appear here when it has finished.
        </div>
      <?php elseif ($srWait > 0): ?>
        <button class="btn" disabled>Scan my account</button>
        <div class="foot" style="margin-top:7px">
          You have used both of your <?= (int) $srPer ?> scans for the last
          <?= (int) $srHours ?> hours. The next one is available
          <?= e(hms($srWait)) ?>.
          Last scan of your account: <?= e(ago((int)($sr['last_run_at'] ?? 0))) ?>.
        </div>
      <?php else: ?>
        <form method="post" style="margin:0">
          <button class="btn" type="submit" name="scan_now" value="1">Scan my account</button>
        </form>
        <div class="foot" style="margin-top:7px">
          Checks the files in your home directory for malware. It starts within a
          minute and runs in the background; you do not need to keep this page open.
          <?php if ($srUsed > 0): ?>
            You have <?= (int) $srLeft ?> of <?= (int) $srPer ?> scans left for the
            next <?= (int) $srHours ?> hours.
          <?php else: ?>
            You can run <?= (int) $srPer ?> scans every <?= (int) $srHours ?> hours.
          <?php endif; ?>
        </div>
      <?php endif; ?>
    </div>
  </div>
<?php
};

/**
 * The card on its own, for the poller.
 *
 * A full page reload every few seconds would work, and it is what this did
 * first -- but inside cPanel's frame it reloads cPanel's chrome too, throws
 * away the scroll position, and flickers. Returning the one card that changes
 * costs a few hundred bytes and leaves the rest of the page alone.
 *
 * Everything above has already run, so the answer is as fresh as a full load.
 * The buffered chrome is discarded rather than sent: this is a fragment, not
 * a page, and the LiveAPI header must not be wrapped around it.
 */
if (($_GET['card'] ?? '') === 'scan') {
    while (ob_get_level() > 0) { ob_end_clean(); }
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    $renderScanCard();
    exit;
}

// ── The threats table, shown on Home and on Virus scanner ───────────────────
$renderThreats = function (array $rows) {
?>
  <div class="card">
    <h2>Detected threats</h2>
    <?php if (!$rows): ?>
      <div class="ok">No threats have been found in your account.</div>
    <?php else: ?>
      <table>
        <thead><tr>
          <th>File</th><th>Detected as</th><th>Severity</th>
          <th class="hide-sm">Status</th><th class="hide-sm">Found</th>
        </tr></thead>
        <tbody>
        <?php foreach ($rows as $t):
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
<?php
};
?>

<?php /* ── HOME ─────────────────────────────────────────────────────────── */ ?>
<?php if ($tab === 'home'): ?>

  <div class="tiles">
    <div class="tile">
      <div class="n <?= ((int)($st30['threats'] ?? 0)) ? 'red' : 'green' ?>">
        <?= (int)($st30['threats'] ?? 0) ?>
      </div>
      <div class="l">Threats found</div>
      <div class="t">last 30 days</div>
    </div>
    <div class="tile">
      <div class="n <?= ((int)($st30['attacks'] ?? 0)) ? 'amber' : 'green' ?>">
        <?= (int)($st30['attacks'] ?? 0) ?>
      </div>
      <div class="l">Attacks blocked</div>
      <div class="t">last 30 days</div>
    </div>
    <div class="tile">
      <div class="n <?= ((int)($st30['cms_issues'] ?? 0)) ? 'amber' : 'green' ?>">
        <?= (int)($st30['cms_issues'] ?? 0) ?>
      </div>
      <div class="l">CMS issues</div>
      <div class="t">needing an update</div>
    </div>
    <div class="tile">
      <div class="n <?= ((int)($s['threats_active'] ?? 0)) ? 'red' : 'green' ?>">
        <?= (int)($s['threats_active'] ?? 0) ?>
      </div>
      <div class="l">Active now</div>
      <div class="t">not yet cleaned</div>
    </div>
  </div>

  <?php $renderScanCard(); ?>
  <?php $renderThreats(array_slice($threats, 0, 10)); ?>

  <?php if (count($threats) > 10): ?>
    <div class="foot" style="margin-bottom:16px">
      Showing the 10 most recent of <?= count($threats) ?>.
      <a href="<?= e($link('scanner')) ?>">See them all in Virus scanner</a>.
    </div>
  <?php endif; ?>

<?php /* ── VIRUS SCANNER ────────────────────────────────────────────────── */ ?>
<?php elseif ($tab === 'scanner'): ?>

  <?php $renderScanCard(); ?>
  <?php $renderThreats($threats); ?>

<?php /* ── SCANNER LOGS ─────────────────────────────────────────────────── */ ?>
<?php elseif ($tab === 'logs'): ?>

  <div class="card">
    <h2>Scanner logs</h2>
    <?php if (!$scanRows): ?>
      <div class="ok">
        No scan has covered your account yet. Scans are scheduled by your hosting
        provider, and you can request one from the Virus scanner page.
      </div>
    <?php else: ?>
      <table>
        <thead><tr>
          <th>Started</th><th>Type</th><th>Status</th>
          <th class="hide-sm">Files</th><th>Threats</th><th class="hide-sm">Took</th>
        </tr></thead>
        <tbody>
        <?php foreach ($scanRows as $j):
          $started  = (int)($j['started_at'] ?? 0);
          $finished = (int)($j['finished_at'] ?? 0);
          $found    = (int)($j['threats_found'] ?? 0);
          $status   = (string)($j['status'] ?? '');
          $scls     = $status === 'completed' ? 'green'
                    : ($status === 'running' || $status === 'pending' ? 'amber' : 'dimc');
          $dur      = ($started > 0 && $finished > $started)
                    ? ($finished - $started < 60
                        ? ($finished - $started) . 's'
                        : intdiv($finished - $started, 60) . 'm')
                    : '—';
        ?>
          <tr>
            <td class="dimc"><?= e(ago($started)) ?></td>
            <td><?= e($j['scan_type'] ?? '') ?></td>
            <td><span class="tag <?= $scls ?>"><?= e($status) ?></span></td>
            <td class="hide-sm"><?= number_format((int)($j['files_scanned'] ?? 0)) ?></td>
            <td class="<?= $found ? 'red' : 'green' ?>"><?= $found ?></td>
            <td class="hide-sm dimc"><?= e($dur) ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>
  </div>

<?php /* ── CMS THREATS ──────────────────────────────────────────────────── */ ?>
<?php elseif ($tab === 'cms'): ?>

  <div class="card">
    <h2>Applications</h2>
    <?php if (!$cmsList): ?>
      <div class="ok">No WordPress, Joomla or Drupal installations were found in your account.</div>
    <?php else: ?>
      <table>
        <thead><tr>
          <th>Application</th><th>Version</th><th>Location</th><th class="hide-sm">Notes</th>
        </tr></thead>
        <tbody>
        <?php foreach ($cmsList as $c):
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

<?php /* ── WAF ──────────────────────────────────────────────────────────── */ ?>
<?php elseif ($tab === 'waf'): ?>

  <div class="card">
    <h2>Web application firewall</h2>
    <?php if (!$wafRows): ?>
      <div class="ok">
        No web application firewall events for your domains.
        <div class="foot" style="margin-top:8px">
          Requests that match a firewall rule are blocked before they reach your
          site, and are listed here when they do.
        </div>
      </div>
    <?php else: ?>
      <table>
        <thead><tr>
          <th>When</th><th>Domain</th><th>Rule</th>
          <th class="hide-sm">From</th><th class="hide-sm">Path</th><th>Action</th>
        </tr></thead>
        <tbody>
        <?php foreach ($wafRows as $w):
          $sev  = strtolower((string)($w['severity'] ?? ''));
          $acls = ((string)($w['action'] ?? '')) === 'block' ? 'red' : 'amber';
        ?>
          <tr>
            <td class="dimc"><?= e(ago((int)($w['timestamp'] ?? 0))) ?></td>
            <td class="mono"><?= e($w['host'] ?? '') ?></td>
            <td><?= e($w['rule_msg'] ?? $w['rule_id'] ?? 'rule') ?></td>
            <td class="hide-sm mono"><?= e($w['ip_address'] ?? '') ?></td>
            <td class="hide-sm mono"><?= e(mb_substr((string)($w['uri'] ?? ''), 0, 60)) ?></td>
            <td><span class="tag <?= $acls ?>"><?= e($w['action'] ?? '') ?></span></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>
  </div>

<?php /* ── ATTACKS ──────────────────────────────────────────────────────── */ ?>
<?php elseif ($tab === 'attacks'): ?>

  <div class="card">
    <h2>Attacks on your domains</h2>
    <?php if (!$atkRows): ?>
      <div class="ok">
        No attacks have been recorded against your domains.
        <div class="foot" style="margin-top:8px">
          Only events that name one of your own domains appear here. Attacks on
          the server as a whole are handled by your hosting provider and are not
          shown.
        </div>
      </div>
    <?php else: ?>
      <table>
        <thead><tr>
          <th>When</th><th>Type</th><th>Severity</th>
          <th class="hide-sm">From</th><th>Target</th>
        </tr></thead>
        <tbody>
        <?php foreach ($atkRows as $a):
          $sev = strtolower((string)($a['severity'] ?? ''));
          $cls = $sev === 'critical' || $sev === 'high' ? 'red' : ($sev === 'medium' ? 'amber' : 'dimc');
        ?>
          <tr>
            <td class="dimc"><?= e(ago((int)($a['timestamp'] ?? 0))) ?></td>
            <td><?= e(str_replace('_', ' ', (string)($a['type'] ?? ''))) ?></td>
            <td><span class="tag <?= $cls ?>"><?= e($a['severity'] ?? '?') ?></span></td>
            <td class="hide-sm mono"><?= e($a['source_ip'] ?? '') ?></td>
            <td class="mono"><?= e($a['target'] ?? '') ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>
  </div>

<?php /* ── FILE CHANGES ─────────────────────────────────────────────────── */ ?>
<?php elseif ($tab === 'files'): ?>

  <div class="card">
    <h2>Changed files</h2>
    <?php if (!$changes): ?>
      <div class="ok">No unexpected file changes have been noticed in your account.</div>
    <?php else: ?>
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
    <?php endif; ?>
  </div>

<?php endif; ?>

  <div class="foot">
    Report generated <?= e(ago((int)($report['generated_at'] ?? 0))) ?>
    from the server scan that ran <?= e(ago((int)($report['last_scan_at'] ?? 0))) ?>.
    Scans are scheduled by your hosting provider. Contact them to act on anything
    listed here.
  </div>

<?php endif; ?>

<script>
/* Keep the scan card current.
 *
 * The card renders its own answer: data-poll="1" means something is moving and
 * is worth re-reading. The replacement carries the same attribute, so the loop
 * stops by itself the moment the scan finishes -- there is no state here
 * deciding when to give up, and nothing to get out of step with the markup.
 *
 * Everything degrades: with scripting off the card is still correct on load,
 * the buttons are real form submits, and the only thing lost is that it
 * stops moving on its own.
 */
(function () {
  var EVERY = 5000, MAX = 60 * 60 * 1000, began = Date.now(), armed = false;

  /* One timer, ever. Coming back to the tab asks for an immediate read, and
   * without this that would start a second chain alongside the first -- then
   * a third, until the card is being re-read several times a second. */
  function arm(ms) {
    if (armed) { return; }
    armed = true;
    setTimeout(function () { armed = false; tick(); }, ms);
  }

  function url() {
    var u = new URL(window.location.href);
    u.searchParams.set('card', 'scan');
    /* Cancels and scan requests are POSTs. Re-reading must not repeat one. */
    return u.toString();
  }

  function tick() {
    var card = document.getElementById('ss-scan');
    if (!card || card.getAttribute('data-poll') !== '1') { return; }
    if (Date.now() - began > MAX) { return; }

    /* Nothing is read while the tab is in the background. The scan carries on
     * server-side either way, and the card is refreshed on the way back. */
    if (document.hidden) { arm(EVERY); return; }

    fetch(url(), { credentials: 'same-origin', headers: { 'X-Requested-With': 'fetch' } })
      .then(function (r) { return r.ok ? r.text() : null; })
      .then(function (html) {
        if (!html) { return; }
        var box = document.createElement('div');
        box.innerHTML = html;
        var fresh = box.querySelector('#ss-scan');
        var now   = document.getElementById('ss-scan');
        /* A response without the card means something is wrong at the other
         * end -- a session that has expired, most likely. Leaving what is on
         * screen is better than blanking it. */
        if (fresh && now) { now.replaceWith(fresh); }
      })
      .catch(function () { /* A dropped request is not worth a message. */ })
      .then(function () { arm(EVERY); });
  }

  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) { arm(150); }
  });
  arm(EVERY);
})();
</script>
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
