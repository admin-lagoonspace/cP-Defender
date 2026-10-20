<?php
/**
 * The third-party security stack: ClamAV, rkhunter, ModSecurity, CSF.
 *
 * Most of this file is about where these come from, because that is where the
 * danger is rather than in the detection.
 *
 * The request that produced this module was "just wget them so we always have
 * the latest patches". That is wrong three times over, and each of the three is
 * asserted here so it cannot be reintroduced:
 *
 *   1. A tarball fetched at install time is pinned forever — the server's own
 *      `dnf update` does not know it exists. The package manager IS the patch
 *      channel.
 *   2. ModSecurity has to be the build matching Apache's ABI. On EasyApache 4
 *      that means cPanel's own package; anything else and httpd does not
 *      start, which on a shared host is every site down at once.
 *   3. CSF's vendor closed on 2025-08-31 and download.configserver.com no
 *      longer resolves. CSF's updater runs AS ROOT. A hardcoded fetch from an
 *      expired domain hands every installed server to whoever re-registers it.
 */

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/assert.php';

$repo    = dirname(__DIR__);
$install = t_shell($repo . '/install.sh');

// ── Nothing is ever downloaded ──────────────────────────────────────────────
//
// The single most important property in this file.

t_ok(!preg_match('/(?:curl|wget)[^\n|]*configserver\.com/i', $install),
     'the installer NEVER downloads CSF from its retired vendor');
t_ok(!preg_match('/(?:curl|wget)[^\n|]*csf\.tgz/i', $install),
     'and never fetches csf.tgz from anywhere');

// ClamAV, ModSecurity and rkhunter are packages, not downloads.
foreach (['clamav' => 'ClamAV',
          'mod_security' => 'ModSecurity',
          'rkhunter' => 'rkhunter'] as $needle => $label) {
    t_ok(!preg_match('/(?:curl|wget)\s[^\n|]*' . preg_quote($needle, '/') . '[^\n]*\.(?:tar\.gz|tgz|zip|rpm|deb)/i',
                     $install),
         "$label is not downloaded as an archive — it comes from the package manager");
}

// ── CSF: the right package, on the right platform only ──────────────────────

t_contains($install, 'cpanel-csf',
     "CSF is installed from cPanel's maintained fork package");
// The source of that package is recorded in code, not only in a comment, so
// anyone auditing where root-privileged firewall software came from can find it
// without reading the installer.
t_eq('https://github.com/cpanel/cpanel-csf', Dependencies::CSF_FORK_REPO,
     'and the fork it is sourced from is recorded as a constant');


// cPanel's own README: the RPM "is intended for cPanel & WHM systems only and
// will fail installation when cPanel is not detected". So off cPanel the
// installer must not try, and must say the fallback is supported rather than
// leaving the operator thinking something is broken.
t_contains($install, '/usr/local/cpanel',
     'the CSF step checks whether this is a cPanel server at all');
t_contains($install, 'nftables/iptables directly',
     'and says the built-in firewall engine is used instead off cPanel');

// The dead-vendor warning for an EXISTING install. This is a real finding: the
// updater runs as root against a domain anyone can now buy.
t_contains($install, 'AUTO_UPDATES',
     'an existing CSF is checked for an armed updater');
t_contains($install, 'runs as root',
     'and the warning says why that matters');

// ── Locking the operator out of SSH is the unrecoverable failure ────────────
//
// Installing a firewall on a live server and losing SSH cannot be undone
// remotely. The port is read from sshd_config rather than assumed to be 22,
// and it is added before anything can start filtering.

t_contains($install, '/etc/ssh/sshd_config',
     "the SSH port is read from sshd's own config, not assumed to be 22");
t_contains($install, 'TCP_IN',
     'and it is added to CSF\'s inbound list');
t_contains($install, 'TESTING = "1"',
     'a newly installed CSF is left in TESTING mode, so a mistake cannot '
   . 'lock anyone out permanently');

$csfSection = substr($install, strpos($install, 'section "CSF firewall"'));
t_contains($csfSection, 'csf.conf.pre-serverscrub',
     'and the existing csf.conf is backed up before being edited');

// ── ModSecurity: installed, but not switched to blocking ────────────────────

t_contains($install, 'ea-apache24-mod_security2',
     'on EasyApache 4 the cPanel-built module is used');
t_contains($install, 'libapache2-mod-security2',
     'and the Debian package on Debian');
t_contains($install, 'detection-only',
     'the WAF is installed but left in detection-only — a rule that matches '
   . 'ordinary traffic blocks paying customers');

// ── Declining is supported ──────────────────────────────────────────────────
//
// Some operators will not have EPEL on a cPanel box at any price, and some
// will not want a second firewall package. Every one of these is refusable.

foreach (['--no-deps', '--no-rootkit-tools', '--no-waf-pkg', '--no-csf'] as $flag) {
    t_contains($install, $flag, "$flag can be used to decline");
}

// ── Dependencies: reporting ─────────────────────────────────────────────────

$st = Dependencies::status();
foreach (['clamav', 'rkhunter', 'chkrootkit', 'modsecurity', 'csf'] as $k) {
    t_ok(isset($st[$k]), "status() reports $k");
    t_ok(array_key_exists('installed', $st[$k]), "  with a presence flag");
    // Every entry says what is lost without it. "Not installed" on its own
    // tells an operator nothing about whether they should care.
    t_ok(strlen($st[$k]['without_it']) > 30,
         "  and says what is degraded without $k");
    t_ok(strlen($st[$k]['source']) > 20, "  and where it comes from");
}

t_contains($st['clamav']['without_it'], 'heuristic',
     'ClamAV missing is honestly described: the built-in engine still runs');
t_contains($st['modsecurity']['without_it'], 'stops the request',
     'ModSecurity missing is NOT described as covered — nothing else in the '
   . 'product filters requests');

// CSF is an integration, not a prerequisite, and the text must say so rather
// than implying the server is unprotected.
t_contains($st['csf']['without_it'], 'not a prerequisite',
     'CSF is described as an integration rather than a requirement');

// It is only recommended where cPanel's package can actually install.
if (Dependencies::isCpanel()) {
    t_eq(true, $st['csf']['installable'], 'on cPanel, CSF is installable');
    t_contains($st['csf']['source'], 'github.com/cpanel/cpanel-csf',
         'and the operator is told which fork it comes from');
} else {
    t_eq(false, $st['csf']['installable'],
         'off cPanel, CSF is reported as not installable rather than missing');
    t_ok(!in_array('CSF', array_column(Dependencies::missing(), 'name'), true),
         'and it is not listed as something to go and install');
    t_contains($st['csf']['source'], 'refuses to install',
         'with cPanel\'s own restriction given as the reason');
}

// ── The CSF upstream risk check ─────────────────────────────────────────────
//
// Entirely local: no request is made to the retired hosts. Asserted, because
// "check whether the dead domain responds" is the obvious wrong implementation.

$dep = t_code($repo . '/backend/lib/Dependencies.php');
t_ok(!preg_match('/(?:curl|file_get_contents|fsockopen|wp_remote)[^\n]*configserver/i', $dep),
     'the risk check never contacts the retired vendor');

t_eq(null, Dependencies::csfUpstreamRisk(false, false),
     'no CSF installed means nothing to warn about');

$ok = Dependencies::csfUpstreamRisk(true, true);
t_eq(false, $ok['risk'], "cPanel's fork is not a risk");
t_eq('ok', $ok['severity'], 'and is reported as fine');
t_contains($ok['what'], 'cpanel-csf', 'naming the package');

$bad = Dependencies::csfUpstreamRisk(true, false);
t_eq(true, $bad['risk'], 'a non-fork CSF is flagged');
t_ok(in_array($bad['severity'], ['high', 'medium'], true),
     'at high or medium depending on whether its updater is armed');
t_contains($bad['action'], 'cpanel-csf',
     'and the fix names the package to migrate to');
t_contains($bad['what'], '2025-08-31',
     'and the finding states when the vendor closed, so it can be verified');

// ── ModSecurity package selection ───────────────────────────────────────────

$pkg = Dependencies::modsecPackage();
t_ok(in_array($pkg, ['ea-apache24-mod_security2', 'libapache2-mod-security2',
                     'mod_security'], true),
     'modsecPackage() returns a real package name for this platform');

if (Dependencies::isCpanel() && is_dir('/etc/apache2/conf.d')) {
    t_eq('ea-apache24-mod_security2', $pkg,
         'on EasyApache 4 it must be cPanel\'s build — a generic module does '
       . 'not match the Apache they compiled, and httpd would not start');
}

// ── The CLI surfaces all of it ──────────────────────────────────────────────
//
// So the "complete package" claim can be checked on a real server instead of
// taken on trust.

$cli = t_code($repo . '/backend/cli/serverscrub.php');
t_contains($cli, "case 'deps'", 'there is a `serverscrub deps` command');
t_contains($cli, 'Dependencies::summary', 'which reports the real state');
t_contains($cli, 'deps  ', 'and it is listed in the help output');
t_contains($cli, 'pinned forever',
     'and the command states why these are packaged rather than downloaded');

// ── Telling an abandoned CSF apart from a maintained fork ───────────────────
//
// The original vendor's last release was 15.00. Anything newer is necessarily
// a community fork, and that is the only signal available locally -- the
// alternative would be contacting a host to ask, which is the thing this whole
// check exists to avoid.
//
// This matters because flagging a maintained fork would be a false alarm, and
// a warning that is usually wrong gets ignored -- including the time it is
// right.
t_eq('15.00', Dependencies::CSF_LAST_UPSTREAM,
     "the original vendor's final release is recorded");
t_ok(version_compare('15.04', Dependencies::CSF_LAST_UPSTREAM, '>'),
     'the Black-HOST community fork (15.04) reads as newer than upstream ever was');
t_ok(!version_compare('14.19', Dependencies::CSF_LAST_UPSTREAM, '>'),
     'and an old abandoned build does not');

// The community fork is named in code so an operator who wants CSF on a
// non-cPanel server is pointed somewhere real instead of being told "no".
t_eq('https://github.com/Black-HOST/csf', Dependencies::CSF_COMMUNITY_REPO,
     'the maintained community fork is recorded');

if (!Dependencies::isCpanel()) {
    $src = Dependencies::status()['csf']['source'];
    t_contains($src, 'Black-HOST/csf',
         'off cPanel the operator is pointed at the fork that works there');
    t_contains($src, 'pinned release',
         'and told to use a pinned release rather than the one-liner');
    // The point of that advice: CSF runs as root, and piping a third-party
    // domain's script into a root shell is how configserver.com became a
    // liability. We are not repeating the pattern on a customer's behalf.
    t_contains($src, 'root shell',
         'with the reason stated, not just the instruction');
    t_contains($src, 'detect it',
         'and told ServerScrub will use it once installed');
}

// Whatever the fork, ServerScrub must never install it for them: that is a
// root-level trust decision about a third party, made on behalf of every
// server this product touches.
t_ok(!preg_match('/(?:curl|wget)[^
|]*csf\.black\.host/i', $install),
     "the installer does not pipe the community fork's one-liner into a root shell");
t_ok(!preg_match('/(?:curl|wget)[^
|]*Black-HOST/i', $install),
     'nor fetch it any other way — the operator chooses to trust it, we do not '
   . 'choose for them');
