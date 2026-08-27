<?php
/**
 * Sentinel Gate — static call checker.
 *
 * Every Foo::bar() must exist on Foo and be callable from outside it.
 *
 * php -l cannot see any of this: these are runtime Errors, not syntax errors,
 * and this codebase is almost entirely static calls between classes, so a
 * renamed or mistyped method stays invisible until the one request that uses it
 * runs. Three releases were spent fixing one instance at a time:
 *
 *     License::log()    -> Logger::write()          private
 *     License::result() -> Database::getSetting()   does not exist
 *
 * A regex version of this check missed seven call sites in a single file,
 * because its string-stripping ate real code. token_get_all() is PHP's own
 * lexer, so strings, comments and heredocs are classified exactly rather than
 * guessed at.
 *
 * Usage:  php scripts/check-calls.php [path]
 * Exit 0 = clean, 1 = problems found.
 */

$root = $argv[1] ?? dirname(__DIR__) . '/backend';

/** Classes we do not own; their API is not ours to verify. */
$ignore = array_flip([
    'self', 'static', 'parent', 'PDO', 'PDOStatement', 'PDOException',
    'Throwable', 'Exception', 'Error', 'TypeError', 'ValueError',
    'RuntimeException', 'InvalidArgumentException', 'JsonException',
    'DateTime', 'DateTimeImmutable', 'DateInterval', 'Closure', 'Generator',
    'ArrayObject', 'SplFileInfo', 'SplQueue', 'SQLite3', 'stdClass',
    'RecursiveIteratorIterator', 'RecursiveDirectoryIterator',
    'DirectoryIterator', 'FilesystemIterator', 'IteratorIterator',
]);

// ── Collect files ────────────────────────────────────────────────────────────
$files = [];
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
foreach ($it as $f) {
    if ($f->isFile() && strtolower($f->getExtension()) === 'php') {
        $files[] = $f->getPathname();
    }
}
sort($files);

// ── Pass 1: declarations ─────────────────────────────────────────────────────
$methods = [];   // class => [method => visibility]
$constants = []; // class => [NAME => true]
$ownerOf = [];   // file  => class

/**
 * Read a file or abort. A transient read failure once made this checker skip a
 * file and then report "All cross-class static calls resolve" — a false pass is
 * worse than no check, because it is indistinguishable from a real one.
 */
function must_read(string $path): string {
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $src = @file_get_contents($path);
        if ($src !== false) { return $src; }
        usleep(200000);
    }
    fwrite(STDERR, "check-calls: cannot read {$path} — refusing to report a result
");
    exit(2);
}

foreach ($files as $file) {
    $tokens = token_get_all(must_read($file));
    $class = null;
    $pendingVis = 'public';
    $depth = 0;

    foreach ($tokens as $i => $t) {
        if (is_string($t)) {
            if ($t === '{') { $depth++; }
            if ($t === '}') { $depth--; }
            continue;
        }
        [$id, $text] = $t;

        if ($id === T_CLASS) {
            // Skip ::class and anonymous classes
            $prev = $tokens[$i - 1] ?? null;
            if (is_array($prev) && $prev[0] === T_DOUBLE_COLON) { continue; }
            for ($j = $i + 1; $j < count($tokens); $j++) {
                if (is_array($tokens[$j]) && $tokens[$j][0] === T_STRING) {
                    $class = $tokens[$j][1];
                    $ownerOf[$file] = $class;
                    $methods[$class] = $methods[$class] ?? [];
                    $constants[$class] = $constants[$class] ?? [];
                    break;
                }
            }
            continue;
        }

        if (in_array($id, [T_PUBLIC, T_PRIVATE, T_PROTECTED], true)) {
            $pendingVis = strtolower($text);
            continue;
        }

        if ($id === T_CONST && $class !== null) {
            for ($j = $i + 1; $j < count($tokens); $j++) {
                if (is_array($tokens[$j]) && $tokens[$j][0] === T_STRING) {
                    $constants[$class][$tokens[$j][1]] = true;
                    break;
                }
            }
            continue;
        }

        if ($id === T_FUNCTION && $class !== null) {
            for ($j = $i + 1; $j < count($tokens); $j++) {
                if (is_array($tokens[$j]) && $tokens[$j][0] === T_STRING) {
                    $methods[$class][$tokens[$j][1]] = $pendingVis;
                    break;
                }
                if (is_string($tokens[$j]) && $tokens[$j] === '(') { break; } // closure
            }
            $pendingVis = 'public';
            continue;
        }
    }
}

// ── Pass 2: call sites ───────────────────────────────────────────────────────
$problems = [];

foreach ($files as $file) {
    $tokens = token_get_all(must_read($file));
    $owner = $ownerOf[$file] ?? null;
    $n = count($tokens);

    for ($i = 0; $i < $n; $i++) {
        $t = $tokens[$i];
        if (!is_array($t) || $t[0] !== T_DOUBLE_COLON) { continue; }

        $left = null;
        for ($j = $i - 1; $j >= 0; $j--) {
            if (is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) { continue; }
            if (is_array($tokens[$j]) && $tokens[$j][0] === T_STRING) { $left = $tokens[$j][1]; }
            break;
        }
        if ($left === null || isset($ignore[$left]) || $left === $owner) { continue; }
        if (!isset($methods[$left])) { continue; }   // not one of ours

        $meth = null; $line = $t[2];
        for ($j = $i + 1; $j < $n; $j++) {
            if (is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) { continue; }
            if (is_array($tokens[$j]) && $tokens[$j][0] === T_STRING) { $meth = $tokens[$j][1]; }
            break;
        }
        if ($meth === null) { continue; }

        // Only flag actual calls; bare Foo::BAR is a constant reference.
        $isCall = false;
        for ($k = $j + 1; $k < $n; $k++) {
            if (is_array($tokens[$k]) && $tokens[$k][0] === T_WHITESPACE) { continue; }
            $isCall = (is_string($tokens[$k]) && $tokens[$k] === '(');
            break;
        }
        if (!$isCall) { continue; }
        if (isset($constants[$left][$meth])) { continue; }

        $rel = str_replace(dirname(__DIR__) . DIRECTORY_SEPARATOR, '', $file);

        if (!isset($methods[$left][$meth])) {
            $near = [];
            foreach (array_keys($methods[$left]) as $cand) {
                $a = strtolower($cand); $b = strtolower($meth);
                if (str_contains($b, $a) || str_contains($a, $b)) { $near[] = $left . '::' . $cand . '()'; }
            }
            $hint = $near ? '  (did you mean ' . implode(', ', array_slice($near, 0, 3)) . '?)' : '';
            $problems[] = sprintf('MISSING    %s:%d  %s::%s()%s', $rel, $line, $left, $meth, $hint);
        } elseif ($methods[$left][$meth] !== 'public') {
            $problems[] = sprintf('NONPUBLIC  %s:%d  %s::%s() is %s',
                                  $rel, $line, $left, $meth, $methods[$left][$meth]);
        }
    }
}

// ── Pass 3: (new Foo())->bar() ───────────────────────────────────────────────
// The static checker missed `(new FileIntegrity())->checkAll()` in the cron
// scheduler -- a method that does not exist, in code that would only run once a
// day and fail silently into a log nobody reads. The router and scheduler are
// built on this pattern, so it needs the same treatment.
foreach ($files as $file) {
    $tokens = token_get_all(must_read($file));
    $n = count($tokens);

    for ($i = 0; $i < $n; $i++) {
        if (!is_array($tokens[$i]) || $tokens[$i][0] !== T_NEW) { continue; }

        // class name directly after `new`
        $cls = null; $j = $i + 1;
        for (; $j < $n; $j++) {
            if (is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) { continue; }
            if (is_array($tokens[$j]) && $tokens[$j][0] === T_STRING) { $cls = $tokens[$j][1]; }
            break;
        }
        if ($cls === null || isset($ignore[$cls]) || !isset($methods[$cls])) { continue; }

        // walk past the constructor's parenthesis pair
        $depth = 0; $k = $j;
        for (; $k < $n; $k++) {
            $t = $tokens[$k];
            if (is_string($t) && $t === '(') { $depth++; }
            elseif (is_string($t) && $t === ')') { $depth--; if ($depth === 0) { $k++; break; } }
        }
        // and any closing paren of `(new Foo(...))`
        for (; $k < $n; $k++) {
            if (is_array($tokens[$k]) && $tokens[$k][0] === T_WHITESPACE) { continue; }
            if (is_string($tokens[$k]) && $tokens[$k] === ')') { continue; }
            break;
        }
        if (!(is_array($tokens[$k] ?? null) && $tokens[$k][0] === T_OBJECT_OPERATOR)) { continue; }

        $meth = null; $line = $tokens[$i][2];
        for ($m2 = $k + 1; $m2 < $n; $m2++) {
            if (is_array($tokens[$m2]) && $tokens[$m2][0] === T_WHITESPACE) { continue; }
            if (is_array($tokens[$m2]) && $tokens[$m2][0] === T_STRING) { $meth = $tokens[$m2][1]; }
            break;
        }
        if ($meth === null) { continue; }

        $rel = str_replace(dirname(__DIR__) . DIRECTORY_SEPARATOR, '', $file);
        if (!isset($methods[$cls][$meth])) {
            $near = [];
            foreach (array_keys($methods[$cls]) as $cand) {
                $a = strtolower($cand); $b = strtolower($meth);
                if (str_contains($b, $a) || str_contains($a, $b)) { $near[] = $cls . '->' . $cand . '()'; }
            }
            $hint = $near ? '  (did you mean ' . implode(', ', array_slice($near, 0, 3)) . '?)' : '';
            $problems[] = sprintf('MISSING    %s:%d  (new %s)->%s()%s', $rel, $line, $cls, $meth, $hint);
        } elseif ($methods[$cls][$meth] !== 'public') {
            $problems[] = sprintf('NONPUBLIC  %s:%d  (new %s)->%s() is %s',
                                  $rel, $line, $cls, $meth, $methods[$cls][$meth]);
        }
    }
}

$problems = array_values(array_unique($problems));
sort($problems);

if ($problems) {
    echo implode("\n", $problems), "\n\n";
    echo count($problems), " problem call site(s).\n";
    exit(1);
}
echo "All cross-class static calls resolve to public methods.\n";
exit(0);
