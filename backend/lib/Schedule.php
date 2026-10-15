<?php
/**
 * When a scheduled task is due.
 *
 * Pulled out of scheduler.php so it can be tested. It had never been: the
 * logic lived inside a script that runs its tasks on include, so the only way
 * to exercise it was to let it fire real scans.
 */
class Schedule
{
    /**
     * Is a task due?
     *
     * @param string $schedule  off | every | hourly | daily | weekly
     * @param int    $last      when it last ran (0 = never)
     * @param int    $now       the current time
     * @param string $atTime    HH:MM, for daily and weekly
     * @param int    $onDay     0-6, Sunday first, for weekly
     */
    public static function isDue(string $schedule, int $last, int $now,
                                 string $atTime = '02:00', int $onDay = 0): bool
    {
        // 'disabled' is accepted as a synonym: the settings UI grew a select
        // that used that word, and a schedule string the scheduler does not
        // recognise falls through to `return false` below -- indistinguishable
        // from off, but by accident rather than intent.
        if ($schedule === 'off' || $schedule === 'disabled' || $schedule === '') {
            return false;
        }

        // An unrecognised schedule is a misconfiguration, not a schedule.
        // The never-run shortcut below used to come first, so a typo in the
        // setting ran the task exactly once and then never again -- the most
        // confusing of the three possible behaviours.
        if (!in_array($schedule, ['every', 'hourly', 'daily', 'weekly'], true)) {
            return false;
        }

        if ($last === 0) { return true; }          // never run - run now

        $elapsed = $now - $last;

        switch ($schedule) {
            // Every scheduler tick, which cron fires at */15. For work that is
            // cheap and wants to react promptly rather than on the hour -- the
            // 60-second floor only guards against a double-fire.
            case 'every':
                return $elapsed >= 60;

            case 'hourly':
                return $elapsed >= 3600 - 300;      // 5 min slack for tick jitter

            // Anchored to the configured time of day, NOT to the last run.
            //
            // This used to require 23h55m to have elapsed before even looking
            // at the clock, which made the configured time meaningless after
            // the first late run. A scan set for 09:00 that once ran at 20:30
            // could not run again until 20:25 the next day -- by which point
            // 09:00 had long passed, so it ran at 20:30 again, and again, for
            // ever. The gate was a ratchet: every run could drift later and
            // none could drift back. On the server that reported this, a scan
            // configured for 09:00 was running at 20:30, and iprep set for
            // 03:00 was running at 04:18.
            //
            // pastTimeOfDay() already answers the real question -- has today's
            // boundary passed, and have we not run since it -- which both
            // prevents a double-fire and lets a task recover its proper time.
            case 'daily':
                return self::pastTimeOfDay($atTime, $now, $last);

            case 'weekly':
                if ((int) date('w', $now) !== $onDay) { return false; }
                return self::pastTimeOfDay($atTime, $now, $last);
        }
        return false;
    }

    /** True once today has passed the configured time and we have not run since. */
    public static function pastTimeOfDay(string $hhmm, int $now, int $last): bool
    {
        [$h, $m] = array_pad(explode(':', $hhmm, 2), 2, '0');
        $target  = mktime((int) $h, (int) $m, 0,
                          (int) date('n', $now), (int) date('j', $now), (int) date('Y', $now));
        if ($now < $target) { return false; }
        return $last < $target;
    }
}
