<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Db;

/**
 * Runs a $wpdb operation with wpdb's own error output suppressed.
 *
 * A wpdb write to a missing/broken table does not throw — it returns false and routes through
 * wpdb::print_error(), which echoes the raw DB error to the response and error_log()s it. On a
 * request-facing path that echo is a fingerprint tell (a real WordPress page never prints it), so
 * every request/cron-facing plugin write is wrapped here to degrade to a silent no-op instead.
 *
 * The caller's prior suppression state is captured and restored in finally, so suppression is never
 * left leaking to the rest of the request and nested calls stay correct (an inner call captures/
 * restores true, the outer restores the real prior). 7.3-clean.
 */
final class WpdbSilencer
{
    /**
     * @param object   $wpdb the WordPress $wpdb handle
     * @param callable $fn   the operation to run under suppression; its value is returned
     * @return mixed the value returned by $fn
     */
    public static function silently($wpdb, callable $fn)
    {
        $canSuppress = is_object($wpdb) && method_exists($wpdb, 'suppress_errors');
        // Capture the prior value so we restore exactly what the caller had, never a hardcoded false.
        $prior = $canSuppress ? $wpdb->suppress_errors(true) : null;
        try {
            return $fn();
        } finally {
            if ($canSuppress) {
                $wpdb->suppress_errors($prior);
            }
        }
    }
}
