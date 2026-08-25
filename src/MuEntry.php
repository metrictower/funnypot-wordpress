<?php

declare(strict_types=1);

namespace Funnypot\WordPress;

/**
 * The stable, versioned entry the mu-loader shim require's + calls (SF-4). Kept deliberately tiny and
 * skew-tolerant: it only ensures the plugin is bootstrapped for the BEFORE position. The shim wraps
 * this call in class_exists/method_exists + try/catch, so an old shim against a newer plugin (or the
 * reverse) degrades to inert rather than fataling. 7.3-clean.
 */
final class MuEntry
{
    /** @var bool */
    private static $booted = false;

    /**
     * Register the BEFORE position at muplugins_loaded. Idempotent + guarded so it can never fatal a
     * request (the one code path that runs before the interceptor's own try/catch exists).
     */
    public static function boot()
    {
        if (self::$booted) {
            return;
        }
        self::$booted = true;

        if (class_exists('Funnypot\Core\\WordPress\\Plugin') && method_exists('Funnypot\Core\\WordPress\\Plugin', 'registerBefore')) {
            Plugin::registerBefore();
        }
    }
}
