<?php

declare(strict_types=1);

namespace Honeypot\WP\Admin;

/**
 * Admin-notice copy for a degraded BEFORE mount (Wordfence gap a). Pure decision — extracted so it is
 * unit-testable; the WP admin_notices hook renders whatever this returns. 7.3-clean.
 */
final class Notices
{
    /**
     * The notice text when the effective BEFORE mount is degraded below the configured posture, else
     * null (no notice).
     *
     * @param string $mountState        'mu-plugin' | 'plugins_loaded (degraded)' | 'not running' | 'n/a'
     * @param bool   $beforeConfigured  is a BEFORE-position posture (WAF/both) configured?
     * @return string|null
     */
    public static function noticeFor($mountState, $beforeConfigured)
    {
        if (!$beforeConfigured) {
            return null; // honeypot (fallback-only) posture -> the BEFORE mount is irrelevant
        }
        if ($mountState === 'mu-plugin') {
            return null; // running at the earliest hook -> nothing to warn about
        }
        if ($mountState === 'plugins_loaded (degraded)') {
            return 'Honeypot is running at plugins_loaded, not the earliest mu-plugin hook. '
                . 'The must-use loader shim is missing or the mu-plugins directory is not writable, '
                . 'so BEFORE-position protection starts later than configured.';
        }
        if ($mountState === 'not running') {
            return 'Honeypot BEFORE-position protection is configured but not running — no hook fired. '
                . 'Re-save the plugin settings, or check that the must-use loader shim is present.';
        }

        return null;
    }
}
