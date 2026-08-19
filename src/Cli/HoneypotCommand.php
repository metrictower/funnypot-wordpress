<?php

declare(strict_types=1);

namespace Honeypot\WP\Cli;

use Honeypot\WP\Settings;

/**
 * `wp honeypot <sub>` (design §4.10). The status summary is a PURE builder (unit-tested) reporting the
 * VERIFIED runtime mount — not the configured intent — so an operator sees when a wiped shim silently
 * demoted the BEFORE position (Wordfence gap a). The WP-CLI I/O around it is registered only when
 * WP_CLI is defined. 7.3-clean.
 */
final class HoneypotCommand
{
    /**
     * Compose the `wp honeypot status` summary. Pure — the caller supplies the verified mount, queue
     * depth, and mirror freshness so this never touches WP I/O.
     *
     * @param Settings    $s
     * @param string      $mountState        'mu-plugin' | 'plugins_loaded (degraded)' | 'not running' | 'n/a'
     * @param int         $queueDepth
     * @param int|null    $mirrorGeneratedAt epoch of the last mirror pull, or null
     * @param int         $now
     * @return string
     */
    public static function statusSummary(Settings $s, $mountState, $queueDepth, $mirrorGeneratedAt, $now)
    {
        $position = ($s->positionActive('before') ? 'before' : '') . ($s->positionActive('fallback') ? ($s->positionActive('before') ? '+fallback' : 'fallback') : '');
        if ($position === '') {
            $position = 'none';
        }

        $lines = array();
        $lines[] = 'Honeypot for WordPress';
        $lines[] = '  enabled:               ' . ($s->enabled() ? 'yes' : 'no');
        $lines[] = '  posture:               ' . $s->posture();
        $lines[] = '  configured position:   ' . $position;
        $lines[] = '  verified BEFORE mount: ' . $mountState;
        $lines[] = '  response style:        ' . $s->responseStyle();
        $lines[] = '  reputation check:      ' . ($s->checkActive() ? 'on' : 'off');
        $lines[] = '  local mirror:          ' . ($s->mirrorEnabled() && $s->checkActive() ? 'on' : 'off')
            . ' (age: ' . self::age($mirrorGeneratedAt, $now) . ')';
        $lines[] = '  reporting:             ' . ($s->reportingActive() ? 'on' : 'off');
        $lines[] = '  report queue depth:    ' . (int) $queueDepth;

        return implode("\n", $lines);
    }

    /** Human-readable age of a timestamp, or 'never' when absent. */
    public static function age($generatedAt, $now)
    {
        if ($generatedAt === null || (int) $generatedAt <= 0) {
            return 'never';
        }
        $delta = (int) $now - (int) $generatedAt;
        if ($delta < 0) {
            $delta = 0;
        }
        if ($delta < 60) {
            return $delta . 's ago';
        }
        if ($delta < 3600) {
            return intdiv($delta, 60) . 'm ago';
        }
        if ($delta < 86400) {
            return intdiv($delta, 3600) . 'h ago';
        }

        return intdiv($delta, 86400) . 'd ago';
    }

    /**
     * Register the command with WP-CLI. Called only when WP_CLI is defined. The subcommand bodies are
     * thin wrappers over the plugin services; kept out of the pure builder above.
     *
     * @param callable $servicesProvider fn(): array — {settings, store, reporter, mirror, geoip}
     * @return void
     */
    public static function register($servicesProvider)
    {
        if (!class_exists('WP_CLI')) {
            return;
        }
        \WP_CLI::add_command('honeypot', new self()); // methods resolved by WP-CLI reflection
        // The provider is stashed for the instance methods to resolve services lazily.
        self::$services = $servicesProvider;
    }

    /** @var callable|null */
    private static $services;

    private function services()
    {
        return is_callable(self::$services) ? call_user_func(self::$services) : array();
    }
}
