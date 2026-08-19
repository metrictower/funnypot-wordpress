<?php

declare(strict_types=1);

namespace Honeypot\WP;

use Funnypot\Policy\Port\Logger;

/**
 * The policy Logger port over an injected sink (default error_log). It logs only the level + message +
 * the non-sensitive reason label — NEVER a canonical signature string or a raw attacker payload (§6.1).
 * A logger fault is swallowed so it can never turn a fail-open into a 500. 7.3-clean.
 */
final class WpLogger implements Logger
{
    /** @var callable(string):void */
    private $sink;

    /** @param callable|null $sink fn(string $line): void; defaults to error_log */
    public function __construct($sink = null)
    {
        $this->sink = $sink !== null ? $sink : 'error_log';
    }

    public function log(string $level, string $message, array $context = array())
    {
        try {
            $reason = isset($context['reason']) ? (string) $context['reason'] : '';
            $line = 'honeypot-wp[' . $level . '] ' . $message . ($reason !== '' ? ' reason=' . $reason : '');
            call_user_func($this->sink, $line);
        } catch (\Throwable $ignored) {
            // logging must never affect the request
        }
    }
}
