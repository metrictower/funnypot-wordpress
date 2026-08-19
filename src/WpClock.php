<?php

declare(strict_types=1);

namespace Honeypot\WP;

use Funnypot\Policy\Port\Clock;

/** Thin time() wrapper (design §4.3) — injected so TTL/decay/window math is deterministic in tests. */
final class WpClock implements Clock
{
    /** @var callable():int */
    private $source;

    /** @param callable|null $source fn(): int epoch; defaults to time() */
    public function __construct($source = null)
    {
        $this->source = $source !== null ? $source : 'time';
    }

    public function now()
    {
        return (int) call_user_func($this->source);
    }
}
