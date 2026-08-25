<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Fakes;

use Funnypot\Policy\Port\Clock;

/** A deterministic, advanceable Clock for TTL/decay tests. */
final class MutableClock implements Clock
{
    /** @var int */
    private $t;

    public function __construct(int $start = 1000000)
    {
        $this->t = $start;
    }

    public function now()
    {
        return $this->t;
    }

    public function advance(int $secs)
    {
        $this->t += $secs;
    }

    public function set(int $t)
    {
        $this->t = $t;
    }

    /** A callable():int view of this clock (for callable-clock consumers). */
    public function asCallable()
    {
        $self = $this;

        return static function () use ($self) {
            return $self->now();
        };
    }
}
