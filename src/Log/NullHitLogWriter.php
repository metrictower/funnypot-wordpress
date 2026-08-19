<?php

declare(strict_types=1);

namespace Honeypot\WP\Log;

/** The default hit-log writer: swallows every row (logging off). */
final class NullHitLogWriter implements HitLogWriter
{
    public function record(array $row)
    {
        // no-op
    }
}
