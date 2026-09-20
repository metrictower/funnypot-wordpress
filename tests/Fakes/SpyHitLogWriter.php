<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Fakes;

use Funnypot\WordPress\Log\HitLogWriter;

/** Records every row passed to it so a test can assert exactly what the absorber wrote. */
final class SpyHitLogWriter implements HitLogWriter
{
    /** @var array<int,array> */
    public $rows = array();

    public function record(array $row)
    {
        $this->rows[] = $row;
    }
}
