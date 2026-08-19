<?php

declare(strict_types=1);

namespace Honeypot\WP\Log;

/**
 * The hit-log seam (design §4.5). DecisionExecutor records one row per log/deceive/block. The row
 * carries only fingerprint-safe fields — the matched signal is the policy's OPAQUE reason label,
 * never a canonical signature string (§6.1).
 */
interface HitLogWriter
{
    /** @param array $row {ts, ip, method, path, action, reason, status} */
    public function record(array $row);
}
