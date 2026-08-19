<?php

declare(strict_types=1);

namespace Honeypot\WP\Report;

use Funnypot\Policy\ReportIntent;

/**
 * The seam DecisionExecutor enqueues a policy-vetted report through (design §4.9). WpReporterBridge
 * implements it; a null reporter means reporting is off. Enqueue is fast + local — never a blocking
 * POST on the visitor request.
 */
interface ReporterBridge
{
    /** Map a policy ReportIntent onto a queued report. */
    public function enqueueIntent(ReportIntent $r);
}
