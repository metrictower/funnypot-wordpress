<?php

declare(strict_types=1);

namespace Honeypot\WP\Reputation;

use Funnypot\Policy\Port\ReputationInterface;
use Funnypot\Policy\ReputationVerdict;

/**
 * The default ReputationInterface when checking is off/inert: every lookup is 'absent' (nothing
 * covers the IP), so reputation contributes nothing to the policy precedence. No key, no lookup, no
 * visitor IP leaves the host — the default-install posture.
 */
final class NullReputation implements ReputationInterface
{
    public function lookup(string $ip)
    {
        return ReputationVerdict::absent();
    }
}
