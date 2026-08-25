<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Reputation;

use Funnypot\Mainnet\CheckResult;
use Funnypot\Policy\Port\ReputationInterface;
use Funnypot\Policy\ReputationVerdict;

/**
 * The policy's ReputationInterface over F's cache-first read (design §4.8). CONTRACT: NEVER a
 * synchronous network call on the request path (M5) — it reads F's already-resolved cached verdict
 * only, and on a miss it enqueues the off-mirror actor IP to the out-of-band Warmer (never checks it
 * inline). Any fault degrades to a fail-open 'unknown'. The cached-read is an injected callable so the
 * bridge never hard-binds F's final Client and stays unit-testable. 7.3-clean.
 */
final class MainnetReputation implements ReputationInterface
{
    /** @var callable(string):?CheckResult F's request-path read (cachedVerdict) — no socket */
    private $cachedVerdictFn;
    /** @var Warmer|null */
    private $warmer;

    /**
     * @param callable    $cachedVerdictFn fn(string $ip): ?CheckResult
     * @param Warmer|null $warmer          the off-mirror escalation warmer
     */
    public function __construct(callable $cachedVerdictFn, $warmer = null)
    {
        $this->cachedVerdictFn = $cachedVerdictFn;
        $this->warmer = $warmer;
    }

    public function lookup(string $ip)
    {
        try {
            $result = call_user_func($this->cachedVerdictFn, $ip);
        } catch (\Throwable $e) {
            return ReputationVerdict::failOpen();
        }

        if ($result === null) {
            // Uncached + off-mirror -> enqueue for the out-of-band warmer; the request never blocks.
            if ($this->warmer !== null) {
                $this->warmer->enqueue($ip);
            }

            return ReputationVerdict::absent();
        }

        return self::convert($result);
    }

    private static function convert(CheckResult $r)
    {
        if ($r->isFailOpen()) {
            return ReputationVerdict::failOpen();
        }
        $context = $r->context();
        $usageType = isset($context['usage_type']) && $context['usage_type'] !== null
            ? (string) $context['usage_type'] : null;

        // The verdict + source constants line up between the packages; carry the score + usage type.
        return new ReputationVerdict($r->verdict(), $r->score(), ReputationVerdict::SOURCE_CACHE, $usageType);
    }
}
