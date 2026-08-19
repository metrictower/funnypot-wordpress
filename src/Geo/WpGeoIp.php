<?php

declare(strict_types=1);

namespace Honeypot\WP\Geo;

use Funnypot\Policy\Port\GeoIpInterface;

/**
 * The country-resolution port for the policy's country gate (design §4.14, decision R2). Resolves an
 * ISO-3166 alpha-2 country from a LOCAL GeoIP DB — NEVER a network call on the request path (M5). The
 * DB reader is injected (a lookup callable) so it is pure-unit-testable and a stale/missing/unreadable
 * DB is handled: any miss or fault returns null (FAIL-OPEN — the gate then contributes nothing, never
 * an error). D authors NO country decision logic; the posture/action is the policy's. 7.3-clean.
 */
final class WpGeoIp implements GeoIpInterface
{
    /** @var callable(string):?string|null fn(string $ip): ?string — the local-DB lookup */
    private $reader;

    /** @param callable|null $reader fn(string $ip): ?string; null => no DB (every lookup is a miss) */
    public function __construct($reader = null)
    {
        $this->reader = $reader;
    }

    public function country(string $ip)
    {
        if ($this->reader === null) {
            return null; // no local DB wired -> fail-open
        }
        try {
            $code = call_user_func($this->reader, $ip);
        } catch (\Throwable $e) {
            return null; // a reader fault must never surface as an error (fail-open)
        }
        if (!is_string($code) || !preg_match('/^[A-Za-z]{2}$/', $code)) {
            return null;
        }

        return strtoupper($code);
    }
}
