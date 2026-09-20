<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Support;

use Funnypot\Core\Rules\HttpFetcher;
use Funnypot\Core\Rules\RulesUpdateException;

/**
 * A network-free HttpFetcher serving bytes from an in-memory URL map. Lets the RulesAutoUpdate wiring
 * exercise the real core updater's whole verify/swap flow without touching the network. Mirrors the
 * core suite's test double (funnypot-core tests/Support/ArrayFetcher.php) so the WP wiring tests the
 * same contract the engine tests do.
 */
final class ArrayFetcher implements HttpFetcher
{
    /** @var array<string,string> */
    private $map;

    /** @param array<string,string> $map url => bytes */
    public function __construct(array $map = array())
    {
        $this->map = $map;
    }

    public function put(string $url, string $bytes): void
    {
        $this->map[$url] = $bytes;
    }

    public function get(string $url): string
    {
        if (!array_key_exists($url, $this->map)) {
            throw new RulesUpdateException(RulesUpdateException::REASON_FETCH_FAILED, "no such asset: {$url}");
        }

        return $this->map[$url];
    }
}
