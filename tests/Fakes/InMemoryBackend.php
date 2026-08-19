<?php

declare(strict_types=1);

namespace Honeypot\WP\Tests\Fakes;

use Honeypot\WP\State\StateBackend;

/** An in-memory TTL KV StateBackend for tests, honoring expiry against an injected clock callable. */
final class InMemoryBackend implements StateBackend
{
    /** @var array<string,array{v:mixed,exp:int}> */
    private $store = array();
    /** @var callable():int */
    private $clock;

    /** @param callable|null $clock fn(): int epoch; defaults to time() */
    public function __construct($clock = null)
    {
        $this->clock = $clock !== null ? $clock : 'time';
    }

    public function get(string $key)
    {
        if (!isset($this->store[$key])) {
            return null;
        }
        $row = $this->store[$key];
        if ($row['exp'] > 0 && $row['exp'] < $this->now()) {
            unset($this->store[$key]);
            return null;
        }

        return $row['v'];
    }

    public function set(string $key, $value, int $ttlSeconds)
    {
        $this->store[$key] = array('v' => $value, 'exp' => $ttlSeconds > 0 ? $this->now() + $ttlSeconds : 0);
    }

    public function delete(string $key)
    {
        unset($this->store[$key]);
    }

    private function now()
    {
        return (int) call_user_func($this->clock);
    }
}
