<?php

declare(strict_types=1);

namespace Honeypot\WP\Reputation;

use Funnypot\Mainnet\Cache\Cache;

/**
 * F's PSR-16-style cache seam over WP transients (design §4.8). Backs the reputation verdict cache
 * (mnc:v:*) AND the shared decision-N breaker marker (mnc:breaker) so the drain and the reputation
 * check/warmer path discover an outage through one record. Caches BOTH positive and negative verdicts
 * (F caches misses too). Keys are namespaced (honeypot_wp_rep_), distinct from the WpStateStore
 * namespace so the two concerns never collide. The transient primitives are injected so it is
 * unit-testable without WordPress. 7.3-clean.
 */
final class WpCache implements Cache
{
    const PREFIX = 'honeypot_wp_rep_';

    /** @var callable */
    private $getFn;
    /** @var callable */
    private $setFn;
    /** @var callable */
    private $deleteFn;

    /**
     * @param callable|null $getFn    fn(string $key): mixed — get_transient (false on miss)
     * @param callable|null $setFn    fn(string $key, $value, int $ttl): bool — set_transient
     * @param callable|null $deleteFn fn(string $key): bool — delete_transient
     */
    public function __construct($getFn = null, $setFn = null, $deleteFn = null)
    {
        $this->getFn = $getFn !== null ? $getFn : 'get_transient';
        $this->setFn = $setFn !== null ? $setFn : 'set_transient';
        $this->deleteFn = $deleteFn !== null ? $deleteFn : 'delete_transient';
    }

    public function get(string $key, $default = null)
    {
        $value = call_user_func($this->getFn, self::key($key));
        if (!is_array($value) || !array_key_exists('v', $value)) {
            return $default;
        }

        return $value['v'];
    }

    public function set(string $key, $value, int $ttlSeconds = 0)
    {
        return (bool) call_user_func($this->setFn, self::key($key), array('v' => $value), $ttlSeconds);
    }

    public function has(string $key)
    {
        $value = call_user_func($this->getFn, self::key($key));

        return is_array($value) && array_key_exists('v', $value);
    }

    /** Namespaced, and hashed when long enough to risk the WP option-name length cap. */
    private static function key(string $key)
    {
        $full = self::PREFIX . $key;
        if (strlen($full) > 160) {
            return self::PREFIX . md5($key);
        }

        return $full;
    }
}
