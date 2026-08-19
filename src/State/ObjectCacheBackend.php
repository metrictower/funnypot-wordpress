<?php

declare(strict_types=1);

namespace Honeypot\WP\State;

/**
 * The default RS-10 backend: WP transients, which ride the persistent object cache when the host has
 * one and never write into the plugin directory. The transient primitives are injected callables so
 * the backend is unit-testable without WordPress. Keys are namespaced (honeypot_wp_ss_). 7.3-clean.
 */
final class ObjectCacheBackend implements StateBackend
{
    const PREFIX = 'honeypot_wp_ss_';

    /** @var callable(string):mixed */
    private $getFn;
    /** @var callable(string,mixed,int):bool */
    private $setFn;
    /** @var callable(string):bool */
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

    public function get(string $key)
    {
        $value = call_user_func($this->getFn, self::key($key));

        // WP transients return false on miss; our stored values are wrapped so false !== "stored false".
        if (!is_array($value) || !array_key_exists('v', $value)) {
            return null;
        }

        return $value['v'];
    }

    public function set(string $key, $value, int $ttlSeconds)
    {
        call_user_func($this->setFn, self::key($key), array('v' => $value), $ttlSeconds);
    }

    public function delete(string $key)
    {
        call_user_func($this->deleteFn, self::key($key));
    }

    /** WP option/transient names cap at 172 chars; hash long keys to stay under it and namespaced. */
    private static function key(string $key)
    {
        $full = self::PREFIX . $key;
        if (strlen($full) > 160) {
            return self::PREFIX . md5($key);
        }

        return $full;
    }
}
