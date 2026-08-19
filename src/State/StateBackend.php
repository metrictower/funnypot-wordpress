<?php

declare(strict_types=1);

namespace Honeypot\WP\State;

/**
 * A backend-independent TTL key/value seam (RS-10). WpStateStore maps every port method onto this, so
 * the policy engine is unaware which concrete backend is active. Two implementations ship:
 * ObjectCacheBackend (WP transients / persistent object cache — the default, never writes the plugin
 * dir) and FileBackend (a plugin-owned state dir for hosts without a shared object cache). 7.3-clean.
 */
interface StateBackend
{
    /**
     * @param string $key
     * @return mixed the stored value, or null on miss/expiry
     */
    public function get(string $key);

    /**
     * @param string $key
     * @param mixed  $value
     * @param int    $ttlSeconds 0 = no expiry
     * @return void
     */
    public function set(string $key, $value, int $ttlSeconds);

    /**
     * @param string $key
     * @return void
     */
    public function delete(string $key);
}
