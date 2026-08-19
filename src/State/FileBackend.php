<?php

declare(strict_types=1);

namespace Honeypot\WP\State;

/**
 * The opt-in RS-10 backend for hosts without a persistent object cache but with a writable state path.
 * Each key is a JSON file carrying the value + an expiry stamp. Fail-soft: an unwritable/unreadable
 * path degrades to a miss, never an exception (the store then behaves as an empty cache). 7.3-clean.
 */
final class FileBackend implements StateBackend
{
    /** @var string */
    private $dir;
    /** @var callable():int */
    private $clock;

    /**
     * @param string        $dir   the plugin-owned state directory (created if absent)
     * @param callable|null $clock fn(): int epoch; defaults to time()
     */
    public function __construct(string $dir, $clock = null)
    {
        $this->dir = rtrim($dir, '/');
        $this->clock = $clock !== null ? $clock : 'time';
        if (!is_dir($this->dir)) {
            @mkdir($this->dir, 0700, true);
        }
    }

    public function get(string $key)
    {
        $file = $this->path($key);
        if (!is_file($file)) {
            return null;
        }
        $raw = @file_get_contents($file);
        if ($raw === false || $raw === '') {
            return null;
        }
        $row = json_decode($raw, true);
        if (!is_array($row) || !array_key_exists('v', $row)) {
            return null;
        }
        if (isset($row['exp']) && $row['exp'] > 0 && $row['exp'] < $this->now()) {
            @unlink($file);
            return null;
        }

        return $row['v'];
    }

    public function set(string $key, $value, int $ttlSeconds)
    {
        $exp = $ttlSeconds > 0 ? $this->now() + $ttlSeconds : 0;
        $payload = json_encode(array('v' => $value, 'exp' => $exp));
        if ($payload === false) {
            return;
        }
        @file_put_contents($this->path($key), $payload, LOCK_EX);
    }

    public function delete(string $key)
    {
        $file = $this->path($key);
        if (is_file($file)) {
            @unlink($file);
        }
    }

    private function path(string $key)
    {
        return $this->dir . '/hpwp_' . md5($key) . '.json';
    }

    private function now()
    {
        return (int) call_user_func($this->clock);
    }
}
