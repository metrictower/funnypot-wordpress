<?php

declare(strict_types=1);

namespace Honeypot\WP;

/**
 * Per-install sensor UUID (design §4.11, D3). Generated ONCE on first run and persisted to a
 * dedicated WP option; sent as `sensor_id` on every report — a convenience/label only, NEVER a
 * hardware/MAC id (blocked reads, privacy, portability). The pure resolver injects the option
 * get/set and the generator so it is unit-testable without WordPress. 7.3-clean.
 */
final class SensorId
{
    const OPTION = 'honeypot_wp_sensor_id';

    /**
     * Return the stored id when present and well-formed; otherwise generate one, persist it, and
     * return it. Never regenerates a valid stored id.
     *
     * @param callable $getOption fn(): mixed — reads the stored option (null/'' when absent)
     * @param callable $setOption fn(string $id): void — persists the option
     * @param callable $generate  fn(): string — produces a v4 UUID
     * @return string
     */
    public static function resolve(callable $getOption, callable $setOption, callable $generate)
    {
        $stored = $getOption();
        if (is_string($stored) && self::isValidUuid($stored)) {
            return $stored;
        }

        $id = (string) $generate();
        if (!self::isValidUuid($id)) {
            $id = self::randomUuidV4();
        }
        $setOption($id);

        return $id;
    }

    /** A random-bytes v4 UUID fallback for when wp_generate_uuid4() is unavailable. */
    public static function randomUuidV4()
    {
        try {
            $data = random_bytes(16);
        } catch (\Throwable $e) {
            // Extremely defensive: mt_rand fallback. Identity label only, not a secret.
            $data = '';
            for ($i = 0; $i < 16; $i++) {
                $data .= chr(mt_rand(0, 255));
            }
        }
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40); // version 4
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80); // variant

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    public static function isValidUuid($value)
    {
        return is_string($value)
            && preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $value) === 1;
    }
}
