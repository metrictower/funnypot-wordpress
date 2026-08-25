<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Admin;

use Funnypot\WordPress\Settings;

/**
 * The register_setting sanitize callback (design §6.6). Whitelists raw admin input to the Settings
 * shape by running it through the SAME normalizer the runtime uses (one source of truth): strips any
 * path from mainnet_base_url, whitelists posture/fail_mode/backend/country enums, whitelists
 * block_verdicts, coerces min_block_score to int|null, and clamps the numeric knobs. Pure; the nonce +
 * capability checks live in the WP settings API around it. 7.3-clean.
 */
final class SettingsSanitizer
{
    /**
     * @param array $input the raw submitted settings
     * @return array the normalized, whitelisted settings array (safe to persist)
     */
    public static function sanitize($input)
    {
        if (!is_array($input)) {
            $input = array();
        }

        // Admin textareas submit newline/comma-separated strings; the normalizer expects arrays for
        // list fields, so split them first.
        foreach (array('self_ips', 'trusted_proxies', 'catalog_disabled', 'country_list') as $key) {
            if (isset($input[$key]) && is_string($input[$key])) {
                $input[$key] = self::splitList($input[$key]);
            }
        }
        if (isset($input['allowlist']) && is_array($input['allowlist'])) {
            foreach (array('ips', 'cidrs', 'asns', 'safe_paths') as $key) {
                if (isset($input['allowlist'][$key]) && is_string($input['allowlist'][$key])) {
                    $input['allowlist'][$key] = self::splitList($input['allowlist'][$key]);
                }
            }
        }

        // Checkbox fields absent from a form submission mean "off" — the normalizer already defaults
        // every missing bool to its safe (usually false/inert) value, so the round-trip is correct.
        return Settings::fromArray($input)->toArray();
    }

    /** Split a newline/comma-separated textarea value into a clean list. */
    private static function splitList($value)
    {
        $parts = preg_split('/[\r\n,]+/', (string) $value);
        $out = array();
        foreach ($parts as $p) {
            $p = trim($p);
            if ($p !== '') {
                $out[] = $p;
            }
        }

        return $out;
    }
}
