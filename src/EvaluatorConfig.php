<?php

declare(strict_types=1);

namespace Funnypot\WordPress;

use Funnypot\Core\Config as CoreConfig;

/**
 * Maps the STYLE/engine Settings knobs to core's Config, the object core's synthesize() reads
 * (design §4.7). This is ONLY the rendering config — D no longer authors any WHEN/WHETHER closure
 * (gate/probeSignature/killSwitch/trustedBypass are the policy's concern now, gone from D).
 *
 * M15 — core's Config is a positional constructor with no named-arg support on 7.3. This builds it
 * POSITIONALLY, passing params 1..N in exact order up to the highest one D sets, with core's own
 * default for every unmapped param. pathScope (pos 3) and personaBreadth (pos 5) are NOT in D's
 * mapping but MUST still be passed at their positions — a skipped middle positional arg silently
 * misassigns every later one. 7.3-clean (no named args).
 */
final class EvaluatorConfig
{
    /**
     * @param Settings      $s
     * @param callable|null $authSaltResolver fn(): string — the WP AUTH_SALT fallback for seedSalt
     * @return CoreConfig
     */
    public static function fromSettings(Settings $s, $authSaltResolver = null)
    {
        $seedSalt = $s->seedSalt();
        if ($seedSalt === '') {
            $seedSalt = self::resolveAuthSalt($authSaltResolver);
        }

        // Positional recipe (core Config constructor order). Each line pins its position + source.
        return new CoreConfig(
            'detect',                 //  1 mode          — classify()/synthesize() ignore it; core default
            null,                     //  2 gate          — the policy's concern; core default (closed)
            'matched-only',           //  3 pathScope     — NOT in D's map; core default (must be passed)
            null,                     //  4 personaSeed   — the policy seeds; core default
            'coherent',               //  5 personaBreadth— NOT in D's map; core default (must be passed)
            $s->responseStyle(),      //  6 responseStyle — STYLE
            $s->severityCeiling(),    //  7 severityCeiling
            65536,                    //  8 maxBodyBytes  — core default
            $s->latencyMs(),          //  9 latencyMs
            $s->latencyJitterMs(),    // 10 latencyJitterMs
            $s->attackEmulation(),    // 11 attackEmulation
            null,                     // 12 trustedBypass — the policy's concern; core default
            null,                     // 13 killSwitch    — the policy's concern; core default
            null,                     // 14 probeSignature— the policy's concern; core default
            $seedSalt,                // 15 seedSalt
            $s->catalogDisabled(),    // 16 exclude
            $s->nucleiReflection()    // 17 nucleiReflection (highest position D sets)
        );
    }

    private static function resolveAuthSalt($resolver)
    {
        if (is_callable($resolver)) {
            return (string) call_user_func($resolver);
        }
        if (defined('AUTH_SALT')) {
            return (string) constant('AUTH_SALT');
        }

        return '';
    }
}
