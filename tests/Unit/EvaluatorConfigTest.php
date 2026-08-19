<?php

declare(strict_types=1);

namespace Honeypot\WP\Tests\Unit;

use Funnypot\Config as CoreConfig;
use Honeypot\WP\EvaluatorConfig;
use Honeypot\WP\Settings;

/**
 * Phase 4 — the STYLE/engine Settings -> core Config mapping, tested against the REAL core Config.
 * Every set field must read back; a wrong value would surface a misassigned pathScope/personaBreadth
 * (the M15 positional guard).
 */
final class EvaluatorConfigTest extends TestCase
{
    private function settings(array $raw = array())
    {
        return Settings::fromArray($raw, static function () {
            return null;
        });
    }

    public function testEverySetFieldReadsBack(): void
    {
        $s = $this->settings(array(
            'response_style' => 'taunt',
            'severity_ceiling' => 'critical',
            'attack_emulation' => true,
            'nuclei_reflection' => false,
            'catalog_disabled' => array('cve-2021-1', 'tag:wordpress'),
            'seed_salt' => 'my-salt',
            'latency_ms' => 40,
            'latency_jitter_ms' => 15,
        ));

        $cfg = EvaluatorConfig::fromSettings($s);
        $this->assertInstanceOf(CoreConfig::class, $cfg);

        $this->assertSame('taunt', $cfg->responseStyle);
        $this->assertSame('critical', $cfg->severityCeiling);
        $this->assertTrue($cfg->attackEmulation);
        $this->assertFalse($cfg->nucleiReflection);
        $this->assertSame(array('cve-2021-1', 'tag:wordpress'), $cfg->exclude);
        $this->assertSame('my-salt', $cfg->seedSalt);
        $this->assertSame(40, $cfg->latencyMs);
        $this->assertSame(15, $cfg->latencyJitterMs);
    }

    public function testPositionalGuardMiddleParamsAreCoreDefaults(): void
    {
        // If a middle positional arg had been skipped, these would carry a shifted value.
        $cfg = EvaluatorConfig::fromSettings($this->settings());
        $this->assertSame('matched-only', $cfg->pathScope);
        $this->assertSame('coherent', $cfg->personaBreadth);
        $this->assertSame('detect', $cfg->mode);
    }

    public function testNoRespondModeClosuresAuthored(): void
    {
        $cfg = EvaluatorConfig::fromSettings($this->settings());
        // WHEN/WHETHER is the policy's — D must author none of these closures.
        $this->assertNull($cfg->gate);
        $this->assertNull($cfg->probeSignature);
        $this->assertNull($cfg->killSwitch);
        $this->assertNull($cfg->trustedBypass);
        $this->assertNull($cfg->personaSeed);
    }

    public function testSeedSaltFallsBackToAuthSaltWhenUnset(): void
    {
        $cfg = EvaluatorConfig::fromSettings($this->settings(), static function () {
            return 'AUTH-SALT-VALUE';
        });
        $this->assertSame('AUTH-SALT-VALUE', $cfg->seedSalt);
    }

    public function testExplicitSeedSaltBeatsAuthSalt(): void
    {
        $cfg = EvaluatorConfig::fromSettings($this->settings(array('seed_salt' => 'explicit')), static function () {
            return 'AUTH-SALT-VALUE';
        });
        $this->assertSame('explicit', $cfg->seedSalt);
    }
}
