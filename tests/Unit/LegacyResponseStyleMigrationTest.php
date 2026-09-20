<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\WordPress\EvaluatorConfig;
use Funnypot\WordPress\Settings;

/**
 * FP-0484 — legacy response_style -> response_mode migration. An install upgraded without a saved
 * response_mode must derive one from its legacy response_style so a configured taunt persona is not
 * silently reverted to realistic. An explicit response_mode always wins.
 */
final class LegacyResponseStyleMigrationTest extends TestCase
{
    private function settings(array $raw)
    {
        return Settings::fromArray($raw, static function () {
            return null;
        });
    }

    public function testLegacyTauntDerivesTauntMode(): void
    {
        $s = $this->settings(array('enabled' => true, 'response_style' => 'taunt'));
        $this->assertSame('taunt', $s->responseMode());
        $this->assertSame('taunt', EvaluatorConfig::fromSettings($s, static function () {
            return '';
        })->responseStyle);
    }

    public function testLegacyRealisticAndMinimalDeriveRealisticMode(): void
    {
        $this->assertSame('realistic', $this->settings(array('response_style' => 'realistic'))->responseMode());
        $this->assertSame('realistic', $this->settings(array('response_style' => 'minimal'))->responseMode());
    }

    public function testNeitherKeyDefaultsRealistic(): void
    {
        $this->assertSame('realistic', $this->settings(array('enabled' => true))->responseMode());
    }

    public function testExplicitModeWinsOverConflictingLegacyStyle(): void
    {
        $s = $this->settings(array('response_mode' => 'stealth', 'response_style' => 'taunt'));
        $this->assertSame('stealth', $s->responseMode());
    }
}
