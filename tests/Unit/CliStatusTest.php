<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\WordPress\Cli\HoneypotCommand;
use Funnypot\WordPress\Settings;

final class CliStatusTest extends TestCase
{
    private function settings(array $raw)
    {
        return Settings::fromArray($raw, static function () {
            return null;
        });
    }

    public function testStatusReportsVerifiedMountNotConfiguredIntent(): void
    {
        $s = $this->settings(array('enabled' => true, 'posture' => 'WAF'));
        // Configured BEFORE, but the verified mount is degraded — status must show the VERIFIED value.
        $summary = HoneypotCommand::statusSummary($s, 'plugins_loaded (degraded)', 7, null, 1000000);

        $this->assertStringContainsString('enabled:', $summary);
        $this->assertStringContainsString('posture:               WAF', $summary);
        $this->assertStringContainsString('verified BEFORE mount: plugins_loaded (degraded)', $summary);
        $this->assertStringContainsString('report queue depth:    7', $summary);
        $this->assertStringContainsString('local mirror:          off (age: never)', $summary);
    }

    public function testMirrorAgeFormatting(): void
    {
        $now = 1000000;
        $this->assertSame('never', HoneypotCommand::age(null, $now));
        $this->assertSame('30s ago', HoneypotCommand::age($now - 30, $now));
        $this->assertSame('5m ago', HoneypotCommand::age($now - 300, $now));
        $this->assertSame('2h ago', HoneypotCommand::age($now - 7200, $now));
        $this->assertSame('3d ago', HoneypotCommand::age($now - 259200, $now));
    }

    public function testReputationAndReportingReflectActiveState(): void
    {
        $s = $this->settings(array(
            'enabled' => true,
            'mainnet_key' => 'k',
            'report_enabled' => true,
            'reputation' => array('check_enabled' => true),
            'mirror_enabled' => true,
        ));
        $summary = HoneypotCommand::statusSummary($s, 'mu-plugin', 0, 999000, 1000000);
        $this->assertStringContainsString('reputation check:      on', $summary);
        $this->assertStringContainsString('reporting:             on', $summary);
        $this->assertStringContainsString('local mirror:          on', $summary);
    }
}
