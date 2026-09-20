<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\WordPress\Admin\SettingsSanitizer;
use Funnypot\WordPress\EvaluatorConfig;
use Funnypot\WordPress\Settings;

/**
 * FP-0484 — response_mode / decoy field normalization, sanitizer rejection of bad input, and the
 * invariant that the default (no saved mode) reproduces today's byte-for-byte served behaviour.
 */
final class SettingsResponseModeTest extends TestCase
{
    private function settings(array $raw)
    {
        return Settings::fromArray($raw, static function () {
            return null;
        });
    }

    public function testUnknownModeWhitelistsToRealistic(): void
    {
        $this->assertSame('realistic', $this->settings(array('response_mode' => 'evil'))->responseMode());
    }

    public function testAbsentModeDefaultsRealistic(): void
    {
        $this->assertSame('realistic', $this->settings(array())->responseMode());
    }

    public function testDecoyDefaults(): void
    {
        $s = $this->settings(array());
        $this->assertFalse($s->decoyXmlrpc());
        $this->assertFalse($s->decoyWpLogin());
        $this->assertSame('', $s->decoySessionKey());
    }

    public function testSanitizerRejectsNonArrayInput(): void
    {
        $out = SettingsSanitizer::sanitize('not-an-array');
        $this->assertIsArray($out);
        $this->assertSame('realistic', $out['response_mode']);
        $this->assertFalse($out['decoy_xmlrpc']);
    }

    public function testSanitizerRoundTripIsIdempotent(): void
    {
        $raw = array(
            'enabled' => true,
            'response_mode' => 'taunt',
            'decoy_xmlrpc' => true,
            'decoy_wp_login' => true,
            'decoy_session_key' => 'k',
        );
        $once = SettingsSanitizer::sanitize($raw);
        $twice = SettingsSanitizer::sanitize($once);
        $this->assertSame($once, $twice);
    }

    public function testDefaultInstallReproducesTodaysBehaviour(): void
    {
        // No response_mode / response_style saved: bands pass through unchanged and core style is
        // realistic — byte-identical to the pre-FP-0484 default.
        $s = $this->settings(array('enabled' => true));
        $actions = $s->toPolicyConfig('fallback')['actions'];
        $this->assertSame('deceive', $actions['scanner_probe']);
        $this->assertSame('block', $actions['attack_class']);
        $this->assertSame('log', $actions['suspicious']);
        $this->assertSame('allow', $actions['clean']);
        $this->assertSame('realistic', EvaluatorConfig::fromSettings($s, static function () {
            return '';
        })->responseStyle);
    }
}
