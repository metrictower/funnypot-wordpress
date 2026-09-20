<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\WordPress\EvaluatorConfig;
use Funnypot\WordPress\Settings;

/**
 * FP-0484 — response_mode -> policy action bands + core responseStyle mapping.
 *
 * The action fixture uses the REAL default bands (scanner_probe=deceive, attack_class=block) so the
 * test exercises exactly what default config produces: stealth must clamp EVERY non-allow band to log
 * (the block-clamp is the whole point — a deceive-only clamp would leave the default attack_class=block
 * band emitting a 403 fingerprint tell), while realistic/taunt pass the operator's bands through.
 */
final class ResponseModeMappingTest extends TestCase
{
    private function settings($mode)
    {
        return Settings::fromArray(array(
            'enabled' => true,
            'response_mode' => $mode,
            'actions' => array(
                'scanner_probe' => 'deceive',
                'attack_class' => 'block',
                'suspicious' => 'log',
                'clean' => 'allow',
            ),
        ), static function () {
            return null;
        });
    }

    public function testStealthClampsEveryNonAllowBandToLog(): void
    {
        $actions = $this->settings('stealth')->toPolicyConfig('fallback')['actions'];

        // The block-clamp: the assertion that fails on a deceive-only implementation.
        $this->assertSame('log', $actions['attack_class']);
        $this->assertSame('log', $actions['scanner_probe']);
        $this->assertSame('log', $actions['suspicious']);
        // allow is left intact so clean traffic proceeds untouched.
        $this->assertSame('allow', $actions['clean']);
    }

    public function testRealisticPassesBandsThrough(): void
    {
        $actions = $this->settings('realistic')->toPolicyConfig('fallback')['actions'];
        $this->assertSame('deceive', $actions['scanner_probe']);
        $this->assertSame('block', $actions['attack_class']);
        $this->assertSame('log', $actions['suspicious']);
        $this->assertSame('allow', $actions['clean']);
    }

    public function testTauntPassesBandsThrough(): void
    {
        $actions = $this->settings('taunt')->toPolicyConfig('fallback')['actions'];
        $this->assertSame('deceive', $actions['scanner_probe']);
        $this->assertSame('block', $actions['attack_class']);
    }

    public function testBlockedClampsEveryNonAllowBandToBlock(): void
    {
        $actions = $this->settings('blocked')->toPolicyConfig('fallback')['actions'];

        // The inverse of stealth: deceive/log/block all clamp UP to block (the assertions that fail on a
        // partial implementation are the deceive->block and log->block up-clamps).
        $this->assertSame('block', $actions['scanner_probe']);
        $this->assertSame('block', $actions['suspicious']);
        $this->assertSame('block', $actions['attack_class']);
        // allow is left intact so clean traffic proceeds untouched (no lockout).
        $this->assertSame('allow', $actions['clean']);
    }

    public function testBlockedServesNoDecoy(): void
    {
        $s = Settings::fromArray(array(
            'enabled' => true,
            'response_mode' => 'blocked',
            'decoy_xmlrpc' => true,
            'decoy_wp_login' => true,
        ), static function () {
            return null;
        });

        $this->assertFalse($s->responseModeServesDecoys());
        $map = $s->decoyMap();
        $this->assertFalse($map['xmlrpc']);
        $this->assertFalse($map['wp_login']);
    }

    public function testModeSelectsCoreResponseStyle(): void
    {
        $salt = static function () {
            return '';
        };
        $this->assertSame('minimal', EvaluatorConfig::fromSettings($this->settings('stealth'), $salt)->responseStyle);
        $this->assertSame('realistic', EvaluatorConfig::fromSettings($this->settings('realistic'), $salt)->responseStyle);
        $this->assertSame('taunt', EvaluatorConfig::fromSettings($this->settings('taunt'), $salt)->responseStyle);
        // blocked bypasses core synthesis; the style is moot but must be a valid enum value.
        $this->assertSame('minimal', EvaluatorConfig::fromSettings($this->settings('blocked'), $salt)->responseStyle);
    }
}
