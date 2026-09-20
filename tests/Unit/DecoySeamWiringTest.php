<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\WordPress\EvaluatorConfig;
use Funnypot\WordPress\Settings;

/**
 * FP-0484 — the two dead seams wired through Settings: Interceptor::$decoys (via Settings::decoyMap())
 * and core Config::$decoySessionKey (via EvaluatorConfig positional param 22). Stealth forces every
 * decoy off and disarms the authed skin regardless of the individual toggles.
 */
final class DecoySeamWiringTest extends TestCase
{
    private function settings(array $raw)
    {
        return Settings::fromArray($raw, static function () {
            return null;
        });
    }

    public function testDecoyMapMirrorsTogglesInRealistic(): void
    {
        $map = $this->settings(array(
            'response_mode' => 'realistic',
            'decoy_xmlrpc' => true,
            'decoy_wp_login' => true,
        ))->decoyMap();
        $this->assertTrue($map['xmlrpc']);
        $this->assertTrue($map['wp_login']);
    }

    public function testStealthForcesEveryDecoyOff(): void
    {
        $map = $this->settings(array(
            'response_mode' => 'stealth',
            'decoy_xmlrpc' => true,
            'decoy_wp_login' => true,
        ))->decoyMap();
        $this->assertFalse($map['xmlrpc']);
        $this->assertFalse($map['wp_login']);
    }

    public function testDecoySessionKeyArmsOnlyWhenWpLoginAndServingAndKeySet(): void
    {
        $s = $this->settings(array(
            'response_mode' => 'realistic',
            'decoy_wp_login' => true,
            'decoy_session_key' => 'seekret',
        ));
        $this->assertSame('seekret', EvaluatorConfig::fromSettings($s, static function () {
            return '';
        })->decoySessionKey);
    }

    public function testDecoySessionKeyNullInStealth(): void
    {
        $s = $this->settings(array(
            'response_mode' => 'stealth',
            'decoy_wp_login' => true,
            'decoy_session_key' => 'seekret',
        ));
        $this->assertNull(EvaluatorConfig::fromSettings($s, static function () {
            return '';
        })->decoySessionKey);
    }

    public function testDecoySessionKeyNullWhenWpLoginOff(): void
    {
        $s = $this->settings(array(
            'response_mode' => 'realistic',
            'decoy_wp_login' => false,
            'decoy_session_key' => 'seekret',
        ));
        $this->assertNull(EvaluatorConfig::fromSettings($s, static function () {
            return '';
        })->decoySessionKey);
    }

    public function testActiveRelocationAutoArmsWpLoginDecoy(): void
    {
        // FP-0490 Derivation B2: relocation active auto-arms the wp-login decoy on the vacated default
        // even with decoy_wp_login off, so there is never a hidden login with no decoy behind it.
        $map = $this->settings(array(
            'enabled' => true,
            'login_relocation_enabled' => true,
            'login_slug' => 'secret-login',
            'response_mode' => 'realistic',
            'decoy_wp_login' => false,
        ))->decoyMap();
        $this->assertTrue($map['wp_login']);
    }

    public function testMultisiteSuppressesRelocationDecoyAutoArm(): void
    {
        // The no-lockout gate: on multisite the relocation hooks are not mounted, so Plugin passes
        // $relocationAutoArm=false and the decoy must NOT auto-arm on the real /wp-login.php — arming
        // the accept-any decoy there would shadow the un-relocated real login and lock the operator out.
        $s = $this->settings(array(
            'enabled' => true,
            'login_relocation_enabled' => true,
            'login_slug' => 'secret-login',
            'response_mode' => 'realistic',
            'decoy_wp_login' => false,
        ));
        $this->assertFalse($s->decoyMap(false)['wp_login']);
    }

    public function testMultisiteStillHonorsExplicitWpLoginDecoyToggle(): void
    {
        // Only the relocation-driven auto-arm is suppressed; an explicit decoy_wp_login=true still arms.
        $s = $this->settings(array(
            'enabled' => true,
            'login_relocation_enabled' => true,
            'login_slug' => 'secret-login',
            'response_mode' => 'realistic',
            'decoy_wp_login' => true,
        ));
        $this->assertTrue($s->decoyMap(false)['wp_login']);
    }
}
