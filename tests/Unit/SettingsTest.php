<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\WordPress\Settings;

final class SettingsTest extends TestCase
{
    /** A resolver that returns nothing (no wp-config constants set). */
    private function noConsts()
    {
        return static function ($name) {
            return null;
        };
    }

    public function testDefaultInstallIsInert(): void
    {
        $s = Settings::fromArray(array(), $this->noConsts());

        $this->assertFalse($s->enabled());
        $this->assertSame('honeypot', $s->posture());
        $this->assertFalse($s->reportingActive());
        $this->assertFalse($s->checkActive());
        $this->assertFalse($s->mirrorEnabled());
        $this->assertSame('object-cache', $s->localStateBackend());
    }

    public function testUnknownKeysDropped(): void
    {
        $s = Settings::fromArray(array('bogus_key' => 'x', 'enabled' => true), $this->noConsts());
        $this->assertArrayNotHasKey('bogus_key', $s->toArray());
        $this->assertTrue($s->enabled());
    }

    public function testMainnetBaseUrlDefaultsToPlaceholderNeverAbuseIpdb(): void
    {
        $s = Settings::fromArray(array(), $this->noConsts());
        $url = $s->mainnetBaseUrl();
        $this->assertStringContainsString('funnypot', $url);
        $this->assertStringNotContainsString('abuseipdb', strtolower($url));
        $this->assertStringNotContainsString('/v1/', $url); // base-URL-only, no path
    }

    public function testBaseUrlStripsAnyPath(): void
    {
        $s = Settings::fromArray(array('mainnet_base_url' => 'https://host.example/v1/report?x=1'), $this->noConsts());
        $this->assertSame('https://host.example', $s->mainnetBaseUrl());
    }

    public function testEnvConstantPrecedence(): void
    {
        $resolver = static function ($name) {
            if ($name === Settings::CONST_BASE_URL) {
                return 'https://env.example';
            }
            if ($name === Settings::CONST_KEY) {
                return 'ENVKEY';
            }
            return null;
        };
        $s = Settings::fromArray(array('mainnet_base_url' => 'https://stored.example', 'mainnet_key' => 'stored'), $resolver);
        $this->assertSame('https://env.example', $s->mainnetBaseUrl());
        $this->assertSame('ENVKEY', $s->mainnetKey());
    }

    public function testReportingAndCheckInertWithoutKeyEvenWhenEnabled(): void
    {
        $s = Settings::fromArray(array(
            'report_enabled' => true,
            'reputation' => array('check_enabled' => true),
            'mainnet_key' => '',
        ), $this->noConsts());

        $this->assertTrue($s->reportEnabled());
        $this->assertTrue($s->checkEnabled());
        $this->assertFalse($s->reportingActive());
        $this->assertFalse($s->checkActive());
    }

    public function testReportingAndCheckActiveWithKey(): void
    {
        $s = Settings::fromArray(array(
            'report_enabled' => true,
            'reputation' => array('check_enabled' => true),
            'mainnet_key' => 'abc',
        ), $this->noConsts());

        $this->assertTrue($s->reportingActive());
        $this->assertTrue($s->checkActive());
    }

    public function testBlockVerdictsDefaultAndJunkCoercedOut(): void
    {
        $s = Settings::fromArray(array(), $this->noConsts());
        $this->assertSame(array('malicious', 'critical'), $s->blockVerdicts());

        $s2 = Settings::fromArray(array('reputation' => array('block_verdicts' => array('malicious', 'garbage', 'suspicious'))), $this->noConsts());
        $this->assertSame(array('malicious', 'suspicious'), $s2->blockVerdicts());
    }

    public function testMinBlockScoreIntOrNull(): void
    {
        $this->assertNull(Settings::fromArray(array(), $this->noConsts())->minBlockScore());
        $this->assertSame(80, Settings::fromArray(array('reputation' => array('min_block_score' => '80')), $this->noConsts())->minBlockScore());
        $this->assertNull(Settings::fromArray(array('reputation' => array('min_block_score' => '')), $this->noConsts())->minBlockScore());
    }

    public function testCacheTtlAndFailModeDefaultsAndWhitelist(): void
    {
        $s = Settings::fromArray(array(), $this->noConsts());
        $this->assertSame(24, $s->cacheTtlHours());
        $this->assertSame('open', $s->failMode());

        $s2 = Settings::fromArray(array('reputation' => array('fail_mode' => 'weird')), $this->noConsts());
        $this->assertSame('open', $s2->failMode());
        $s3 = Settings::fromArray(array('reputation' => array('fail_mode' => 'closed')), $this->noConsts());
        $this->assertSame('closed', $s3->failMode());
    }

    public function testLocalStateBackendWhitelist(): void
    {
        $this->assertSame('object-cache', Settings::fromArray(array('local_state_backend' => 'nope'), $this->noConsts())->localStateBackend());
        $this->assertSame('file', Settings::fromArray(array('local_state_backend' => 'file'), $this->noConsts())->localStateBackend());
    }

    public function testDrainKnobDefaultsAndClamps(): void
    {
        $s = Settings::fromArray(array(), $this->noConsts());
        $this->assertSame(10, $s->drainBudgetSecs());
        $this->assertSame(3, $s->drainMaxAttempts());
        $this->assertSame(10000, $s->queueCap());
        // clamp out of range
        $this->assertSame(60, Settings::fromArray(array('drain_budget_secs' => 9999), $this->noConsts())->drainBudgetSecs());
        $this->assertSame(100, Settings::fromArray(array('queue_cap' => 1), $this->noConsts())->queueCap());
    }

    public function testEnumAbsorberKnobDefaultsAndClamps(): void
    {
        $s = Settings::fromArray(array(), $this->noConsts());
        $this->assertTrue($s->pluginEnumAbsorber()); // on by default
        $this->assertSame(60, $s->enumWindowSecs());
        $this->assertSame(5, $s->enumEscalateThreshold());
        $this->assertFalse($s->enumAutoBan()); // opt-in
        $this->assertSame(3600, $s->enumBanTtlSecs());

        $off = Settings::fromArray(array('plugin_enum_absorber' => false), $this->noConsts());
        $this->assertFalse($off->pluginEnumAbsorber());

        // Clamp out of range.
        $this->assertSame(3600, Settings::fromArray(array('enum_window_secs' => 999999), $this->noConsts())->enumWindowSecs());
        $this->assertSame(5, Settings::fromArray(array('enum_window_secs' => 1), $this->noConsts())->enumWindowSecs());
        $this->assertSame(1000, Settings::fromArray(array('enum_escalate_threshold' => 999999), $this->noConsts())->enumEscalateThreshold());
        $this->assertSame(86400, Settings::fromArray(array('enum_ban_ttl_secs' => 999999), $this->noConsts())->enumBanTtlSecs());
    }

    public function testCountryKnobDefaultsAndEnums(): void
    {
        $s = Settings::fromArray(array(), $this->noConsts());
        $this->assertSame('off', $s->countryPosture());
        $this->assertSame('score-modifier', $s->countryAction());
        $this->assertSame(array(), $s->countryList());

        $s2 = Settings::fromArray(array(
            'country_posture' => 'deny_list',
            'country_action' => 'block',
            'country_list' => array('us', 'GB', 'zzz', '1'),
        ), $this->noConsts());
        $this->assertSame('deny_list', $s2->countryPosture());
        $this->assertSame('block', $s2->countryAction());
        $this->assertSame(array('US', 'GB'), $s2->countryList());
    }

    public function testPositionActiveDerivesFromPosture(): void
    {
        $honeypot = Settings::fromArray(array('posture' => 'honeypot'), $this->noConsts());
        $this->assertTrue($honeypot->positionActive('fallback'));
        $this->assertFalse($honeypot->positionActive('before'));

        $waf = Settings::fromArray(array('posture' => 'WAF'), $this->noConsts());
        $this->assertTrue($waf->positionActive('before'));
        $this->assertFalse($waf->positionActive('fallback'));

        $both = Settings::fromArray(array('posture' => 'both'), $this->noConsts());
        $this->assertTrue($both->positionActive('before'));
        $this->assertTrue($both->positionActive('fallback'));
    }

    public function testToPolicyConfigDefaultIsInert(): void
    {
        $s = Settings::fromArray(array(), $this->noConsts());
        $cfg = $s->toPolicyConfig('fallback');

        $this->assertSame('honeypot', $cfg['posture']);
        $this->assertTrue($cfg['position']['fallback']);
        $this->assertFalse($cfg['position']['before']);
        $this->assertFalse($cfg['reputation']['enabled']);
        $this->assertSame(array('malicious', 'critical'), $cfg['reputation']['block_verdicts']);
        $this->assertNull($cfg['reputation']['min_block_score']);
        $this->assertFalse($cfg['country']['enabled']);
        // No score-only block_threshold key exists (verdict-first).
        $this->assertArrayNotHasKey('block_threshold', $cfg['reputation']);
    }

    public function testToPolicyConfigForcesGivenPosition(): void
    {
        $s = Settings::fromArray(array('posture' => 'both'), $this->noConsts());

        $before = $s->toPolicyConfig('before');
        $this->assertTrue($before['position']['before']);
        $this->assertFalse($before['position']['fallback']);

        $fallback = $s->toPolicyConfig('fallback');
        $this->assertFalse($fallback['position']['before']);
        $this->assertTrue($fallback['position']['fallback']);
    }

    public function testToPolicyConfigCountryBlockRendersWhenOn(): void
    {
        $s = Settings::fromArray(array(
            'country_posture' => 'allow_list',
            'country_list' => array('us'),
            'country_action' => 'score-modifier',
        ), $this->noConsts());
        $cfg = $s->toPolicyConfig('fallback');
        $this->assertTrue($cfg['country']['enabled']);
        $this->assertSame('allow', $cfg['country']['mode']);
        $this->assertSame(array('US'), $cfg['country']['countries']);
        $this->assertSame('modifier', $cfg['country']['action']);
    }

    public function testToPolicyConfigConsumableByRealPolicyConfig(): void
    {
        // The rendered array must be accepted by the real PolicyConfig::fromArray without loss.
        $s = Settings::fromArray(array('posture' => 'WAF', 'mainnet_key' => 'k', 'reputation' => array('check_enabled' => true)), $this->noConsts());
        $cfg = \Funnypot\Policy\PolicyConfig::fromArray($s->toPolicyConfig('before'));
        $this->assertSame('WAF', $cfg->posture());
        $this->assertTrue($cfg->positionEnabled('before'));
        $this->assertFalse($cfg->positionEnabled('fallback'));
        $rep = $cfg->reputation();
        $this->assertTrue($rep['enabled']);
        $this->assertSame(array('malicious', 'critical'), $rep['block_verdicts']);
    }

    // --- deception-corpus auto-update (FP-0502) --------------------------------------------------

    public function testRulesAutoUpdateDefaultsOffWithSaneChannelAndInterval(): void
    {
        $s = Settings::fromArray(array(), $this->noConsts());
        $this->assertFalse($s->rulesAutoUpdateEnabled()); // OFF by default
        $this->assertSame('stable', $s->rulesChannel());
        $this->assertSame('daily', $s->rulesUpdateInterval());
    }

    public function testRulesChannelAndIntervalWhitelisted(): void
    {
        $s = Settings::fromArray(array('rules_channel' => 'nope', 'rules_update_interval' => 'weekly'), $this->noConsts());
        $this->assertSame('stable', $s->rulesChannel());
        $this->assertSame('daily', $s->rulesUpdateInterval());

        $s2 = Settings::fromArray(array('rules_channel' => 'beta', 'rules_update_interval' => 'hourly'), $this->noConsts());
        $this->assertSame('beta', $s2->rulesChannel());
        $this->assertSame('hourly', $s2->rulesUpdateInterval());
    }

    public function testRulesAutoUpdateEnabledRoundTrips(): void
    {
        $s = Settings::fromArray(array('rules_autoupdate_enabled' => true), $this->noConsts());
        $this->assertTrue($s->rulesAutoUpdateEnabled());
        $this->assertTrue($s->toArray()['rules_autoupdate_enabled']);
    }

    public function testRulesAutoUpdateEnvConstantOverridesStoredToggle(): void
    {
        $resolver = static function ($name) {
            return $name === Settings::CONST_RULES_AUTOUPDATE ? '1' : null;
        };
        $s = Settings::fromArray(array('rules_autoupdate_enabled' => false), $resolver);
        $this->assertTrue($s->rulesAutoUpdateEnabled(), 'a wp-config constant forces the toggle on');
    }

    // --- login relocation (FP-0490) --------------------------------------------------------------

    public function testSanitizeSlugCleansMixedInput(): void
    {
        $this->assertSame('my-secret-login', Settings::sanitizeSlug('  My Secret Login '));
        $this->assertSame('a-b', Settings::sanitizeSlug('a__--!!b'));
        $this->assertSame('login2026', Settings::sanitizeSlug('Login2026'));
        $this->assertSame('', Settings::sanitizeSlug('!!!'));
        $this->assertSame('', Settings::sanitizeSlug('   '));
    }

    public function testIsValidLoginSlugRejectsUnsafeSlugs(): void
    {
        $this->assertFalse(Settings::isValidLoginSlug(''));
        $this->assertFalse(Settings::isValidLoginSlug('my-wp-login-x')); // contains wp-login
        $this->assertFalse(Settings::isValidLoginSlug('wp-admin'));
        $this->assertFalse(Settings::isValidLoginSlug('author'));        // WP query var
        $this->assertFalse(Settings::isValidLoginSlug('feed'));          // WP query var
        $this->assertFalse(Settings::isValidLoginSlug('wp-cron.php'));   // reserved surface
        $this->assertFalse(Settings::isValidLoginSlug('wp-json'));       // reserved prefix dir
        $this->assertTrue(Settings::isValidLoginSlug('secret-login'));
        $this->assertTrue(Settings::isValidLoginSlug('my-door'));
    }

    public function testInvalidSlugStoresEmptyAndDeactivatesRelocation(): void
    {
        $s = Settings::fromArray(array(
            'enabled' => true,
            'login_relocation_enabled' => true,
            'login_slug' => 'wp-admin',
        ), $this->noConsts());
        $this->assertSame('', $s->loginSlug());
        $this->assertFalse($s->loginRelocationActive());
    }

    public function testLoginRelocationActiveRequiresMasterSwitchAndValidSlug(): void
    {
        $base = array('enabled' => true, 'login_relocation_enabled' => true, 'login_slug' => 'secret-login');

        $this->assertTrue(Settings::fromArray($base, $this->noConsts())->loginRelocationActive());

        // master switch off -> inactive
        $offMaster = array_merge($base, array('enabled' => false));
        $this->assertFalse(Settings::fromArray($offMaster, $this->noConsts())->loginRelocationActive());

        // toggle off -> inactive
        $offToggle = array_merge($base, array('login_relocation_enabled' => false));
        $this->assertFalse(Settings::fromArray($offToggle, $this->noConsts())->loginRelocationActive());

        // empty slug -> inactive
        $noSlug = array_merge($base, array('login_slug' => ''));
        $this->assertFalse(Settings::fromArray($noSlug, $this->noConsts())->loginRelocationActive());
    }

    public function testActiveRelocationAllowlistsSlugVariantsAtRuntime(): void
    {
        $s = Settings::fromArray(array(
            'enabled' => true,
            'login_relocation_enabled' => true,
            'login_slug' => 'secret-login',
        ), $this->noConsts());

        // The engine reads toPolicyConfig()['allowlist']['safe_paths'] — assert the exact strings.
        $safe = $s->toPolicyConfig('before')['allowlist']['safe_paths'];
        $this->assertContains('/secret-login', $safe);
        $this->assertContains('/secret-login/', $safe);

        // Not persisted into the stored option (runtime-only injection).
        $this->assertNotContains('/secret-login', $s->toArray()['allowlist']['safe_paths']);
    }

    public function testInactiveRelocationDoesNotAllowlistSlug(): void
    {
        $s = Settings::fromArray(array(
            'enabled' => true,
            'login_relocation_enabled' => false,
            'login_slug' => 'secret-login',
        ), $this->noConsts());
        $safe = $s->toPolicyConfig('before')['allowlist']['safe_paths'];
        $this->assertNotContains('/secret-login', $safe);
        $this->assertNotContains('/secret-login/', $safe);
    }

    public function testActiveRelocationAutoArmsWpLoginDecoyExceptStealth(): void
    {
        $realistic = Settings::fromArray(array(
            'enabled' => true,
            'login_relocation_enabled' => true,
            'login_slug' => 'secret-login',
            'response_mode' => 'realistic',
            'decoy_wp_login' => false, // auto-armed by relocation
        ), $this->noConsts());
        $this->assertTrue($realistic->decoyMap()['wp_login']);

        $stealth = Settings::fromArray(array(
            'enabled' => true,
            'login_relocation_enabled' => true,
            'login_slug' => 'secret-login',
            'response_mode' => 'stealth',
            'decoy_wp_login' => false,
        ), $this->noConsts());
        $this->assertFalse($stealth->decoyMap()['wp_login']);
    }
}
