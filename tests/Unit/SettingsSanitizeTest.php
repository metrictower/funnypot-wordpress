<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\WordPress\Admin\SettingsSanitizer;

final class SettingsSanitizeTest extends TestCase
{
    public function testJunkNormalizedToSettingsShape(): void
    {
        $out = SettingsSanitizer::sanitize(array(
            'posture' => 'nonsense',
            'mainnet_base_url' => 'https://host.example/v1/report',
            'reputation' => array(
                'fail_mode' => 'weird',
                'block_verdicts' => array('malicious', 'garbage'),
                'min_block_score' => '250',
            ),
            'local_state_backend' => 'zzz',
            'country_posture' => 'bogus',
            'country_action' => 'nuke',
            'country_list' => array('us', 'xx1'),
            'evil' => 'dropme',
        ));

        $this->assertSame('honeypot', $out['posture']);
        $this->assertSame('https://host.example', $out['mainnet_base_url']); // path stripped
        $this->assertSame('open', $out['fail_mode']);
        $this->assertSame(array('malicious'), $out['block_verdicts']);
        $this->assertSame(100, $out['min_block_score']); // clamped to 0..100
        $this->assertSame('object-cache', $out['local_state_backend']);
        $this->assertSame('off', $out['country_posture']);
        $this->assertSame('score-modifier', $out['country_action']);
        $this->assertSame(array('US'), $out['country_list']);
        $this->assertArrayNotHasKey('evil', $out);
    }

    public function testNonArrayInputYieldsInertDefaults(): void
    {
        $out = SettingsSanitizer::sanitize('not-an-array');
        $this->assertFalse($out['enabled']);
        $this->assertSame('honeypot', $out['posture']);
    }

    public function testBadLoginSlugRoundTripsOffThroughAdminPath(): void
    {
        // A bad slug submitted through the admin sanitizer normalizes to '' (relocation stays off),
        // proving the admin path uses the same normalizer as the runtime (FP-0490).
        $out = SettingsSanitizer::sanitize(array(
            'enabled' => true,
            'login_relocation_enabled' => true,
            'login_slug' => 'wp-admin',
        ));
        $this->assertSame('', $out['login_slug']);
    }

    public function testGoodLoginSlugIsSanitizedAndKept(): void
    {
        $out = SettingsSanitizer::sanitize(array(
            'enabled' => true,
            'login_relocation_enabled' => true,
            'login_slug' => '  My Secret Login ',
        ));
        $this->assertSame('my-secret-login', $out['login_slug']);
    }
}
