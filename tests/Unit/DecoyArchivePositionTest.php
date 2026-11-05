<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\Core\Honeypot;
use Funnypot\WordPress\CoreEvaluator;
use Funnypot\WordPress\EvaluatorConfig;
use Funnypot\WordPress\RequestFactory;
use Funnypot\WordPress\Settings;
use Funnypot\WordPress\WpSiteProfile;

/**
 * Decoy archives are served only at the fallback position. At 'before' WordPress has not routed yet,
 * so a plugin route that serves a real archive under a backup-style name would otherwise be shadowed.
 */
final class DecoyArchivePositionTest extends TestCase
{
    private function settings()
    {
        return Settings::fromArray(array(
            'enabled' => true,
            'posture' => 'both',
            'decoy_archives' => true,
        ), static function () {
            return null;
        });
    }

    private function core(Settings $s)
    {
        @ini_set('memory_limit', '1024M');
        try {
            return Honeypot::default(EvaluatorConfig::fromSettings($s));
        } catch (\Throwable $e) {
            $this->markTestSkipped('bundled core rules artifact unavailable: ' . $e->getMessage());
        }
    }

    private function classify($core, Settings $s, $position, $path)
    {
        $server = array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => $path, 'REMOTE_ADDR' => '203.0.113.9');
        $evidence = RequestFactory::evidence($server, null, $s);
        $ctx = CoreEvaluator::contextFromEvidence($evidence);
        $profile = (new WpSiteProfile(false))->toPolicyProfile($path);
        $bridge = new CoreEvaluator($core, $ctx, $position);

        return array($bridge, $bridge->classify($evidence, $profile), $profile);
    }

    public function testBeforePositionLeavesBackupNamesUnclaimed(): void
    {
        $s = $this->settings();
        $core = $this->core($s);

        list(, $before) = $this->classify($core, $s, 'before', '/backup.zip');
        list(, $fallback) = $this->classify($core, $s, 'fallback', '/backup.zip');

        $this->assertSame('', $before->engineHandle(), 'before must not claim a decoy archive');
        $this->assertSame('clean', $before->classification());
        $this->assertNotSame('', $fallback->engineHandle(), 'fallback still claims the backup name');
    }

    public function testBeforePositionNeverRendersAnArchiveHandle(): void
    {
        $s = $this->settings();
        $core = $this->core($s);

        list(, $fallbackVerdict, $profile) = $this->classify($core, $s, 'fallback', '/backup.zip');
        list($beforeBridge) = $this->classify($core, $s, 'before', '/backup.zip');

        $fake = $beforeBridge->synthesize($fallbackVerdict, $profile, 'seed');
        $this->assertSame(404, $fake->status());
        $this->assertSame('', $fake->body());

        list($fallbackBridge) = $this->classify($core, $s, 'fallback', '/backup.zip');
        $served = $fallbackBridge->synthesize($fallbackVerdict, $profile, 'seed');
        $this->assertSame(200, $served->status());
        $this->assertStringStartsWith('PK', $served->body());
    }

    public function testOtherDecoysStillClaimedAtBefore(): void
    {
        $s = $this->settings();
        $core = $this->core($s);

        list(, $before) = $this->classify($core, $s, 'before', '/.env');
        $this->assertNotSame('', $before->engineHandle(), 'only decoy archives move to fallback');
    }
}
