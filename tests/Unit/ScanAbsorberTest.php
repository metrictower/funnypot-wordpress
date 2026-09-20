<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\WordPress\Log\ScanAbsorbingHitLogWriter;
use Funnypot\WordPress\Tests\Fakes\InMemoryBackend;
use Funnypot\WordPress\Tests\Fakes\MutableClock;
use Funnypot\WordPress\Tests\Fakes\SpyHitLogWriter;
use Funnypot\WordPress\WpStateStore;

final class ScanAbsorberTest extends TestCase
{
    /** @var MutableClock */
    private $clock;
    /** @var InMemoryBackend */
    private $backend;
    /** @var WpStateStore */
    private $store;
    /** @var SpyHitLogWriter */
    private $inner;

    protected function setUp(): void
    {
        parent::setUp();
        $this->clock = new MutableClock(1000000);
        $this->backend = new InMemoryBackend($this->clock->asCallable());
        $this->store = new WpStateStore($this->backend, $this->clock);
        $this->inner = new SpyHitLogWriter();
    }

    private function absorber($autoBan = false, $threshold = 5): ScanAbsorbingHitLogWriter
    {
        return new ScanAbsorbingHitLogWriter($this->inner, $this->store, 60, $threshold, $autoBan, 3600);
    }

    private function probeRow(string $slug, string $ip = '203.0.113.9'): array
    {
        return array(
            'ts' => $this->clock->now(),
            'ip' => $ip,
            'method' => 'GET',
            'path' => '/wp-content/plugins/' . $slug . '/readme.txt',
            'action' => 'deceive',
            'reason' => 'sacrificial-path',
            'status' => 200,
            'ua' => 'WPScan v3.8.25',
        );
    }

    public function testBurstCollapsesToOneRollupRow(): void
    {
        $absorber = $this->absorber();
        for ($i = 0; $i < 500; $i++) {
            $absorber->record($this->probeRow('plugin-' . $i));
        }

        // Exactly ONE local row for a 500-request sweep.
        $this->assertCount(1, $this->inner->rows);
        $this->assertSame('mass_plugin_scan', $this->inner->rows[0]['reason']);
        $this->assertSame('/wp-content/plugins/*', $this->inner->rows[0]['path']);
        $this->assertSame('deceive', $this->inner->rows[0]['action']);

        // The aggregate carries the full count, a capped/de-duped slug sample, and the UA.
        $agg = $this->backend->get('enumscan_agg:203.0.113.9');
        $this->assertSame(500, $agg['count']);
        $this->assertLessThanOrEqual(20, count($agg['slugs_sample']));
        $this->assertSame(20, count($agg['slugs_sample']));
        $this->assertSame('WPScan v3.8.25', $agg['ua']);
    }

    public function testNonEnumRowPassesThrough(): void
    {
        $absorber = $this->absorber();
        $row = array('ts' => $this->clock->now(), 'ip' => '203.0.113.9', 'method' => 'GET', 'path' => '/.env', 'action' => 'deceive', 'reason' => 'sacrificial-path', 'status' => 200);
        $absorber->record($row);

        $this->assertCount(1, $this->inner->rows);
        $this->assertSame('/.env', $this->inner->rows[0]['path']);
        $this->assertSame('sacrificial-path', $this->inner->rows[0]['reason']);
    }

    public function testAllowRowIsNotAbsorbedEvenIfEnumShaped(): void
    {
        // An installed asset would be ALLOW and never reach the log; guard the action filter anyway.
        $absorber = $this->absorber();
        $row = $this->probeRow('akismet');
        $row['action'] = 'allow';
        $absorber->record($row);

        $this->assertCount(1, $this->inner->rows);
        $this->assertSame('/wp-content/plugins/akismet/readme.txt', $this->inner->rows[0]['path']);
    }

    public function testSecondIpGetsItsOwnWindow(): void
    {
        $absorber = $this->absorber();
        $absorber->record($this->probeRow('a', '203.0.113.9'));
        $absorber->record($this->probeRow('b', '203.0.113.9'));
        $absorber->record($this->probeRow('a', '198.51.100.7'));

        // One rollup row per IP.
        $this->assertCount(2, $this->inner->rows);
        $this->assertSame(2, $this->backend->get('enumscan_agg:203.0.113.9')['count']);
        $this->assertSame(1, $this->backend->get('enumscan_agg:198.51.100.7')['count']);
    }

    public function testWindowExpiryStartsANewRollup(): void
    {
        $absorber = $this->absorber();
        $absorber->record($this->probeRow('a'));
        $absorber->record($this->probeRow('b'));
        $this->assertCount(1, $this->inner->rows);

        // Past the 60s window the counter TTL lapses -> a fresh window emits a new rollup row.
        $this->clock->advance(61);
        $absorber->record($this->probeRow('c'));
        $this->assertCount(2, $this->inner->rows);
    }

    public function testAutoBanOffByDefaultDoesNotBlock(): void
    {
        $absorber = $this->absorber(false, 5);
        for ($i = 0; $i < 20; $i++) {
            $absorber->record($this->probeRow('p-' . $i));
        }
        $this->assertFalse($this->store->isBlocked('203.0.113.9'));
    }

    public function testAutoBanBlocksAfterThresholdWhenEnabled(): void
    {
        $absorber = $this->absorber(true, 5);
        for ($i = 0; $i < 6; $i++) {
            $absorber->record($this->probeRow('p-' . $i));
        }
        // n>5 within the window -> blocked.
        $this->assertTrue($this->store->isBlocked('203.0.113.9'));
    }
}
