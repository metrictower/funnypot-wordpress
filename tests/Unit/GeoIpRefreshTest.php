<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\WordPress\Geo\GeoIpRefresh;
use Funnypot\WordPress\Settings;
use Funnypot\WordPress\Tests\Fakes\InMemoryBackend;
use Funnypot\WordPress\Tests\Fakes\MutableClock;
use Funnypot\WordPress\Tests\Fakes\RecordingTransport;

final class GeoIpRefreshTest extends TestCase
{
    private function settings(string $countryPosture = 'deny_list')
    {
        return Settings::fromArray(array('country_posture' => $countryPosture), static function () {
            return null;
        });
    }

    public function test200WritesDbAndStoresEtag(): void
    {
        $clock = new MutableClock();
        $written = null;
        $backend = new InMemoryBackend($clock->asCallable());
        $transport = new RecordingTransport(array(
            array('status' => 200, 'body' => 'MMDB-BYTES', 'headers' => array('etag' => '"v1"', 'last-modified' => 'Wed')),
        ));
        $refresh = new GeoIpRefresh($this->settings(), $transport, static function ($bytes) use (&$written) {
            $written = $bytes;
            return true;
        }, $backend, 'https://cdn.example/dbip.mmdb', $clock->asCallable());

        $res = $refresh->refresh();
        $this->assertTrue($res['refreshed']);
        $this->assertSame('MMDB-BYTES', $written);
        $meta = $backend->get(GeoIpRefresh::META_KEY);
        $this->assertSame('v1', $meta['etag']);
    }

    public function test304WritesNothing(): void
    {
        $clock = new MutableClock();
        $written = false;
        $backend = new InMemoryBackend($clock->asCallable());
        $backend->set(GeoIpRefresh::META_KEY, array('etag' => 'v1', 'last_modified' => 'Wed'), 0);
        $transport = new RecordingTransport(array(
            array('status' => 304, 'body' => '', 'headers' => array()),
        ));
        $refresh = new GeoIpRefresh($this->settings(), $transport, static function () use (&$written) {
            $written = true;
            return true;
        }, $backend, 'https://cdn.example/dbip.mmdb', $clock->asCallable());

        $res = $refresh->refresh();
        $this->assertTrue($res['refreshed']);
        $this->assertSame('not-modified', $res['reason']);
        $this->assertFalse($written, '304 writes nothing');
        // stored etag/last-modified sent on this pull
        $this->assertContains('If-None-Match: v1', $transport->gets[0]['headers']);
        $this->assertContains('If-Modified-Since: Wed', $transport->gets[0]['headers']);
    }

    public function testInertWhenCountryOff(): void
    {
        $clock = new MutableClock();
        $transport = new RecordingTransport();
        $refresh = new GeoIpRefresh($this->settings('off'), $transport, static function () {
            return true;
        }, new InMemoryBackend($clock->asCallable()), 'https://cdn.example/dbip.mmdb', $clock->asCallable());

        $this->assertFalse($refresh->refresh()['refreshed']);
        $this->assertCount(0, $transport->gets);
    }

    public function testFailedPullLeavesExistingDbAndDoesNotThrow(): void
    {
        $clock = new MutableClock();
        $written = false;
        $transport = new RecordingTransport(array(
            array('status' => 500, 'body' => '', 'headers' => array()),
        ));
        $refresh = new GeoIpRefresh($this->settings(), $transport, static function () use (&$written) {
            $written = true;
            return true;
        }, new InMemoryBackend($clock->asCallable()), 'https://cdn.example/dbip.mmdb', $clock->asCallable());

        $res = $refresh->refresh();
        $this->assertFalse($res['refreshed']);
        $this->assertFalse($written, 'a failed pull never overwrites the existing DB (fail-open)');
    }
}
