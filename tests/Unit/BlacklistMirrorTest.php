<?php

declare(strict_types=1);

namespace Honeypot\WP\Tests\Unit;

use Funnypot\Mainnet\Cache\ArrayCache;
use Funnypot\Mainnet\CircuitBreaker;
use Honeypot\WP\Mirror\BlacklistMirror;
use Honeypot\WP\Settings;
use Honeypot\WP\Tests\Fakes\InMemoryBackend;
use Honeypot\WP\Tests\Fakes\MutableClock;
use Honeypot\WP\Tests\Fakes\RecordingTransport;
use Honeypot\WP\WpStateStore;

final class BlacklistMirrorTest extends TestCase
{
    private function activeSettings(array $extra = array())
    {
        return Settings::fromArray(array_merge(array(
            'mainnet_base_url' => 'https://mainnet.example',
            'mainnet_key' => 'KEY',
            'reputation' => array('check_enabled' => true),
            'mirror_enabled' => true,
        ), $extra), static function () {
            return null;
        });
    }

    private function store(MutableClock $clock)
    {
        return new WpStateStore(new InMemoryBackend($clock->asCallable()), $clock);
    }

    public function test200PopulatesMirror(): void
    {
        $clock = new MutableClock();
        $store = $this->store($clock);
        $body = json_encode(array(
            'meta' => array('generated_at' => 123),
            'data' => array(
                array('ip' => '203.0.113.5', 'verdict' => 'critical'),
                array('cidr' => '198.51.100.0/24', 'verdict' => 'malicious'),
            ),
        ));
        $transport = new RecordingTransport(array(
            array('status' => 200, 'body' => $body, 'headers' => array('etag' => '"abc"')),
        ));
        $mirror = new BlacklistMirror($this->activeSettings(), $store, $transport, null, $clock->asCallable());

        $res = $mirror->pull();
        $this->assertTrue($res['pulled']);
        $this->assertSame(2, $res['count']);

        $meta = $store->mirrorMeta();
        $this->assertSame('abc', $meta['etag']);
        $this->assertSame(2, $meta['count']);

        // rows resolvable (cidr row normalized to an 'ip' key -> containment match).
        $this->assertSame('critical', $store->mirrorVerdict('203.0.113.5')->verdict());
        $this->assertSame('malicious', $store->mirrorVerdict('198.51.100.99')->verdict());
    }

    public function test304RefreshesFreshnessOnly(): void
    {
        $clock = new MutableClock();
        $store = $this->store($clock);
        // seed a mirror
        $store->putMirror(array(array('ip' => '203.0.113.5', 'verdict' => 'critical')), 'seed', $clock->now(), 3600);

        $transport = new RecordingTransport(array(
            array('status' => 304, 'body' => '', 'headers' => array()),
        ));
        $mirror = new BlacklistMirror($this->activeSettings(), $store, $transport, null, $clock->asCallable());

        $res = $mirror->pull();
        $this->assertTrue($res['pulled']);
        $this->assertSame('not-modified', $res['reason']);
        // rows preserved
        $this->assertSame('critical', $store->mirrorVerdict('203.0.113.5')->verdict());
    }

    public function testStoredEtagSentOnNextPull(): void
    {
        $clock = new MutableClock();
        $store = $this->store($clock);
        $store->putMirror(array(), 'etag-xyz', $clock->now(), 3600);

        $transport = new RecordingTransport(array(
            array('status' => 304, 'body' => '', 'headers' => array()),
        ));
        $mirror = new BlacklistMirror($this->activeSettings(), $store, $transport, null, $clock->asCallable());
        $mirror->pull();

        $this->assertCount(1, $transport->gets);
        $this->assertContains('If-None-Match: etag-xyz', $transport->gets[0]['headers']);
    }

    public function testBreakerOpenSkipsPull(): void
    {
        $clock = new MutableClock();
        $store = $this->store($clock);
        $cache = new ArrayCache($clock->asCallable());
        $breaker = new CircuitBreaker($cache, 5, 60, 21600, $clock->asCallable());
        $breaker->tripTransport(); // OPEN

        $transport = new RecordingTransport();
        $mirror = new BlacklistMirror($this->activeSettings(), $store, $transport, $breaker, $clock->asCallable());

        $res = $mirror->pull();
        $this->assertFalse($res['pulled']);
        $this->assertSame('breaker-open', $res['reason']);
        $this->assertCount(0, $transport->gets, 'no network while the breaker is OPEN');
    }

    public function testInertWhenDisabled(): void
    {
        $clock = new MutableClock();
        $store = $this->store($clock);
        $transport = new RecordingTransport();

        // mirror_enabled false
        $mirror = new BlacklistMirror($this->activeSettings(array('mirror_enabled' => false)), $store, $transport, null, $clock->asCallable());
        $this->assertFalse($mirror->pull()['pulled']);

        // no key -> checkActive false
        $mirror2 = new BlacklistMirror($this->activeSettings(array('mainnet_key' => '')), $store, $transport, null, $clock->asCallable());
        $this->assertFalse($mirror2->pull()['pulled']);

        $this->assertCount(0, $transport->gets);
    }
}
