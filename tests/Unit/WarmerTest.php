<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\Mainnet\Cache\ArrayCache;
use Funnypot\Mainnet\CircuitBreaker;
use Funnypot\WordPress\Reputation\Warmer;
use Funnypot\WordPress\Tests\Fakes\InMemoryBackend;
use Funnypot\WordPress\Tests\Fakes\MutableClock;

final class WarmerTest extends TestCase
{
    public function testEnqueueBoundsQueue(): void
    {
        $checked = array();
        $backend = new InMemoryBackend();
        $warmer = new Warmer(static function ($ip) use (&$checked) {
            $checked[] = $ip;
        }, $backend, null, 3);

        foreach (array('1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5') as $ip) {
            $warmer->enqueue($ip);
        }
        $this->assertSame(3, $warmer->pending(), 'queue is capped, oldest dropped first');
    }

    public function testEnqueueDeduplicates(): void
    {
        $backend = new InMemoryBackend();
        $warmer = new Warmer(static function () {
        }, $backend, null, 100);
        $warmer->enqueue('1.1.1.1');
        $warmer->enqueue('1.1.1.1');
        $this->assertSame(1, $warmer->pending());
    }

    public function testDrainCallsCheckUpToLimit(): void
    {
        $checked = array();
        $backend = new InMemoryBackend();
        $warmer = new Warmer(static function ($ip) use (&$checked) {
            $checked[] = $ip;
        }, $backend, null, 100);

        foreach (array('1.1.1.1', '2.2.2.2', '3.3.3.3') as $ip) {
            $warmer->enqueue($ip);
        }
        $res = $warmer->drain(2);
        $this->assertSame(2, $res['checked']);
        $this->assertSame(1, $res['pending']);
        $this->assertSame(array('1.1.1.1', '2.2.2.2'), $checked);
    }

    public function testDrainSkippedWhileBreakerOpen(): void
    {
        $clock = new MutableClock();
        $cache = new ArrayCache($clock->asCallable());
        $breaker = new CircuitBreaker($cache, 5, 60, 21600, $clock->asCallable());
        $breaker->tripTransport();

        $checked = array();
        $backend = new InMemoryBackend();
        $warmer = new Warmer(static function ($ip) use (&$checked) {
            $checked[] = $ip;
        }, $backend, $breaker, 100);
        $warmer->enqueue('1.1.1.1');

        $res = $warmer->drain(10);
        $this->assertTrue($res['skipped']);
        $this->assertSame(array(), $checked, 'no check while the breaker is OPEN');
    }

    public function testCheckFaultIsSwallowed(): void
    {
        $backend = new InMemoryBackend();
        $warmer = new Warmer(static function () {
            throw new \RuntimeException('mainnet down');
        }, $backend, null, 100);
        $warmer->enqueue('1.1.1.1');

        // must not throw
        $res = $warmer->drain(10);
        $this->assertSame(1, $res['checked']);
        $this->assertSame(0, $res['pending']);
    }
}
