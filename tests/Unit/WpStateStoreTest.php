<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\Policy\Pin;
use Funnypot\Policy\ReputationVerdict;
use Funnypot\Policy\RuleState;
use Funnypot\WordPress\State\FileBackend;
use Funnypot\WordPress\State\ObjectCacheBackend;
use Funnypot\WordPress\Tests\Fakes\InMemoryBackend;
use Funnypot\WordPress\Tests\Fakes\MutableClock;
use Funnypot\WordPress\WpStateStore;

final class WpStateStoreTest extends TestCase
{
    private function store($backend, MutableClock $clock)
    {
        return new WpStateStore($backend, $clock);
    }

    public function testPinRoundTripWithTtl(): void
    {
        $clock = new MutableClock();
        $store = $this->store(new InMemoryBackend($clock->asCallable()), $clock);

        $this->assertNull($store->getPin('1.2.3.4'));
        $store->setPin('1.2.3.4', 'deceive', 'seed-abc', 3600);

        $pin = $store->getPin('1.2.3.4');
        $this->assertInstanceOf(Pin::class, $pin);
        $this->assertSame('deceive', $pin->action());
        $this->assertSame('seed-abc', $pin->seed());

        $clock->advance(3601);
        $this->assertNull($store->getPin('1.2.3.4'), 'pin must expire past its TTL');
    }

    public function testIsBlocked(): void
    {
        $clock = new MutableClock();
        $store = $this->store(new InMemoryBackend($clock->asCallable()), $clock);

        $this->assertFalse($store->isBlocked('9.9.9.9'));
        $store->block('9.9.9.9', 86400);
        $this->assertTrue($store->isBlocked('9.9.9.9'));
    }

    public function testRuleStateRoundTripAndBump(): void
    {
        $clock = new MutableClock();
        $store = $this->store(new InMemoryBackend($clock->asCallable()), $clock);

        $s = $store->ruleState('rule-x');
        $this->assertSame(RuleState::SHADOW, $s->phase());
        $this->assertSame(0, $s->count());

        $store->putRuleState('rule-x', new RuleState(RuleState::TUNING, 100, 3));
        $s2 = $store->ruleState('rule-x');
        $this->assertSame(RuleState::TUNING, $s2->phase());
        $this->assertSame(3, $s2->count());

        $store->bumpRuleEvaluated('rule-x', 2);
        $this->assertSame(5, $store->ruleState('rule-x')->count());
    }

    public function testSeenVerdictDedup(): void
    {
        $clock = new MutableClock();
        $store = $this->store(new InMemoryBackend($clock->asCallable()), $clock);

        $this->assertFalse($store->seenVerdict('k1', 86400), 'first sight is not a dup');
        $this->assertTrue($store->seenVerdict('k1', 86400), 'second sight within window is a dup');

        $clock->advance(86401);
        $this->assertFalse($store->seenVerdict('k1', 86400), 'window expiry resets dedup');
    }

    public function testIncrCounters(): void
    {
        $clock = new MutableClock();
        $store = $this->store(new InMemoryBackend($clock->asCallable()), $clock);

        $this->assertSame(1, $store->incr('c', 600));
        $this->assertSame(2, $store->incr('c', 600));
        $this->assertSame(1, $store->incrAlertCount('5.5.5.5', 600));
        $this->assertSame(2, $store->incrAlertCount('5.5.5.5', 600));
    }

    public function testDecayScoreAddsThenDecays(): void
    {
        $clock = new MutableClock();
        $store = $this->store(new InMemoryBackend($clock->asCallable()), $clock);

        $this->assertSame(10, $store->decayScore('actor', 10, 600, 86400));
        $this->assertSame(20, $store->decayScore('actor', 10, 600, 86400));

        // Past the cap TTL the prior contribution is fully decayed; only the new inc remains.
        $clock->advance(86400);
        $this->assertSame(10, $store->decayScore('actor', 10, 600, 86400));
    }

    public function testMirrorVerdictExactAndCidrContainment(): void
    {
        $clock = new MutableClock();
        $store = $this->store(new InMemoryBackend($clock->asCallable()), $clock);

        $store->putMirror(array(
            array('ip' => '203.0.113.5', 'verdict' => 'critical'),
            array('ip' => '198.51.100.0/24', 'verdict' => 'malicious'),
        ), 'etag-1', $clock->now(), 3600);

        // Exact IP row.
        $exact = $store->mirrorVerdict('203.0.113.5');
        $this->assertInstanceOf(ReputationVerdict::class, $exact);
        $this->assertSame('critical', $exact->verdict());
        $this->assertSame('mirror', $exact->source());

        // CIDR containment row (/24 blocks 256 addresses).
        $inRange = $store->mirrorVerdict('198.51.100.77');
        $this->assertNotNull($inRange);
        $this->assertSame('malicious', $inRange->verdict());

        // Off-mirror IP -> null (escalate).
        $this->assertNull($store->mirrorVerdict('8.8.8.8'));

        $meta = $store->mirrorMeta();
        $this->assertSame('etag-1', $meta['etag']);
        $this->assertSame(2, $meta['count']);
    }

    public function testBufferReportAndTake(): void
    {
        $clock = new MutableClock();
        $store = $this->store(new InMemoryBackend($clock->asCallable()), $clock);

        $this->assertSame(1, $store->bufferReport('g', array('ip' => '1.1.1.1'), 900));
        $this->assertSame(2, $store->bufferReport('g', array('ip' => '2.2.2.2'), 900));

        $drained = $store->takeReportBuffer();
        $this->assertArrayHasKey('g', $drained);
        $this->assertCount(2, $drained['g']);
        $this->assertSame(array(), $store->takeReportBuffer(), 'take clears the buffer');
    }

    /** RS-10: the full port contract round-trips under BOTH backends, default object-cache. */
    public function testBothBackendsRoundTrip(): void
    {
        $clock = new MutableClock();

        // object-cache backend backed by array closures (simulating transients; no plugin-dir write).
        $mem = array();
        $oc = new ObjectCacheBackend(
            static function ($k) use (&$mem) {
                return isset($mem[$k]) ? $mem[$k] : false;
            },
            static function ($k, $v, $ttl) use (&$mem) {
                $mem[$k] = $v;
                return true;
            },
            static function ($k) use (&$mem) {
                unset($mem[$k]);
                return true;
            }
        );

        // file backend in a temp dir.
        $dir = sys_get_temp_dir() . '/hpwp_state_' . uniqid();
        $file = new FileBackend($dir, $clock->asCallable());

        foreach (array($oc, $file) as $backend) {
            $store = new WpStateStore($backend, $clock);
            $store->setPin('7.7.7.7', 'block', 's', 3600);
            $this->assertSame('block', $store->getPin('7.7.7.7')->action());
            $this->assertFalse($store->seenVerdict('dk', 600));
            $this->assertTrue($store->seenVerdict('dk', 600));
            $this->assertSame(1, $store->incr('n', 600));
        }

        // The default backend (object-cache) never wrote into the plugin directory.
        $this->assertDirectoryDoesNotExist(dirname(__DIR__, 2) . '/state');

        // cleanup file backend
        array_map('unlink', glob($dir . '/*') ?: array());
        @rmdir($dir);
    }
}
