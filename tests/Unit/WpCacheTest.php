<?php

declare(strict_types=1);

namespace Honeypot\WP\Tests\Unit;

use Honeypot\WP\Reputation\WpCache;

final class WpCacheTest extends TestCase
{
    private $store;
    private $ttls;

    private function cache()
    {
        $this->store = array();
        $this->ttls = array();
        $self = $this;

        return new WpCache(
            static function ($k) use ($self) {
                return array_key_exists($k, $self->store) ? $self->store[$k] : false;
            },
            static function ($k, $v, $ttl) use ($self) {
                $self->store[$k] = $v;
                $self->ttls[$k] = $ttl;
                return true;
            },
            static function ($k) use ($self) {
                unset($self->store[$k]);
                return true;
            }
        );
    }

    public function testSetGetRoundTrip(): void
    {
        $cache = $this->cache();
        $cache->set('mnc:v:1.2.3.4:90:balanced', array('verdict' => 'malicious'), 24 * 3600);
        $this->assertSame(array('verdict' => 'malicious'), $cache->get('mnc:v:1.2.3.4:90:balanced'));
        $this->assertTrue($cache->has('mnc:v:1.2.3.4:90:balanced'));
    }

    public function testTtlEqualsCacheHoursTimesSeconds(): void
    {
        $cache = $this->cache();
        $cache->set('k', 'v', 24 * 3600);
        // key is namespaced; the TTL passed through must be the full seconds value.
        $stored = array_values($this->ttls);
        $this->assertSame(86400, $stored[0]);
    }

    public function testKeysAreNamespaced(): void
    {
        $cache = $this->cache();
        $cache->set('mnc:breaker', array('open' => 1), 60);
        $keys = array_keys($this->store);
        $this->assertStringStartsWith('honeypot_wp_rep_', $keys[0]);
    }

    public function testMissReturnsDefaultAndCachesNegative(): void
    {
        $cache = $this->cache();
        $this->assertNull($cache->get('absent'));
        $this->assertSame('fallback', $cache->get('absent', 'fallback'));

        // F caches misses too: a stored null/false value round-trips as a real hit, not a miss.
        $cache->set('neg', null, 60);
        $this->assertTrue($cache->has('neg'));
        $this->assertNull($cache->get('neg', 'default-should-not-win'));
    }
}
