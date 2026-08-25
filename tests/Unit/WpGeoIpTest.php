<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\WordPress\Geo\WpGeoIp;

final class WpGeoIpTest extends TestCase
{
    public function testResolvesIpv4AndIpv6(): void
    {
        $db = array('203.0.113.5' => 'US', '2001:db8::1' => 'de');
        $geo = new WpGeoIp(static function ($ip) use ($db) {
            return isset($db[$ip]) ? $db[$ip] : null;
        });

        $this->assertSame('US', $geo->country('203.0.113.5'));
        $this->assertSame('DE', $geo->country('2001:db8::1'), 'lower-case codes are upper-cased');
    }

    public function testUnknownIpReturnsNull(): void
    {
        $geo = new WpGeoIp(static function () {
            return null;
        });
        $this->assertNull($geo->country('8.8.8.8'));
    }

    public function testNoDbReturnsNull(): void
    {
        $this->assertNull((new WpGeoIp())->country('8.8.8.8'));
    }

    public function testReaderFaultIsFailOpen(): void
    {
        $geo = new WpGeoIp(static function () {
            throw new \RuntimeException('DB unreadable');
        });
        $this->assertNull($geo->country('8.8.8.8'), 'a reader fault must return null, never throw');
    }

    public function testInvalidCodeReturnsNull(): void
    {
        $geo = new WpGeoIp(static function () {
            return 'USA';
        });
        $this->assertNull($geo->country('203.0.113.5'));
    }
}
