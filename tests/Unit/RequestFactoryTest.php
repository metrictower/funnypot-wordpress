<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\WordPress\RequestFactory;
use Funnypot\WordPress\Settings;

final class RequestFactoryTest extends TestCase
{
    private function settings(array $raw = array())
    {
        return Settings::fromArray($raw, static function () {
            return null;
        });
    }

    public function testXffIgnoredFromUntrustedPeer(): void
    {
        $server = array(
            'REMOTE_ADDR' => '203.0.113.9',
            'HTTP_X_FORWARDED_FOR' => '1.2.3.4',
        );
        $ip = RequestFactory::clientIp($server, $this->settings());
        $this->assertSame('203.0.113.9', $ip, 'spoofed XFF must not rotate the actor id');
    }

    public function testXffHonoredBehindTrustedProxy(): void
    {
        $server = array(
            'REMOTE_ADDR' => '10.0.0.5',
            'HTTP_X_FORWARDED_FOR' => '198.51.100.23, 10.0.0.5',
        );
        $s = $this->settings(array('trusted_proxies' => array('10.0.0.0/8')));
        $this->assertSame('198.51.100.23', RequestFactory::clientIp($server, $s));
    }

    public function testTrustedProxyExactMatchWithoutCidr(): void
    {
        $server = array(
            'REMOTE_ADDR' => '192.0.2.1',
            'HTTP_X_FORWARDED_FOR' => '198.51.100.7',
        );
        $s = $this->settings(array('trusted_proxies' => array('192.0.2.1')));
        $this->assertSame('198.51.100.7', RequestFactory::clientIp($server, $s));
    }

    public function testMalformedXffFallsBackToRemote(): void
    {
        $server = array(
            'REMOTE_ADDR' => '10.0.0.5',
            'HTTP_X_FORWARDED_FOR' => 'not-an-ip',
        );
        $s = $this->settings(array('trusted_proxies' => array('10.0.0.0/8')));
        $this->assertSame('10.0.0.5', RequestFactory::clientIp($server, $s));
    }

    public function testIpv6PeerHandling(): void
    {
        $server = array('REMOTE_ADDR' => '2001:db8::1');
        $this->assertSame('2001:db8::1', RequestFactory::clientIp($server, $this->settings()));
    }

    public function testEvidenceBuildsMethodPathQueryHeaders(): void
    {
        $server = array(
            'REQUEST_METHOD' => 'get',
            'REQUEST_URI' => '/wp-json/wp/v2/posts?per_page=5&x=1',
            'REMOTE_ADDR' => '203.0.113.9',
            'HTTP_USER_AGENT' => 'sqlmap/1.0',
            'HTTP_ACCEPT' => 'application/json',
            'CONTENT_TYPE' => 'application/json',
        );
        $e = RequestFactory::evidence($server, null, $this->settings());

        $this->assertSame('GET', $e->method());
        $this->assertSame('/wp-json/wp/v2/posts', $e->path());
        $this->assertSame(array('per_page' => '5', 'x' => '1'), $e->query());
        $this->assertSame('sqlmap/1.0', $e->header('user-agent'));
        $this->assertSame('application/json', $e->header('accept'));
        $this->assertSame('203.0.113.9', $e->ip());
    }

    public function testRawBodyNeverAppearsInEvidence(): void
    {
        $server = array(
            'REQUEST_METHOD' => 'POST',
            'REQUEST_URI' => '/xmlrpc.php',
            'REMOTE_ADDR' => '203.0.113.9',
            'CONTENT_TYPE' => 'text/xml',
        );
        $payload = '<?xml version="1.0"?><methodCall>SECRET_PAYLOAD</methodCall>';
        $e = RequestFactory::evidence($server, $payload, $this->settings());

        $shape = $e->bodyShape();
        $this->assertTrue($shape['present']);
        $this->assertSame(strlen($payload), $shape['length']);
        $this->assertSame('text/xml', $shape['content_type']);

        // The raw payload must not appear anywhere in the serialized evidence.
        $blob = json_encode(array(
            'q' => $e->query(),
            'h' => $e->headers(),
            'b' => $e->bodyShape(),
        ));
        $this->assertStringNotContainsString('SECRET_PAYLOAD', (string) $blob);
    }
}
