<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\Core\Rules\RulesUpdateException;
use Funnypot\WordPress\Rules\WpRemoteRulesFetcher;

/**
 * The exec-free WP fetcher's anti-SSRF posture: HTTPS-only, a pinned host allow-list, no auto-follow
 * with every redirect re-checked, and a bounded response size. No real network — wp_remote_get is
 * injected. These assert the guards the HttpFetcher contract requires; core owns the verify tests.
 */
final class WpRemoteRulesFetcherTest extends TestCase
{
    private const GH = 'https://github.com/metrictower/funnypot-rules/releases/download/v1/v1.manifest.json';

    /** A wp_remote_get double returning a canned response array, recording the URLs it saw. */
    private function getFn(array $responses, array &$seen = array())
    {
        $i = 0;

        return static function ($url, $args) use (&$i, $responses, &$seen) {
            $seen[] = $url;
            $r = $responses[$i] ?? $responses[count($responses) - 1];
            $i++;

            return $r;
        };
    }

    /** A WP_Error-like object (duck-typed on get_error_message). */
    private function wpError(string $msg = 'dns failure')
    {
        return new class($msg) {
            private $msg;
            public function __construct($m)
            {
                $this->msg = $m;
            }
            public function get_error_message()
            {
                return $this->msg;
            }
        };
    }

    public function testAllowListedHttpsReturnsBody(): void
    {
        $fetcher = new WpRemoteRulesFetcher(
            array('github.com'),
            33554432,
            30,
            5,
            $this->getFn(array(array('response' => array('code' => 200), 'body' => 'MANIFEST-BYTES', 'headers' => array())))
        );

        $this->assertSame('MANIFEST-BYTES', $fetcher->get(self::GH));
    }

    public function testNonHttpsRejected(): void
    {
        $fetcher = new WpRemoteRulesFetcher(array('github.com'), 33554432, 30, 5, $this->getFn(array()));

        $this->expectException(RulesUpdateException::class);
        $this->expectExceptionMessage('non-HTTPS'); // asserts the scheme guard
        $fetcher->get('http://github.com/x');
    }

    public function testOffAllowlistHostRejected(): void
    {
        $fetcher = new WpRemoteRulesFetcher(array('github.com'), 33554432, 30, 5, $this->getFn(array()));

        $this->expectException(RulesUpdateException::class);
        $this->expectExceptionMessage('allow-list'); // asserts the host allow-list
        $fetcher->get('https://evil.example/x');
    }

    public function testRedirectToOffAllowlistHostRejected(): void
    {
        $seen = array();
        $fetcher = new WpRemoteRulesFetcher(
            array('github.com'),
            33554432,
            30,
            5,
            $this->getFn(array(
                array('response' => array('code' => 302), 'body' => '', 'headers' => array('Location' => 'https://evil.example/pwn')),
            ), $seen)
        );

        try {
            $fetcher->get(self::GH);
            $this->fail('expected a rejection on an off-allowlist redirect');
        } catch (RulesUpdateException $e) {
            $this->assertStringContainsString('allow-list', $e->getMessage()); // asserts per-hop re-check
        }
        // The off-allowlist redirect target must never have been fetched.
        $this->assertNotContains('https://evil.example/pwn', $seen);
    }

    public function testBodyOverSizeCapRejected(): void
    {
        $fetcher = new WpRemoteRulesFetcher(
            array('github.com'),
            10, // tiny cap
            30,
            5,
            $this->getFn(array(array('response' => array('code' => 200), 'body' => str_repeat('A', 11), 'headers' => array())))
        );

        $this->expectException(RulesUpdateException::class);
        $this->expectExceptionMessage('size cap'); // asserts the size bound
        $fetcher->get(self::GH);
    }

    public function testWpErrorMappedToException(): void
    {
        $fetcher = new WpRemoteRulesFetcher(
            array('github.com'),
            33554432,
            30,
            5,
            $this->getFn(array($this->wpError()))
        );

        $this->expectException(RulesUpdateException::class);
        $this->expectExceptionMessage('wp_remote_get failed'); // asserts transport-fault mapping (no partial return)
        $fetcher->get(self::GH);
    }

    public function testNon200Rejected(): void
    {
        $fetcher = new WpRemoteRulesFetcher(
            array('github.com'),
            33554432,
            30,
            5,
            $this->getFn(array(array('response' => array('code' => 404), 'body' => 'nope', 'headers' => array())))
        );

        $this->expectException(RulesUpdateException::class);
        $this->expectExceptionMessage('HTTP 404');
        $fetcher->get(self::GH);
    }
}
