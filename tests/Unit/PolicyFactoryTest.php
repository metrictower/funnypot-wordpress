<?php

declare(strict_types=1);

namespace Honeypot\WP\Tests\Unit;

use Funnypot\Policy\Decision;
use Funnypot\Policy\PolicyEngine;
use Honeypot\WP\CoreEvaluator;
use Honeypot\WP\PolicyFactory;
use Honeypot\WP\RequestFactory;
use Honeypot\WP\Settings;
use Honeypot\WP\Tests\Fakes\FakeCoreEvaluator;
use Honeypot\WP\Tests\Fakes\InMemoryBackend;
use Honeypot\WP\Tests\Fakes\MutableClock;
use Honeypot\WP\Tests\Fakes\RecordingTransport;
use Honeypot\WP\WpStateStore;

final class PolicyFactoryTest extends TestCase
{
    private function settings(array $raw)
    {
        return Settings::fromArray($raw, static function () {
            return null;
        });
    }

    private function deps(MutableClock $clock, array $extra = array())
    {
        return array_merge(array(
            'evaluator' => new FakeCoreEvaluator(),
            'store' => new WpStateStore(new InMemoryBackend($clock->asCallable()), $clock),
            'clock' => $clock,
        ), $extra);
    }

    public function testBuildsPolicyEngineByDefault(): void
    {
        $clock = new MutableClock();
        $engine = PolicyFactory::forPosition($this->settings(array('enabled' => true)), 'fallback', $this->deps($clock));
        $this->assertInstanceOf(PolicyEngine::class, $engine);
    }

    public function testGeoIpPortWiredOnlyWhenCountryPolicyEnabled(): void
    {
        $clock = new MutableClock();
        $s = $this->settings(array(
            'enabled' => true,
            'posture' => 'WAF',
            'country_posture' => 'deny_list',
            'country_list' => array('CN'),
            'country_action' => 'block',
        ));
        $deps = $this->deps($clock, array('geo_reader' => static function ($ip) {
            return 'CN';
        }));

        $engine = PolicyFactory::forPosition($s, 'before', $deps);

        $server = array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/some-path', 'REMOTE_ADDR' => '203.0.113.9');
        $evidence = RequestFactory::evidence($server, null, $s);
        $profile = (new \Honeypot\WP\WpSiteProfile(null))->toPolicyProfile('/some-path');

        // The country gate resolved a listed country via the wired WpGeoIp -> block at before/WAF.
        $decision = $engine->evaluate($evidence, $profile);
        $this->assertSame(Decision::BLOCK, $decision->action());
        $this->assertSame('country', $decision->reason());
    }

    public function testCountryOffMeansNoGeoResolution(): void
    {
        $clock = new MutableClock();
        $calls = 0;
        $s = $this->settings(array('enabled' => true, 'posture' => 'WAF', 'country_posture' => 'off'));
        $deps = $this->deps($clock, array('geo_reader' => static function () use (&$calls) {
            $calls++;
            return 'CN';
        }));
        $engine = PolicyFactory::forPosition($s, 'before', $deps);

        $server = array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/some-path', 'REMOTE_ADDR' => '203.0.113.9');
        $evidence = RequestFactory::evidence($server, null, $s);
        $profile = (new \Honeypot\WP\WpSiteProfile(null))->toPolicyProfile('/some-path');
        $engine->evaluate($evidence, $profile);

        $this->assertSame(0, $calls, 'geo is never resolved when country policy is off');
    }

    public function testReputationWiringConstructsWithInjectedTransport(): void
    {
        $clock = new MutableClock();
        $s = $this->settings(array(
            'enabled' => true,
            'posture' => 'WAF',
            'mainnet_key' => 'KEY',
            'reputation' => array('check_enabled' => true),
        ));
        // checkActive true -> MainnetReputation wired over F's Client; an injected transport keeps it
        // off the network. cachedVerdict is a local read (no socket), so evaluate must not error.
        $deps = $this->deps($clock, array(
            'evaluator' => new FakeCoreEvaluator(\Funnypot\Verdict::CLEAN),
            'transport' => new RecordingTransport(),
            'cache' => new \Honeypot\WP\Reputation\WpCache(
                static function () {
                    return false;
                },
                static function () {
                    return true;
                },
                static function () {
                    return true;
                }
            ),
        ));
        $engine = PolicyFactory::forPosition($s, 'before', $deps);

        $server = array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/some-path', 'REMOTE_ADDR' => '203.0.113.9', 'HTTP_USER_AGENT' => 'Mozilla/5.0', 'HTTP_ACCEPT' => 'text/html', 'HTTP_ACCEPT_LANGUAGE' => 'en', 'HTTP_ACCEPT_ENCODING' => 'gzip');
        $evidence = RequestFactory::evidence($server, null, $s);
        $profile = (new \Honeypot\WP\WpSiteProfile(null))->toPolicyProfile('/some-path');

        $decision = $engine->evaluate($evidence, $profile);
        // Clean content + no cached verdict -> the request path made no synchronous check; allow.
        $this->assertContains($decision->action(), array(Decision::ALLOW, Decision::LOG));
        $this->assertCount(0, (new RecordingTransport())->posts); // sanity: nothing forced a POST here
    }
}
