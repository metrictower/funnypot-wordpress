<?php

declare(strict_types=1);

namespace Honeypot\WP\Tests\Unit;

use Funnypot\Policy\Decision;
use Funnypot\Policy\RequestEvidence;
use Funnypot\Policy\SiteProfile;
use Honeypot\WP\Interceptor;
use Honeypot\WP\Settings;
use Honeypot\WP\Tests\Fakes\InMemoryBackend;
use Honeypot\WP\WpClock;
use Honeypot\WP\WpStateStore;

final class InterceptorTest extends TestCase
{
    /** @var array captured executor.execute() calls */
    private $executed;
    /** @var InMemoryBackend */
    private $backend;

    protected function setUp(): void
    {
        parent::setUp();
        Interceptor::reset();
        $this->executed = array();
        $this->backend = new InMemoryBackend();

        Interceptor::$serverProvider = static function () {
            return array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/.env', 'REMOTE_ADDR' => '203.0.113.9');
        };
        Interceptor::$rawBodyProvider = static function () {
            return null;
        };
        Interceptor::$currentHookProvider = static function () {
            return 'muplugins_loaded';
        };
        $backend = $this->backend;
        Interceptor::$storeProvider = static function ($s, $clock) use ($backend) {
            return new WpStateStore($backend, $clock);
        };
        $self = $this;
        Interceptor::$executorProvider = static function () use ($self) {
            return new class($self->executed) {
                private $ref;
                public function __construct(&$ref)
                {
                    $this->ref = &$ref;
                }
                public function execute(Decision $d, RequestEvidence $e)
                {
                    $this->ref[] = $d;
                    return $d->action() === Decision::DECEIVE || $d->action() === Decision::BLOCK;
                }
            };
        };
    }

    protected function tearDown(): void
    {
        Interceptor::$settingsProvider = null;
        Interceptor::$serverProvider = null;
        Interceptor::$rawBodyProvider = null;
        Interceptor::$is404Provider = null;
        Interceptor::$currentHookProvider = null;
        Interceptor::$policyFactory = null;
        Interceptor::$executorProvider = null;
        Interceptor::$storeProvider = null;
        Interceptor::reset();
        parent::tearDown();
    }

    private function settings(array $raw)
    {
        $s = Settings::fromArray($raw, static function () {
            return null;
        });
        Interceptor::$settingsProvider = static function () use ($s) {
            return $s;
        };
        return $s;
    }

    private function engineReturning($decisionOrThrow)
    {
        Interceptor::$policyFactory = static function () use ($decisionOrThrow) {
            return new class($decisionOrThrow) {
                private $d;
                public function __construct($d)
                {
                    $this->d = $d;
                }
                public function evaluate(RequestEvidence $e, SiteProfile $p)
                {
                    if ($this->d instanceof \Throwable) {
                        throw $this->d;
                    }
                    return $this->d;
                }
            };
        };
    }

    public function testMasterOffDoesNotEvaluate(): void
    {
        $this->settings(array('enabled' => false, 'posture' => 'WAF'));
        $this->engineReturning(Decision::deceive(new \Funnypot\Policy\FakeResponse(200, array(), 'x', 'text/plain')));
        Interceptor::runBefore();
        $this->assertCount(0, $this->executed);
    }

    public function testRunBeforeReturnsWhenBeforeNotConfigured(): void
    {
        // honeypot posture -> before is NOT active.
        $this->settings(array('enabled' => true, 'posture' => 'honeypot'));
        $this->engineReturning(Decision::block(403));
        Interceptor::runBefore();
        $this->assertCount(0, $this->executed);
    }

    public function testRunFallbackReturnsWhenNot404(): void
    {
        $this->settings(array('enabled' => true, 'posture' => 'honeypot'));
        Interceptor::$is404Provider = static function () {
            return false;
        };
        $this->engineReturning(Decision::deceive(new \Funnypot\Policy\FakeResponse(200, array(), 'x', 'text/plain')));
        Interceptor::runFallback();
        $this->assertCount(0, $this->executed);
    }

    public function testDeceiveDecisionReachesExecutor(): void
    {
        $this->settings(array('enabled' => true, 'posture' => 'WAF'));
        $decision = Decision::deceive(new \Funnypot\Policy\FakeResponse(200, array(), 'FAKE', 'text/plain'), null, 'sacrificial-path');
        $this->engineReturning($decision);
        Interceptor::runBefore();
        $this->assertCount(1, $this->executed);
        $this->assertSame(Decision::DECEIVE, $this->executed[0]->action());
    }

    public function testThrowingEngineIsSwallowed(): void
    {
        $this->settings(array('enabled' => true, 'posture' => 'WAF'));
        $this->engineReturning(new \RuntimeException('boom'));
        // Must not throw and must not reach the executor (fail-safe to allow, no 500).
        Interceptor::runBefore();
        $this->assertCount(0, $this->executed);
    }

    public function testIdempotencyRunsBodyOnce(): void
    {
        $this->settings(array('enabled' => true, 'posture' => 'WAF'));
        $this->engineReturning(Decision::block(403));
        Interceptor::runBefore();
        Interceptor::runBefore();
        $this->assertCount(1, $this->executed);
    }

    public function testMountMarkerRecordedAndMappedByMountState(): void
    {
        $this->settings(array('enabled' => true, 'posture' => 'WAF'));
        $this->engineReturning(Decision::allow());
        Interceptor::runBefore();

        $store = new WpStateStore($this->backend, new WpClock());
        $hook = $store->backend()->get('mount:before');
        $this->assertSame('muplugins_loaded', $hook);
        $this->assertSame('mu-plugin', Interceptor::mountState($hook, true));
        $this->assertSame('plugins_loaded (degraded)', Interceptor::mountState('plugins_loaded', true));
        $this->assertSame('not running', Interceptor::mountState(null, true));
    }
}
