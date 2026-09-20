<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\Policy\Decision;
use Funnypot\Policy\RequestEvidence;
use Funnypot\Policy\SiteProfile;
use Funnypot\WordPress\Interceptor;
use Funnypot\WordPress\Settings;
use Funnypot\WordPress\Tests\Fakes\InMemoryBackend;
use Funnypot\WordPress\WpClock;
use Funnypot\WordPress\WpStateStore;

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
        Interceptor::$installedSetProvider = null;
        Interceptor::$genuineRouteProvider = null;
        Interceptor::$decoyOwnershipProvider = null;
        Interceptor::$coreProvider = null;
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

    public function testForcedBeforeFiresUnderHoneypotPostureAfterRunBeforeNoOp(): void
    {
        // Honeypot posture leaves BEFORE off: runBefore@0 sets $ranBefore then returns at the gate.
        $this->settings(array('enabled' => true, 'posture' => 'honeypot'));
        $decision = Decision::deceive(new \Funnypot\Policy\FakeResponse(200, array(), 'FAKE', 'text/plain'), null, 'sacrificial-path');
        $this->engineReturning($decision);

        Interceptor::runBefore();          // no-op under honeypot (before not active)
        $this->assertCount(0, $this->executed);

        Interceptor::runBeforeForced();    // separate guard -> the decoy fires despite before being off
        $this->assertCount(1, $this->executed);
        $this->assertSame(Decision::DECEIVE, $this->executed[0]->action());
    }

    public function testForcedBeforeIsIdempotent(): void
    {
        $this->settings(array('enabled' => true, 'posture' => 'honeypot'));
        $this->engineReturning(Decision::deceive(new \Funnypot\Policy\FakeResponse(200, array(), 'x', 'text/plain')));
        Interceptor::runBeforeForced();
        Interceptor::runBeforeForced();
        $this->assertCount(1, $this->executed);
    }

    public function testForcedBeforeThrowingEngineDegradesToWpProceeds(): void
    {
        $this->settings(array('enabled' => true, 'posture' => 'honeypot'));
        $this->engineReturning(new \RuntimeException('boom'));
        // A fault under the forced pass must still degrade to WP-proceeds (real login), never a 500.
        Interceptor::runBeforeForced();
        $this->assertCount(0, $this->executed);
    }

    public function testForcedBeforeStillGatedByMasterSwitch(): void
    {
        $this->settings(array('enabled' => false, 'posture' => 'honeypot'));
        $this->engineReturning(Decision::deceive(new \Funnypot\Policy\FakeResponse(200, array(), 'x', 'text/plain')));
        Interceptor::runBeforeForced();
        $this->assertCount(0, $this->executed);
    }

    /** Capture the SiteProfile the engine is handed so the oracle wiring can be asserted directly. */
    private function engineCapturingProfile(&$captured)
    {
        Interceptor::$policyFactory = static function () use (&$captured) {
            return new class($captured) {
                private $ref;
                public function __construct(&$ref)
                {
                    $this->ref = &$ref;
                }
                public function evaluate(RequestEvidence $e, SiteProfile $p)
                {
                    $this->ref = $p;
                    return Decision::allow();
                }
            };
        };
    }

    public function testInstalledSetProviderMarksUninstalledSlugSacrificial(): void
    {
        $this->settings(array('enabled' => true, 'posture' => 'WAF'));
        Interceptor::$serverProvider = static function () {
            return array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/wp-content/plugins/tutor/readme.txt', 'REMOTE_ADDR' => '203.0.113.9');
        };
        Interceptor::$installedSetProvider = static function () {
            return array('plugins' => array('akismet'), 'themes' => array(), 'known' => true);
        };
        $captured = null;
        $this->engineCapturingProfile($captured);

        Interceptor::runBefore();

        $this->assertInstanceOf(SiteProfile::class, $captured);
        $this->assertTrue($captured->isSacrificialPath('/wp-content/plugins/tutor/readme.txt'));
        $this->assertFalse($captured->routeExists('/wp-content/plugins/tutor/readme.txt'));
    }

    public function testInstalledSlugStaysRealRouteThroughInterceptor(): void
    {
        $this->settings(array('enabled' => true, 'posture' => 'WAF'));
        Interceptor::$serverProvider = static function () {
            return array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/wp-content/plugins/akismet/readme.txt', 'REMOTE_ADDR' => '203.0.113.9');
        };
        Interceptor::$installedSetProvider = static function () {
            return array('plugins' => array('akismet'), 'themes' => array(), 'known' => true);
        };
        $captured = null;
        $this->engineCapturingProfile($captured);

        Interceptor::runBefore();

        $this->assertInstanceOf(SiteProfile::class, $captured);
        $this->assertFalse($captured->isSacrificialPath('/wp-content/plugins/akismet/readme.txt'));
        $this->assertTrue($captured->routeExists('/wp-content/plugins/akismet/readme.txt'));
    }

    public function testFaultingInstalledSetProviderFailsSafeToBlanket(): void
    {
        $this->settings(array('enabled' => true, 'posture' => 'WAF'));
        Interceptor::$serverProvider = static function () {
            return array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/wp-content/plugins/tutor/readme.txt', 'REMOTE_ADDR' => '203.0.113.9');
        };
        Interceptor::$installedSetProvider = static function () {
            throw new \RuntimeException('boom');
        };
        $captured = null;
        $this->engineCapturingProfile($captured);

        // A provider fault must not break interception; the profile reverts to blanket (real route).
        Interceptor::runBefore();

        $this->assertInstanceOf(SiteProfile::class, $captured);
        $this->assertTrue($captured->routeExists('/wp-content/plugins/tutor/readme.txt'));
        $this->assertFalse($captured->isSacrificialPath('/wp-content/plugins/tutor/readme.txt'));
    }

    // --- FP-0504: serve core decoys on WP-preempted scanner paths -------------------------------

    /** The pure fail-safe-to-genuine oracle. not-genuine ONLY for is_404 or empty-query fallthrough. */
    public function testIsGenuineRouteTruthTable(): void
    {
        // (a) hard 404 -> not genuine.
        $this->assertFalse(Interceptor::isGenuineRoute(true, false, false, false));
        $this->assertFalse(Interceptor::isGenuineRoute(true, true, true, true));
        // (b) front-page fallthrough off root with an EMPTY main query -> not genuine (/phpmyadmin).
        $this->assertFalse(Interceptor::isGenuineRoute(false, true, false, true));
        // SEO sitemap: front-page/home off root but a NON-empty main query (carries `sitemap`) -> genuine.
        $this->assertTrue(Interceptor::isGenuineRoute(false, true, false, false));
        // Real homepage requested at "/" -> genuine (requestIsRoot excludes it).
        $this->assertTrue(Interceptor::isGenuineRoute(false, true, true, true));
        // feed/robots/favicon/search land here (WP suppresses is_home) -> genuine regardless of query.
        $this->assertTrue(Interceptor::isGenuineRoute(false, false, false, true));
        $this->assertTrue(Interceptor::isGenuineRoute(false, false, false, false));
    }

    /** /phpmyadmin (owned, WP-preempted soft-404) serves the decoy under realistic. */
    public function testOwnedPreemptedPathServesDecoyUnderRealistic(): void
    {
        $this->settings(array('enabled' => true, 'posture' => 'honeypot', 'response_mode' => 'realistic'));
        Interceptor::$serverProvider = static function () {
            return array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/phpmyadmin', 'REMOTE_ADDR' => '203.0.113.9');
        };
        Interceptor::$is404Provider = static function () {
            return false; // WP soft-resolved it (no hard 404)
        };
        Interceptor::$genuineRouteProvider = static function () {
            return false; // not genuine (front-page fallthrough, empty query)
        };
        Interceptor::$decoyOwnershipProvider = static function () {
            return true; // core owns a decoy for /phpmyadmin
        };
        $this->engineReturning(Decision::deceive(new \Funnypot\Policy\FakeResponse(200, array('Content-Type' => 'text/html'), '<title>phpMyAdmin', 'text/html')));

        Interceptor::runFallback();

        $this->assertCount(1, $this->executed);
        $this->assertSame(Decision::DECEIVE, $this->executed[0]->action());
    }

    /**
     * Legit no-object endpoints (feed/robots/favicon/search) and a real page are LEFT UNTOUCHED under
     * BOTH realistic and taunt, even when the evaluator reports the path OWNED — the oracle spares them.
     */
    public function testGenuineEndpointsNeverDecoyedEvenWhenOwned(): void
    {
        foreach (array('realistic', 'taunt') as $mode) {
            foreach (array('/feed', '/feed/', '/robots.txt', '/favicon.ico', '/?s=foo', '/hello-world') as $path) {
                Interceptor::reset();
                $this->executed = array();
                $this->settings(array('enabled' => true, 'posture' => 'honeypot', 'response_mode' => $mode));
                Interceptor::$serverProvider = static function () use ($path) {
                    return array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => $path, 'REMOTE_ADDR' => '203.0.113.9');
                };
                Interceptor::$is404Provider = static function () {
                    return false;
                };
                Interceptor::$genuineRouteProvider = static function () {
                    return true; // WP resolved a genuine route -> never touch
                };
                Interceptor::$decoyOwnershipProvider = static function () {
                    return true; // even though core OWNS a decoy for it
                };
                $this->engineReturning(Decision::deceive(new \Funnypot\Policy\FakeResponse(200, array(), 'FAKE', 'text/plain')));

                Interceptor::runFallback();

                $this->assertCount(0, $this->executed, "$path must not be decoyed under $mode");
            }
        }
    }

    /**
     * SEO-plugin sitemaps (is_home=true, non-root, NON-empty main query carrying `sitemap`) resolve as
     * genuine and are left untouched even when the evaluator reports them OWNED. The bare harness cannot
     * route Yoast/RankMath, so this unit case is the authoritative guard for the sitemap subclass.
     */
    public function testSeoSitemapWithNonEmptyQueryIsGenuineNotDecoyed(): void
    {
        $this->settings(array('enabled' => true, 'posture' => 'honeypot', 'response_mode' => 'realistic'));
        Interceptor::$serverProvider = static function () {
            return array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/sitemap_index.xml', 'REMOTE_ADDR' => '203.0.113.9');
        };
        Interceptor::$is404Provider = static function () {
            return false;
        };
        // The production provider computes isGenuineRoute from WP booleans; mirror it for the sitemap:
        // is_home=true, non-root, but a NON-empty main query -> genuine.
        Interceptor::$genuineRouteProvider = static function () {
            return Interceptor::isGenuineRoute(false, true, false, false);
        };
        Interceptor::$decoyOwnershipProvider = static function () {
            return true; // core owns /sitemap_index.xml — ownership must NOT promote it
        };
        $this->engineReturning(Decision::deceive(new \Funnypot\Policy\FakeResponse(200, array(), 'FAKE', 'text/plain')));

        Interceptor::runFallback();

        $this->assertCount(0, $this->executed);
    }

    /** A guard fault (unreadable WP state) degrades to genuine: never decoy a real page (doubt=>genuine). */
    public function testGenuineRouteProviderFaultDegradesToGenuine(): void
    {
        $this->settings(array('enabled' => true, 'posture' => 'honeypot', 'response_mode' => 'realistic'));
        Interceptor::$is404Provider = static function () {
            return false;
        };
        Interceptor::$genuineRouteProvider = static function () {
            throw new \RuntimeException('unreadable $wp');
        };
        Interceptor::$decoyOwnershipProvider = static function () {
            return true;
        };
        $this->engineReturning(Decision::deceive(new \Funnypot\Policy\FakeResponse(200, array(), 'FAKE', 'text/plain')));

        Interceptor::runFallback();

        $this->assertCount(0, $this->executed);
    }

    /** An unowned not-genuine soft-404 is left to WordPress (no forced hard-404). */
    public function testUnownedPreemptedPathLeavesWpUntouched(): void
    {
        $this->settings(array('enabled' => true, 'posture' => 'honeypot', 'response_mode' => 'realistic'));
        Interceptor::$serverProvider = static function () {
            return array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/random-junk-path', 'REMOTE_ADDR' => '203.0.113.9');
        };
        Interceptor::$is404Provider = static function () {
            return false;
        };
        Interceptor::$genuineRouteProvider = static function () {
            return false; // not genuine
        };
        Interceptor::$decoyOwnershipProvider = static function () {
            return false; // core owns no decoy -> WP proceeds
        };
        $this->engineReturning(Decision::deceive(new \Funnypot\Policy\FakeResponse(200, array(), 'FAKE', 'text/plain')));

        Interceptor::runFallback();

        $this->assertCount(0, $this->executed);
    }

    /** Stealth (capture-only) never serves the decoy on the FP-0504 branch, even for an owned path. */
    public function testStealthNeverServesPreemptedDecoy(): void
    {
        $this->settings(array('enabled' => true, 'posture' => 'honeypot', 'response_mode' => 'stealth'));
        Interceptor::$serverProvider = static function () {
            return array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/phpmyadmin', 'REMOTE_ADDR' => '203.0.113.9');
        };
        Interceptor::$is404Provider = static function () {
            return false;
        };
        Interceptor::$genuineRouteProvider = static function () {
            return false;
        };
        Interceptor::$decoyOwnershipProvider = static function () {
            return true;
        };
        $this->engineReturning(Decision::deceive(new \Funnypot\Policy\FakeResponse(200, array(), 'FAKE', 'text/plain')));

        Interceptor::runFallback();

        $this->assertCount(0, $this->executed);
    }

    /** The genuine-404 path still serves (legacy default oracle, no ownership pre-check needed). */
    public function testGenuine404StillServesViaLegacyPath(): void
    {
        $this->settings(array('enabled' => true, 'posture' => 'honeypot', 'response_mode' => 'realistic'));
        Interceptor::$serverProvider = static function () {
            return array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/.env', 'REMOTE_ADDR' => '203.0.113.9');
        };
        Interceptor::$is404Provider = static function () {
            return true; // WP genuinely 404'd
        };
        // No genuineRouteProvider wired -> legacy default (only a hard 404 is not-genuine).
        $this->engineReturning(Decision::deceive(new \Funnypot\Policy\FakeResponse(200, array(), 'APP_KEY=fake', 'text/plain'), null, 'sacrificial-path'));

        Interceptor::runFallback();

        $this->assertCount(1, $this->executed);
        $this->assertSame(Decision::DECEIVE, $this->executed[0]->action());
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
