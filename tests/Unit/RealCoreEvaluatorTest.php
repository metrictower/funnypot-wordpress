<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\Core\Honeypot;
use Funnypot\Policy\Decision;
use Funnypot\WordPress\CoreEvaluator;
use Funnypot\WordPress\EvaluatorConfig;
use Funnypot\WordPress\PolicyFactory;
use Funnypot\WordPress\RequestFactory;
use Funnypot\WordPress\Settings;
use Funnypot\WordPress\Tests\Fakes\InMemoryBackend;
use Funnypot\WordPress\Tests\Fakes\MutableClock;
use Funnypot\WordPress\WpSiteProfile;
use Funnypot\WordPress\WpStateStore;

/**
 * Integration-flavoured smoke test wiring the REAL core evaluator (Funnypot\Core\Honeypot over the bundled
 * rules artifact). Proves the CoreEvaluator bridge + PolicyFactory integrate with the real engine end
 * to end. If the bundled artifact cannot load in this environment (a C-prerequisite gap), the test
 * skips rather than fails.
 */
final class RealCoreEvaluatorTest extends TestCase
{
    private function realEvaluator()
    {
        // Compiling core's compiled rules artifact spikes memory (it grew across core 0.6.x); the default
        // 128M CLI limit is not enough, and 512M no longer fits the v0.6 corpus under patchwork
        // instrumentation. Raise it for this integration-flavoured test only.
        @ini_set('memory_limit', '1024M');
        $s = Settings::fromArray(array('enabled' => true), static function () {
            return null;
        });
        try {
            return Honeypot::default(EvaluatorConfig::fromSettings($s));
        } catch (\Throwable $e) {
            $this->markTestSkipped('bundled core rules artifact unavailable: ' . $e->getMessage());
        }
    }

    public function testFallbackEnvProbeYieldsAValidDecisionThroughRealCore(): void
    {
        $core = $this->realEvaluator();
        $clock = new MutableClock();
        $store = new WpStateStore(new InMemoryBackend($clock->asCallable()), $clock);
        $s = Settings::fromArray(array('enabled' => true, 'posture' => 'honeypot'), static function () {
            return null;
        });

        $server = array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/.env', 'REMOTE_ADDR' => '203.0.113.9');
        $evidence = RequestFactory::evidence($server, null, $s);
        $ctx = CoreEvaluator::contextFromEvidence($evidence);
        // Counterfactual-404 (no genuine object resolved) -> the engine earns the sacrificial deceive.
        $profile = (new WpSiteProfile(false))->toPolicyProfile('/.env');

        $engine = PolicyFactory::forPosition($s, 'fallback', array(
            'evaluator' => $core,
            'store' => $store,
            'clock' => $clock,
            'ctx' => $ctx,
        ));

        $decision = $engine->evaluate($evidence, $profile);

        // The policy decided to deceive the sacrificial path (FP-free counterfactual-404). The real
        // core either renders a byte-exact fake or the bridge degrades to a plain 404 — both are a
        // deceive Decision with an app-chosen status, never a 5xx.
        $this->assertSame(Decision::DECEIVE, $decision->action());
        $this->assertNotNull($decision->fakeHandle());
        $this->assertIsInt($decision->status());
    }

    /**
     * FP-0504: a WP-preempted panel-root path core owns (/phpmyadmin) earns a DECEIVE with a byte-
     * rendered fake through the real core, given the counterfactual-404 profile the interceptor builds.
     */
    public function testPhpMyAdminPanelDeceivedThroughRealCore(): void
    {
        $core = $this->realEvaluator();
        $clock = new MutableClock();
        $store = new WpStateStore(new InMemoryBackend($clock->asCallable()), $clock);
        $s = Settings::fromArray(array('enabled' => true, 'posture' => 'honeypot', 'response_mode' => 'realistic'), static function () {
            return null;
        });

        $server = array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/phpmyadmin', 'REMOTE_ADDR' => '203.0.113.9');
        $evidence = RequestFactory::evidence($server, null, $s);
        $ctx = CoreEvaluator::contextFromEvidence($evidence);
        $profile = (new WpSiteProfile(false))->toPolicyProfile('/phpmyadmin');

        $engine = PolicyFactory::forPosition($s, 'fallback', array(
            'evaluator' => $core,
            'store' => $store,
            'clock' => $clock,
            'ctx' => $ctx,
        ));

        $decision = $engine->evaluate($evidence, $profile);

        $this->assertSame(Decision::DECEIVE, $decision->action());
        $this->assertNotNull($decision->fakeHandle());
        $this->assertIsInt($decision->status());
    }

    /**
     * HAZARD FREEZE (FP-0504) — do NOT delete. Core positively OWNS decoys for these LEGITIMATE WP
     * endpoints (verified against the adopted core v0.6.4 corpus vendored here). Ownership is therefore
     * NOT a safety signal: the interceptor MUST NOT decoy them on ownership alone. They are protected by
     * the fail-safe-to-genuine oracle (Interceptor::isGenuineRoute) — WP suppresses is_home for
     * feed/robots/favicon/search, and SEO sitemaps carry a non-empty `sitemap` query var. This test
     * fails loudly if a future corpus stops owning them (re-verify the oracle) or if someone assumes the
     * reserved set already covers them (it does not).
     */
    public function testCoreOwnsLegitEndpointsHazardFreeze(): void
    {
        $core = $this->realEvaluator();
        $s = Settings::fromArray(array('enabled' => true, 'posture' => 'honeypot'), static function () {
            return null;
        });

        $owned = array('/feed', '/feed/', '/robots.txt', '/sitemap.xml', '/sitemap_index.xml', '/favicon.ico');
        foreach ($owned as $path) {
            $server = array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => $path, 'REMOTE_ADDR' => '203.0.113.9');
            $evidence = RequestFactory::evidence($server, null, $s);
            $ctx = CoreEvaluator::contextFromEvidence($evidence);
            $profile = (new WpSiteProfile(false))->toPolicyProfile($path);
            $verdict = (new CoreEvaluator($core, $ctx))->classify($evidence, $profile);
            $this->assertNotSame('', $verdict->engineHandle(), "$path is core-OWNED — the oracle, not ownership, must spare it");
        }
    }
}
