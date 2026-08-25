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
        // Compiling core's ~84k-line rules artifact spikes memory; the default 128M CLI limit is not
        // enough. Raise it for this integration-flavoured test only.
        @ini_set('memory_limit', '512M');
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
        $profile = (new WpSiteProfile(true))->toPolicyProfile('/.env');

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
}
