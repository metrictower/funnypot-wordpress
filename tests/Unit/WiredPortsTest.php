<?php

declare(strict_types=1);

namespace Honeypot\WP\Tests\Unit;

use Funnypot\Policy\Decision;
use Funnypot\Policy\FakeResponse;
use Funnypot\Policy\RequestEvidence;
use Honeypot\WP\CoreEvaluator;
use Honeypot\WP\DecisionExecutor;
use Honeypot\WP\PolicyFactory;
use Honeypot\WP\RequestFactory;
use Honeypot\WP\Settings;
use Honeypot\WP\Tests\Fakes\FakeCoreEvaluator;
use Honeypot\WP\Tests\Fakes\InMemoryBackend;
use Honeypot\WP\Tests\Fakes\MutableClock;
use Honeypot\WP\WpSiteProfile;
use Honeypot\WP\WpStateStore;

/**
 * Priority-3 deliverable: a scanner-probe / sacrificial evidence flows through the REAL PolicyEngine
 * wired with D's REAL ports (WpStateStore, CoreEvaluator bridge, NullReputation, WpClock, WpLogger),
 * producing a deceive/block Decision the DecisionExecutor emits — with fakes only where WP I/O is
 * involved (the core evaluator, the state backend, the emitter/halt).
 */
final class WiredPortsTest extends TestCase
{
    private function settings(array $raw)
    {
        return Settings::fromArray($raw, static function () {
            return null;
        });
    }

    private function store(MutableClock $clock)
    {
        return new WpStateStore(new InMemoryBackend($clock->asCallable()), $clock);
    }

    public function testSacrificialPathIsDeceivedThroughWiredPorts(): void
    {
        $clock = new MutableClock();
        $store = $this->store($clock);
        $s = $this->settings(array('enabled' => true, 'posture' => 'honeypot'));

        $server = array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/.env', 'REMOTE_ADDR' => '203.0.113.9');
        $evidence = RequestFactory::evidence($server, null, $s);
        $ctx = CoreEvaluator::contextFromEvidence($evidence);

        // FALLBACK position: is_404 true (WP genuinely 404'd), so /.env is sacrificial.
        $profile = (new WpSiteProfile(true))->toPolicyProfile('/.env');

        $engine = PolicyFactory::forPosition($s, 'fallback', array(
            'evaluator' => new FakeCoreEvaluator(),
            'store' => $store,
            'clock' => $clock,
            'ctx' => $ctx,
        ));

        $decision = $engine->evaluate($evidence, $profile);
        $this->assertSame(Decision::DECEIVE, $decision->action());
        $this->assertInstanceOf(FakeResponse::class, $decision->fakeHandle());
        $this->assertStringContainsString('APP_KEY=fake', $decision->fakeHandle()->body());

        // The pin was set by the engine through the real WpStateStore port (deception consistency).
        $this->assertNotNull($store->getPin('203.0.113.9'));

        // The executor emits the fake with the app-chosen status.
        $emitted = array();
        $halted = 0;
        $executor = new DecisionExecutor(
            static function (FakeResponse $f, $status) use (&$emitted) {
                $emitted[] = array('body' => $f->body(), 'status' => $status, 'ct' => $f->contentType());
            },
            static function () {
            },
            static function () use (&$halted) {
                $halted++;
            }
        );
        $this->assertTrue($executor->execute($decision, $evidence));
        $this->assertCount(1, $emitted);
        $this->assertStringContainsString('APP_KEY=fake', $emitted[0]['body']);
        $this->assertSame('text/plain; charset=UTF-8', $emitted[0]['ct'], 'Content-Type flows from the fake');
        $this->assertSame(1, $halted);
    }

    public function testScannerUaBlockedAtBeforePositionWafPosture(): void
    {
        $clock = new MutableClock();
        $store = $this->store($clock);
        $s = $this->settings(array('enabled' => true, 'posture' => 'WAF'));

        $server = array(
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/wp-admin/',
            'REMOTE_ADDR' => '203.0.113.9',
            'HTTP_USER_AGENT' => 'sqlmap/1.7',
        );
        $evidence = RequestFactory::evidence($server, null, $s);
        $ctx = CoreEvaluator::contextFromEvidence($evidence);
        // BEFORE position: is_404 unknown (null). /wp-admin/ is a reserved real route.
        $profile = (new WpSiteProfile(null))->toPolicyProfile('/wp-admin/');

        $engine = PolicyFactory::forPosition($s, 'before', array(
            'evaluator' => new FakeCoreEvaluator(),
            'store' => $store,
            'clock' => $clock,
            'ctx' => $ctx,
        ));

        $decision = $engine->evaluate($evidence, $profile);
        $this->assertSame(Decision::BLOCK, $decision->action());
        $this->assertSame(403, $decision->status());

        $blocked = array();
        $executor = new DecisionExecutor(
            static function () {
            },
            static function ($status) use (&$blocked) {
                $blocked[] = $status;
            },
            static function () {
            }
        );
        $this->assertTrue($executor->execute($decision, $evidence));
        $this->assertSame(array(403), $blocked);
    }

    public function testCleanRequestFallsThroughAsAllow(): void
    {
        $clock = new MutableClock();
        $store = $this->store($clock);
        $s = $this->settings(array('enabled' => true, 'posture' => 'WAF'));

        // A well-formed browser request to a real route with a clean classification.
        $server = array(
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/wp-login.php',
            'REMOTE_ADDR' => '203.0.113.9',
            'HTTP_USER_AGENT' => 'Mozilla/5.0',
            'HTTP_ACCEPT' => 'text/html',
            'HTTP_ACCEPT_LANGUAGE' => 'en',
            'HTTP_ACCEPT_ENCODING' => 'gzip',
        );
        $evidence = RequestFactory::evidence($server, null, $s);
        $ctx = CoreEvaluator::contextFromEvidence($evidence);
        $profile = (new WpSiteProfile(null))->toPolicyProfile('/wp-login.php');

        $engine = PolicyFactory::forPosition($s, 'before', array(
            'evaluator' => new FakeCoreEvaluator(\Funnypot\Verdict::CLEAN),
            'store' => $store,
            'clock' => $clock,
            'ctx' => $ctx,
        ));

        $decision = $engine->evaluate($evidence, $profile);
        $this->assertSame(Decision::ALLOW, $decision->action());
    }
}
