<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Fakes;

use Funnypot\Core\BotSignalSet;
use Funnypot\Core\Contracts\Evaluator;
use Funnypot\Core\Detection;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\SynthesizedResponse;
use Funnypot\Core\Verdict;

/**
 * A deterministic core Evaluator (Funnypot\Core\Contracts\Evaluator) for testing the CoreEvaluator bridge
 * and the wired ports without core's bundled rule artifact.
 */
final class FakeCoreEvaluator implements Evaluator
{
    /** @var string */
    public $classification;
    /** @var SynthesizedResponse|null */
    public $synthResponse;

    public function __construct(string $classification = Verdict::SCANNER_PROBE, $synthResponse = null)
    {
        $this->classification = $classification;
        $this->synthResponse = $synthResponse !== null
            ? $synthResponse
            : new SynthesizedResponse(200, array('Content-Type' => 'text/plain; charset=UTF-8'), "APP_KEY=fake\nDB_PASSWORD=fake\n", Detection::none());
    }

    public function classify(RequestContext $r, SiteProfile $profile): Verdict
    {
        $detection = new Detection(true, array(), 'cluster-x', 'high');
        $handle = FakeHandle::route($r->method . ' ' . $r->path);

        return new Verdict($this->classification, $detection, 'high', 0, BotSignalSet::empty(), $handle);
    }

    public function synthesize(Verdict $verdict, SiteProfile $profile, string $seed): ?SynthesizedResponse
    {
        return $this->synthResponse;
    }
}
