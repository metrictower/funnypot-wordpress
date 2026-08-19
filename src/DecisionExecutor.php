<?php

declare(strict_types=1);

namespace Honeypot\WP;

use Funnypot\Policy\Decision;
use Funnypot\Policy\Port\Clock;
use Funnypot\Policy\RequestEvidence;
use Honeypot\WP\Http\ResponseEmitter;
use Honeypot\WP\Log\HitLogWriter;
use Honeypot\WP\Log\NullHitLogWriter;
use Honeypot\WP\Report\ReporterBridge;

/**
 * Turns the policy's pure-data Decision into a WordPress effect (design §4.5) — the one place D does
 * so. All seams are injected so it is unit-testable with no real side effects. Status is taken from
 * the Decision, NEVER invented (invariant §6.3). The deception-consistency pin is set by the policy
 * engine itself through the injected StateStore, so D does not re-set it here. 7.3-clean.
 */
final class DecisionExecutor
{
    /** @var callable(\Funnypot\Policy\FakeResponse,?int):void */
    private $fakeEmitter;
    /** @var callable(?int):void */
    private $blockEmitter;
    /** @var callable():void */
    private $halt;
    /** @var HitLogWriter */
    private $log;
    /** @var ReporterBridge|null */
    private $reporter;
    /** @var Clock */
    private $clock;

    /**
     * @param callable|null       $fakeEmitter  fn(FakeResponse $f, ?int $status): void
     * @param callable|null       $blockEmitter fn(?int $status): void
     * @param callable|null       $halt         fn(): void — default exit
     * @param HitLogWriter|null   $log
     * @param ReporterBridge|null $reporter
     * @param Clock|null          $clock
     */
    public function __construct($fakeEmitter = null, $blockEmitter = null, $halt = null, $log = null, $reporter = null, $clock = null)
    {
        $this->fakeEmitter = $fakeEmitter !== null ? $fakeEmitter : array(ResponseEmitter::class, 'emit');
        $this->blockEmitter = $blockEmitter !== null ? $blockEmitter : array(ResponseEmitter::class, 'emitBlock');
        $this->halt = $halt !== null ? $halt : static function () {
            exit;
        };
        $this->log = $log !== null ? $log : new NullHitLogWriter();
        $this->reporter = $reporter;
        $this->clock = $clock !== null ? $clock : new WpClock();
    }

    /**
     * Perform the effect of a Decision at the given position; returns true iff it emitted + halted.
     *
     * @param Decision        $d
     * @param RequestEvidence $e
     * @return bool
     */
    public function execute(Decision $d, RequestEvidence $e)
    {
        $action = $d->action();

        if ($action === Decision::ALLOW) {
            return false; // WordPress proceeds untouched
        }

        // Record + report side-channels first (local, fast) so they run before any halt.
        $this->recordHit($d, $e);
        $this->maybeReport($d);

        if ($action === Decision::LOG) {
            return false; // shadow / below-block: no visible response effect
        }

        if ($action === Decision::DECEIVE) {
            $fake = $d->fakeHandle();
            if ($fake === null) {
                return false; // nothing to emit -> degrade to letting WP serve its 404
            }
            call_user_func($this->fakeEmitter, $fake, $d->status());
            call_user_func($this->halt);

            return true;
        }

        if ($action === Decision::BLOCK) {
            $status = $d->status() !== null ? $d->status() : 403;
            call_user_func($this->blockEmitter, $status);
            call_user_func($this->halt);

            return true;
        }

        return false;
    }

    private function recordHit(Decision $d, RequestEvidence $e)
    {
        try {
            $this->log->record(array(
                'ts' => $this->clock->now(),
                'ip' => $e->ip(),
                'method' => $e->method(),
                'path' => $e->path(),
                'action' => $d->action(),
                'reason' => $d->reason(),
                'status' => $d->status() !== null ? $d->status() : 0,
            ));
        } catch (\Throwable $ignored) {
            // a hit-log fault must never affect the response
        }
    }

    private function maybeReport(Decision $d)
    {
        $intent = $d->report();
        if ($intent === null || $this->reporter === null) {
            return;
        }
        try {
            $this->reporter->enqueueIntent($intent);
        } catch (\Throwable $ignored) {
            // a reporter fault must never affect the response (never a blocking POST here anyway)
        }
    }
}
