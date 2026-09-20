<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Fakes;

use Funnypot\Core\Rules\RulesStatus;
use Funnypot\Core\Rules\UpdateResult;

/**
 * A test double for core's RulesUpdater exposing just the two methods RulesAutoUpdate calls, so the
 * result-translation + fail-closed wiring can be asserted with canned UpdateResults (the exhaustive
 * crypto tests live in funnypot-core). `update()` can also be made to throw, to exercise the cron
 * handler's try/catch around the pre-`try` ensureDir throw on a read-only data dir.
 */
final class FakeRulesUpdater
{
    /** @var UpdateResult|null */
    private $result;
    /** @var \Throwable|null */
    private $throw;
    /** @var RulesStatus|null */
    private $status;
    /** @var int */
    public $updateCalls = 0;

    public function __construct(?UpdateResult $result = null, ?\Throwable $throw = null, ?RulesStatus $status = null)
    {
        $this->result = $result;
        $this->throw = $throw;
        $this->status = $status;
    }

    public function update(): UpdateResult
    {
        $this->updateCalls++;
        if ($this->throw !== null) {
            throw $this->throw;
        }

        return $this->result ?? UpdateResult::noop(null);
    }

    public function status(): RulesStatus
    {
        return $this->status ?? new RulesStatus('bundled', null, null, null, null, array(), array());
    }
}
