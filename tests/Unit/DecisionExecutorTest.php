<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\Policy\Decision;
use Funnypot\Policy\FakeResponse;
use Funnypot\Policy\ReportIntent;
use Funnypot\Policy\RequestEvidence;
use Funnypot\WordPress\DecisionExecutor;
use Funnypot\WordPress\Log\HitLogWriter;
use Funnypot\WordPress\Report\ReporterBridge;

final class DecisionExecutorTest extends TestCase
{
    private $emitted;
    private $blocked;
    private $halted;
    private $rows;
    private $reported;

    private function executor()
    {
        $this->emitted = array();
        $this->blocked = array();
        $this->halted = 0;
        $this->rows = array();
        $this->reported = array();

        $self = $this;
        $fakeEmitter = static function (FakeResponse $f, $status) use ($self) {
            $self->emitted[] = array('fake' => $f, 'status' => $status);
        };
        $blockEmitter = static function ($status) use ($self) {
            $self->blocked[] = $status;
        };
        $halt = static function () use ($self) {
            $self->halted++;
        };
        $log = new class($this->rows) implements HitLogWriter {
            private $rowsRef;
            public function __construct(&$rowsRef)
            {
                $this->rowsRef = &$rowsRef;
            }
            public function record(array $row)
            {
                $this->rowsRef[] = $row;
            }
        };
        $reporter = new class($this->reported) implements ReporterBridge {
            private $ref;
            public function __construct(&$ref)
            {
                $this->ref = &$ref;
            }
            public function enqueueIntent(ReportIntent $r)
            {
                $this->ref[] = $r;
            }
        };

        return new DecisionExecutor($fakeEmitter, $blockEmitter, $halt, $log, $reporter);
    }

    private function evidence()
    {
        return new RequestEvidence('GET', '/.env', array(), array(), array(), '203.0.113.9');
    }

    private function fake()
    {
        return new FakeResponse(200, array('X-Test' => '1'), 'FAKE-BODY', 'text/plain');
    }

    public function testAllowDoesNothing(): void
    {
        $exec = $this->executor();
        $emitted = $exec->execute(Decision::allow(), $this->evidence());
        $this->assertFalse($emitted);
        $this->assertCount(0, $this->emitted);
        $this->assertCount(0, $this->rows);
        $this->assertSame(0, $this->halted);
    }

    public function testLogWritesRowNoEmit(): void
    {
        $exec = $this->executor();
        $emitted = $exec->execute(Decision::log('shadow'), $this->evidence());
        $this->assertFalse($emitted);
        $this->assertCount(1, $this->rows);
        $this->assertSame('log', $this->rows[0]['action']);
        $this->assertSame('shadow', $this->rows[0]['reason']);
        $this->assertCount(0, $this->emitted);
        $this->assertSame(0, $this->halted);
    }

    public function testDeceiveEmitsFakeWithDecisionStatusThenHalts(): void
    {
        $exec = $this->executor();
        $decision = Decision::deceive($this->fake(), 3600, 'sacrificial-path');
        $emitted = $exec->execute($decision, $this->evidence());

        $this->assertTrue($emitted);
        $this->assertCount(1, $this->emitted);
        $this->assertSame('FAKE-BODY', $this->emitted[0]['fake']->body());
        $this->assertSame(200, $this->emitted[0]['status'], 'status is taken from the Decision');
        $this->assertSame(1, $this->halted);
        $this->assertSame('deceive', $this->rows[0]['action']);
    }

    public function testBlockEmits403ThenHalts(): void
    {
        $exec = $this->executor();
        $emitted = $exec->execute(Decision::block(403, 'reputation-block'), $this->evidence());

        $this->assertTrue($emitted);
        $this->assertSame(array(403), $this->blocked);
        $this->assertSame(1, $this->halted);
        $this->assertCount(0, $this->emitted);
        $this->assertSame('block', $this->rows[0]['action']);
    }

    public function testReportIntentIsEnqueuedOnce(): void
    {
        $exec = $this->executor();
        $intent = new ReportIntent('203.0.113.9', 'attack-class', 'honeypot', 200, array('bad-bot'), 'dedup1');
        $decision = Decision::block(403, 'attack-class')->withReport($intent);

        $exec->execute($decision, $this->evidence());
        $this->assertCount(1, $this->reported);
        $this->assertSame('203.0.113.9', $this->reported[0]->ip());
    }

    public function testThrowingReporterDoesNotBubble(): void
    {
        $self = $this;
        $throwingReporter = new class implements ReporterBridge {
            public function enqueueIntent(ReportIntent $r)
            {
                throw new \RuntimeException('reporter down');
            }
        };
        $exec = new DecisionExecutor(
            static function () use ($self) {
                $self->emitted[] = true;
            },
            static function () {
            },
            static function () use ($self) {
                $self->halted++;
            },
            null,
            $throwingReporter
        );
        $this->emitted = array();
        $this->halted = 0;

        $intent = new ReportIntent('203.0.113.9', 'attack-class', 'honeypot', 200, array('bad-bot'), 'dk');
        $decision = Decision::deceive($this->fake(), null, 'sacrificial-path')->withReport($intent);

        // Must not throw; emit + halt still happen.
        $emitted = $exec->execute($decision, $this->evidence());
        $this->assertTrue($emitted);
        $this->assertSame(1, $this->halted);
    }
}
