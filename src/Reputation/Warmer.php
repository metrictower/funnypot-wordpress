<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Reputation;

use Funnypot\Mainnet\CircuitBreaker;
use Funnypot\WordPress\State\StateBackend;

/**
 * The SF-6 out-of-band reputation warmer. The interceptor enqueues uncached, OFF-mirror actor IPs
 * (bounded, non-blocking); a cron tick drains them through F's escalation check (which populates F's
 * verdict cache for the next request), breaker-guarded and bounded per tick — NEVER an inline
 * request-path check (M5). The escalation check is an injected callable so the warmer never hard-binds
 * F's final Client and stays unit-testable. 7.3-clean.
 */
final class Warmer
{
    const QUEUE_KEY = 'warm:queue';

    /** @var callable(string):void the escalation check, e.g. fn($ip) => $client->check($ip) */
    private $checkFn;
    /** @var StateBackend */
    private $backend;
    /** @var CircuitBreaker|null */
    private $breaker;
    /** @var int */
    private $queueCap;

    /**
     * @param callable          $checkFn  fn(string $ip): void — populates F's verdict cache
     * @param StateBackend      $backend  the bounded local queue store
     * @param CircuitBreaker|null $breaker shared mnc:breaker marker (skip the drain while OPEN)
     * @param int               $queueCap hard queue cap (oldest dropped first)
     */
    public function __construct(callable $checkFn, StateBackend $backend, $breaker = null, int $queueCap = 1000)
    {
        $this->checkFn = $checkFn;
        $this->backend = $backend;
        $this->breaker = $breaker;
        $this->queueCap = $queueCap;
    }

    /** Enqueue an uncached, off-mirror actor IP (local, non-blocking). */
    public function enqueue(string $ip)
    {
        if ($ip === '') {
            return;
        }
        $queue = $this->queue();
        if (in_array($ip, $queue, true)) {
            return; // already pending
        }
        $queue[] = $ip;
        while (count($queue) > $this->queueCap) {
            array_shift($queue); // oldest dropped first
        }
        $this->backend->set(self::QUEUE_KEY, $queue, 86400);
    }

    /**
     * Drain up to $limit IPs through the escalation check. Breaker-guarded + bounded per tick; a fault
     * on one IP never aborts the tick (fail-open).
     *
     * @param int $limit
     * @return array {checked:int, pending:int, skipped?:bool}
     */
    public function drain(int $limit)
    {
        if ($this->breaker !== null && !$this->breaker->allow()) {
            return array('checked' => 0, 'pending' => count($this->queue()), 'skipped' => true);
        }

        $queue = $this->queue();
        $checked = 0;
        while ($checked < $limit && $queue !== array()) {
            $ip = array_shift($queue);
            try {
                call_user_func($this->checkFn, $ip);
            } catch (\Throwable $ignored) {
                // a check fault must never abort the tick (fail-open)
            }
            $checked++;
        }
        $this->backend->set(self::QUEUE_KEY, array_values($queue), 86400);

        return array('checked' => $checked, 'pending' => count($queue));
    }

    public function pending()
    {
        return count($this->queue());
    }

    private function queue()
    {
        $q = $this->backend->get(self::QUEUE_KEY);

        return is_array($q) ? array_values($q) : array();
    }
}
