<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Report;

use Funnypot\Mainnet\Cache\Cache;
use Funnypot\Mainnet\CircuitBreaker;
use Funnypot\Mainnet\Report\Reporter;
use Funnypot\Mainnet\Report\ReportQueue;
use Funnypot\Mainnet\Transport\Transport;
use Funnypot\Policy\ReportIntent;
use Funnypot\WordPress\Settings;

/**
 * The WP adapter over the relocated mainnet-client reporter (design §4.9, M8). Named so it does NOT
 * shadow Funnypot\Mainnet\Reporter — it COMPOSES that reporter over a WpdbReportQueue + a WP transport.
 * The 4-layer suppression is the policy's; the reporter's transport guards (self-IP / public-IP-only /
 * dedup / daily cap) and the SF-6 outage-bounded drain (budget / 3-fail abort + shared mnc:breaker /
 * 429-class branch / re-queue + queue caps) are F's — D does not reimplement them. 7.3-clean.
 *
 * The enqueue signature matches the reporter EXACTLY: enqueue($ip, $comment, $categories='21') — the
 * comment-then-categories order is load-bearing (swapping them corrupts the feed).
 */
final class WpReporterBridge implements ReporterBridge
{
    /** @var Reporter */
    private $reporter;
    /** @var bool */
    private $active;

    /**
     * @param Settings      $s
     * @param ReportQueue   $queue     WpdbReportQueue in prod; a fake in tests
     * @param Transport     $transport WP wp_remote_post transport in prod; a fake in tests
     * @param Cache|null    $cache     backs the shared mnc:breaker marker (breaker off when null)
     * @param callable|null $clock     fn(): int epoch; defaults to time()
     */
    public function __construct(Settings $s, ReportQueue $queue, Transport $transport, $cache = null, $clock = null)
    {
        $this->active = $s->reportingActive();

        $breaker = null;
        if ($cache instanceof Cache) {
            // Shares the decision-N mnc:breaker marker with the reputation check/warmer path (N6).
            $breaker = new CircuitBreaker($cache, 5, 60, 21600, $clock);
        }

        $this->reporter = new Reporter(
            $queue,
            $transport,
            $s->mainnetBaseUrl(),
            $s->mainnetKey(),
            $s->selfIps(),
            $s->dailyCap(),
            24, // per-IP dedup window (hours)
            $breaker,
            $clock
        );
    }

    /** Map a policy ReportIntent onto enqueue(ip, comment, categories) in the correct arg order (M8). */
    public function enqueueIntent(ReportIntent $r)
    {
        $comment = $r->resultLabel();
        $categories = $r->categories() !== array() ? implode(',', $r->categories()) : '21';
        $signals = $r->signals() !== null ? $r->signals() : array();

        return $this->enqueue($r->ip(), $comment, $categories, $signals);
    }

    /**
     * @param string $ip
     * @param string $comment
     * @param string $categories
     * @param array  $signals
     * @return array {queued:bool, reason:string}
     */
    public function enqueue(string $ip, string $comment, string $categories = '21', array $signals = array())
    {
        // Belt-and-suspenders: the reporter is also key-gated, but skip the call entirely when off.
        if (!$this->active) {
            return array('queued' => false, 'reason' => 'reporting inactive');
        }

        return $this->reporter->enqueue($ip, $comment, $categories, $signals);
    }

    /** Drain the queue (WP-Cron / wp honeypot report-drain). Outage-bounded inside F's Reporter. */
    public function drain(int $limit = 200)
    {
        return $this->reporter->drain($limit);
    }

    public function queueCount()
    {
        return $this->reporter->queueCount();
    }
}
