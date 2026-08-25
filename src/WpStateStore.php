<?php

declare(strict_types=1);

namespace Funnypot\WordPress;

use Funnypot\Policy\ActorFacts;
use Funnypot\Policy\AggScore;
use Funnypot\Policy\Net;
use Funnypot\Policy\Pin;
use Funnypot\Policy\Port\Clock;
use Funnypot\Policy\Port\StateStoreInterface;
use Funnypot\Policy\ReputationVerdict;
use Funnypot\Policy\RuleState;
use Funnypot\WordPress\State\FileBackend;
use Funnypot\WordPress\State\ObjectCacheBackend;
use Funnypot\WordPress\State\StateBackend;

/**
 * The one persistence seam the policy engine reads/writes through (design §4.6). D maps each port
 * method onto the selected RS-10 StateBackend (object-cache or file); it authors NO pin/TTL,
 * learn-then-enforce, or suppression logic — all of that lives in the policy. Also carries the O1
 * mirror write methods (putMirror/mirrorMeta) the BlacklistMirror cron uses; those are NOT port
 * methods (the engine only reads mirrorVerdict). 7.3-clean.
 */
final class WpStateStore implements StateStoreInterface
{
    /** @var StateBackend */
    private $backend;
    /** @var Clock */
    private $clock;

    public function __construct(StateBackend $backend, Clock $clock)
    {
        $this->backend = $backend;
        $this->clock = $clock;
    }

    /**
     * Build the store with the RS-10 backend the settings select. Default (object-cache) never writes
     * into the plugin dir; the file backend is opt-in for hosts without a persistent object cache.
     *
     * @param Settings    $s
     * @param Clock       $clock
     * @param string|null $fileDir the plugin-owned state dir for the file backend
     * @return self
     */
    public static function forSettings(Settings $s, Clock $clock, $fileDir = null)
    {
        if ($s->localStateBackend() === Settings::BACKEND_FILE) {
            $dir = $fileDir !== null ? $fileDir : sys_get_temp_dir() . '/honeypot-wp-state';
            $clockFn = static function () use ($clock) {
                return $clock->now();
            };
            $backend = new FileBackend($dir, $clockFn);
        } else {
            $backend = new ObjectCacheBackend();
        }

        return new self($backend, $clock);
    }

    /** The active backend (so the mirror/warmer can share it). */
    public function backend()
    {
        return $this->backend;
    }

    // --- deception-consistency pins + local blocklist -------------------------------------------

    public function getPin(string $ip)
    {
        $row = $this->backend->get('pin:' . $ip);
        if (!is_array($row) || !isset($row['action'], $row['seed'], $row['expires_at'])) {
            return null;
        }
        if ((int) $row['expires_at'] <= $this->now()) {
            return null;
        }

        return new Pin((string) $row['action'], (string) $row['seed'], (int) $row['expires_at']);
    }

    public function setPin(string $ip, string $action, string $seed, int $ttlSeconds)
    {
        $expiresAt = $this->now() + $ttlSeconds;
        $this->backend->set('pin:' . $ip, array(
            'action' => $action,
            'seed' => $seed,
            'expires_at' => $expiresAt,
        ), $ttlSeconds);
    }

    public function isBlocked(string $ip)
    {
        return $this->backend->get('block:' . $ip) !== null;
    }

    /** Add a local blocklist entry (not a port method; used by the CLI / admin). */
    public function block(string $ip, int $ttlSeconds)
    {
        $this->backend->set('block:' . $ip, 1, $ttlSeconds);
    }

    // --- fleet-read: local blacklist mirror (O1) ------------------------------------------------

    public function mirrorVerdict(string $ip)
    {
        $rows = $this->backend->get('mirror:rows');
        if (!is_array($rows) || $rows === array()) {
            return null;
        }

        $best = null;
        $bestLen = -1;
        foreach ($rows as $row) {
            if (!is_array($row) || !isset($row['ip'])) {
                continue;
            }
            $len = $this->rowMatchLength((string) $row['ip'], $ip);
            if ($len > $bestLen) {
                $bestLen = $len;
                $best = $row;
            }
        }
        if ($best === null) {
            return null;
        }
        if (isset($best['expires_at']) && $best['expires_at'] !== null && (int) $best['expires_at'] <= $this->now()) {
            return null; // an expired mirror row covers nothing
        }

        $verdict = isset($best['verdict']) ? (string) $best['verdict'] : ReputationVerdict::VERDICT_UNKNOWN;
        $score = isset($best['score']) && $best['score'] !== null ? (int) $best['score'] : null;
        $usageType = isset($best['usage_type']) && $best['usage_type'] !== null ? (string) $best['usage_type'] : null;

        return new ReputationVerdict($verdict, $score, ReputationVerdict::SOURCE_MIRROR, $usageType);
    }

    /**
     * Store a freshly pulled thin blacklist artifact (O1). NOT a port method — the BlacklistMirror cron
     * calls it. Rows are stored as-is; the request-path match is by containment (funnypot-policy's Net).
     */
    public function putMirror(array $rows, string $etag, int $generatedAt, int $ttlSeconds)
    {
        $this->backend->set('mirror:rows', array_values($rows), $ttlSeconds);
        $this->backend->set('mirror:meta', array(
            'etag' => $etag,
            'generated_at' => $generatedAt,
            'count' => count($rows),
        ), $ttlSeconds);
    }

    /** {etag, generated_at, count} for the conditional pull. NOT a port method. */
    public function mirrorMeta()
    {
        $meta = $this->backend->get('mirror:meta');

        return is_array($meta) ? $meta : null;
    }

    /** Refresh only the freshness timestamp on a 304 (no re-download). NOT a port method. */
    public function touchMirror(int $generatedAt, int $ttlSeconds)
    {
        $meta = $this->mirrorMeta();
        if ($meta === null) {
            return;
        }
        $meta['generated_at'] = $generatedAt;
        $this->backend->set('mirror:meta', $meta, $ttlSeconds);
        $rows = $this->backend->get('mirror:rows');
        if (is_array($rows)) {
            $this->backend->set('mirror:rows', $rows, $ttlSeconds);
        }
    }

    // --- learn-then-enforce per-rule state ------------------------------------------------------

    public function ruleState(string $ruleId)
    {
        $row = $this->backend->get('rule:' . $ruleId);
        if (!is_array($row)) {
            return new RuleState(RuleState::SHADOW, $this->now(), 0);
        }

        return new RuleState(
            isset($row['phase']) ? (string) $row['phase'] : RuleState::SHADOW,
            isset($row['since']) ? (int) $row['since'] : 0,
            isset($row['count']) ? (int) $row['count'] : 0,
            isset($row['exclusions']) && is_array($row['exclusions']) ? $row['exclusions'] : array(),
            isset($row['human_approved']) ? (bool) $row['human_approved'] : false
        );
    }

    public function putRuleState(string $ruleId, RuleState $s)
    {
        $this->backend->set('rule:' . $ruleId, array(
            'phase' => $s->phase(),
            'since' => $s->since(),
            'count' => $s->count(),
            'exclusions' => $s->exclusions(),
            'human_approved' => $s->humanApproved(),
        ), 0);
    }

    public function bumpRuleEvaluated(string $ruleId, int $n = 1)
    {
        $s = $this->ruleState($ruleId);
        $this->backend->set('rule:' . $ruleId, array(
            'phase' => $s->phase(),
            'since' => $s->since(),
            'count' => $s->count() + $n,
            'exclusions' => $s->exclusions(),
            'human_approved' => $s->humanApproved(),
        ), 0);
    }

    // --- suppression ledger + per-actor counters ------------------------------------------------

    public function seenVerdict(string $dedupKey, int $ttlSeconds)
    {
        if ($this->backend->get('seen:' . $dedupKey) !== null) {
            return true;
        }
        $this->backend->set('seen:' . $dedupKey, 1, $ttlSeconds);

        return false;
    }

    public function incrAlertCount(string $ip, int $windowSeconds)
    {
        return $this->incr('alert:' . $ip, $windowSeconds);
    }

    public function bufferReport(string $groupKey, array $report, int $ttlSeconds)
    {
        $buffers = $this->backend->get('report_buffers');
        if (!is_array($buffers)) {
            $buffers = array();
        }
        if (!isset($buffers[$groupKey]) || !is_array($buffers[$groupKey])) {
            $buffers[$groupKey] = array();
        }
        $buffers[$groupKey][] = $report;
        $this->backend->set('report_buffers', $buffers, $ttlSeconds);

        return count($buffers[$groupKey]);
    }

    public function takeReportBuffer()
    {
        $buffers = $this->backend->get('report_buffers');
        $this->backend->delete('report_buffers');

        return is_array($buffers) ? $buffers : array();
    }

    public function aggregateScore(string $scoreKey, int $windowDays)
    {
        $row = $this->backend->get('agg:' . $scoreKey);
        if (!is_array($row)) {
            return new AggScore(array(), 0);
        }
        $sources = isset($row['sources']) && is_array($row['sources']) ? $row['sources'] : array();
        $total = isset($row['total']) ? (int) $row['total'] : 0;

        return new AggScore($sources, $total);
    }

    public function decayScore(string $key, int $inc, int $baseTtlSeconds, int $capTtlSeconds)
    {
        $now = $this->now();
        $row = $this->backend->get('score:' . $key);
        $value = 0.0;
        if (is_array($row) && isset($row['v'], $row['t'])) {
            $elapsed = $now - (int) $row['t'];
            if ($elapsed < 0) {
                $elapsed = 0;
            }
            if ($capTtlSeconds > 0 && $elapsed >= $capTtlSeconds) {
                $value = 0.0; // fully decayed past the cap
            } elseif ($baseTtlSeconds > 0) {
                $value = (float) $row['v'] * exp(-$elapsed / $baseTtlSeconds);
            } else {
                $value = (float) $row['v'];
            }
        }
        $value += $inc;
        $this->backend->set('score:' . $key, array('v' => $value, 't' => $now), $capTtlSeconds > 0 ? $capTtlSeconds : 0);

        return (int) round($value);
    }

    public function actorFacts(string $ip)
    {
        $row = $this->backend->get('facts:' . $ip);
        if (!is_array($row)) {
            return new ActorFacts(false, false, 0, 0);
        }

        return new ActorFacts(
            isset($row['auth_session']) ? (bool) $row['auth_session'] : false,
            isset($row['loads_assets']) ? (bool) $row['loads_assets'] : false,
            isset($row['matches_30d']) ? (int) $row['matches_30d'] : 0,
            isset($row['first_seen']) ? (int) $row['first_seen'] : 0
        );
    }

    public function incr(string $counterKey, int $windowSeconds)
    {
        $current = $this->backend->get('ctr:' . $counterKey);
        $next = (is_int($current) || is_numeric($current)) ? ((int) $current) + 1 : 1;
        $this->backend->set('ctr:' . $counterKey, $next, $windowSeconds);

        return $next;
    }

    // --- helpers --------------------------------------------------------------------------------

    /** Most-specific match length for a stored mirror row key against the visitor IP (Q4). */
    private function rowMatchLength(string $rowIp, string $ip)
    {
        if ($rowIp === $ip) {
            return PHP_INT_MAX; // exact wins
        }
        // IPv6 normalisation to the /64 score_key before comparison (P2), the policy's helper.
        $norm = Net::normaliseV6($ip);
        if ($rowIp === $norm) {
            return PHP_INT_MAX;
        }
        if (strpos($rowIp, '/') !== false) {
            return Net::containment($rowIp, $ip);
        }

        return -1; // a bare non-matching IP (or an ASN row we cannot resolve at this seam)
    }

    private function now()
    {
        return $this->clock->now();
    }
}
