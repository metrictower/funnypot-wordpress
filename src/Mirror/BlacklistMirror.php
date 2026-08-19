<?php

declare(strict_types=1);

namespace Honeypot\WP\Mirror;

use Funnypot\Mainnet\CircuitBreaker;
use Funnypot\Mainnet\Transport\Transport;
use Honeypot\WP\Settings;
use Honeypot\WP\WpStateStore;

/**
 * O1 local-mirror-lite: a cron-driven, ETag/304-conditional pull of A1's THIN blacklist artifact
 * (GET {base_url}/v1/blacklist?variant=thin&format=json) into WpStateStore — the PRIMARY request-path
 * fresh-read that keeps origin QPS off per-IP checks. Breaker-guarded (a mainnet outage skips the pull
 * and the mirror simply ages) and fail-open (a stale/empty mirror never blocks). Inert unless checking
 * AND the mirror are enabled with a key. Rows are stored AS-IS — a row's key may be a CIDR (IPv4 /24,
 * IPv6 /64) or an ASN (P2/Q2); the request-path match is by containment (funnypot-policy's Net), never
 * reimplemented here. 7.3-clean.
 */
final class BlacklistMirror
{
    /** @var Settings */
    private $settings;
    /** @var WpStateStore */
    private $store;
    /** @var Transport */
    private $transport;
    /** @var CircuitBreaker|null */
    private $breaker;
    /** @var callable():int */
    private $clock;

    public function __construct(Settings $s, WpStateStore $store, Transport $transport, $breaker = null, $clock = null)
    {
        $this->settings = $s;
        $this->store = $store;
        $this->transport = $transport;
        $this->breaker = $breaker;
        $this->clock = $clock !== null ? $clock : 'time';
    }

    /**
     * Conditionally pull the thin artifact. Returns a status summary for the CLI/cron.
     *
     * @return array {pulled:bool, reason:string, count?:int}
     */
    public function pull()
    {
        if (!$this->settings->checkActive() || !$this->settings->mirrorEnabled()) {
            return array('pulled' => false, 'reason' => 'inactive');
        }
        if ($this->breaker !== null && !$this->breaker->allow()) {
            return array('pulled' => false, 'reason' => 'breaker-open'); // outage -> skip, mirror ages
        }

        $meta = $this->store->mirrorMeta();
        $etag = is_array($meta) && isset($meta['etag']) ? (string) $meta['etag'] : '';

        $url = rtrim($this->settings->mainnetBaseUrl(), '/') . '/v1/blacklist?variant=thin&format=json';
        $headers = array('Key: ' . $this->settings->mainnetKey(), 'Accept: application/json');
        if ($etag !== '') {
            $headers[] = 'If-None-Match: ' . $etag;
        }

        try {
            $res = $this->transport->get($url, $headers);
        } catch (\Throwable $e) {
            return array('pulled' => false, 'reason' => 'transport-error');
        }

        $status = isset($res['status']) ? (int) $res['status'] : 0;
        $ttl = max($this->settings->mirrorPullIntervalSecs() * 3, 3600);

        if ($status === 304) {
            $this->store->touchMirror($this->now(), $ttl);
            if ($this->breaker !== null) {
                $this->breaker->recordSuccess();
            }

            return array('pulled' => true, 'reason' => 'not-modified');
        }

        if ($status === 200) {
            $body = isset($res['body']) ? (string) $res['body'] : '';
            $json = json_decode($body, true);
            $rows = (is_array($json) && isset($json['data']) && is_array($json['data'])) ? $json['data'] : array();
            $rows = $this->normalizeRows($rows);
            $newEtag = $this->headerValue($res, 'etag');
            $this->store->putMirror($rows, $newEtag, $this->now(), $ttl);
            if ($this->breaker !== null) {
                $this->breaker->recordSuccess();
            }

            return array('pulled' => true, 'reason' => 'refreshed', 'count' => count($rows));
        }

        // 0 / 5xx / 401/403 -> transport-class; the mirror simply ages (fail-open).
        if (($status === 0 || $status >= 500 || $status === 401 || $status === 403) && $this->breaker !== null) {
            $this->breaker->recordTransportFailure();
        }

        return array('pulled' => false, 'reason' => 'status-' . $status);
    }

    /** Normalize each thin row to carry an 'ip' key (from ip / score_key / cidr). */
    private function normalizeRows(array $rows)
    {
        $out = array();
        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }
            $key = null;
            foreach (array('ip', 'score_key', 'cidr') as $k) {
                if (isset($row[$k]) && (string) $row[$k] !== '') {
                    $key = (string) $row[$k];
                    break;
                }
            }
            if ($key === null) {
                continue;
            }
            $row['ip'] = $key;
            $out[] = $row;
        }

        return $out;
    }

    private function headerValue(array $res, $name)
    {
        if (!isset($res['headers']) || !is_array($res['headers'])) {
            return '';
        }
        $name = strtolower($name);

        return isset($res['headers'][$name]) ? trim((string) $res['headers'][$name], '"') : '';
    }

    private function now()
    {
        return (int) call_user_func($this->clock);
    }
}
