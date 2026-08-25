<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Geo;

use Funnypot\Mainnet\Transport\Transport;
use Funnypot\WordPress\Settings;
use Funnypot\WordPress\State\StateBackend;

/**
 * R2 local-GeoIP-DB refresh: a cron-driven, ETag/Last-Modified-conditional pull of the local GeoIP
 * dataset the WpGeoIp port reads, riding the SAME data-distribution/freshness seam as the O1 mirror.
 * Writes the DB file IN PLACE on a 200; a 304 refreshes only freshness. Inert unless country policy is
 * on. Fail-open: a failed/stale pull leaves the existing DB untouched and never throws — a missing DB
 * simply makes country() return null. NOT a request-path concern (request-time resolution is the local
 * read only). 7.3-clean.
 */
final class GeoIpRefresh
{
    const META_KEY = 'geoip:meta';

    /** @var Settings */
    private $settings;
    /** @var Transport */
    private $transport;
    /** @var callable(string):bool the file writer, fn(string $bytes): bool */
    private $writer;
    /** @var StateBackend */
    private $backend;
    /** @var string */
    private $dbUrl;
    /** @var callable():int */
    private $clock;

    /**
     * @param Settings      $s
     * @param Transport     $transport
     * @param callable      $writer   fn(string $bytes): bool — writes the DB file in place
     * @param StateBackend  $backend  stores the etag/last-modified freshness meta
     * @param string        $dbUrl    the DB-IP Lite dataset URL (a data-distribution concern)
     * @param callable|null $clock
     */
    public function __construct(Settings $s, Transport $transport, callable $writer, StateBackend $backend, string $dbUrl, $clock = null)
    {
        $this->settings = $s;
        $this->transport = $transport;
        $this->writer = $writer;
        $this->backend = $backend;
        $this->dbUrl = $dbUrl;
        $this->clock = $clock !== null ? $clock : 'time';
    }

    /**
     * @return array {refreshed:bool, reason:string}
     */
    public function refresh()
    {
        if ($this->settings->countryPosture() === Settings::COUNTRY_OFF) {
            return array('refreshed' => false, 'reason' => 'inactive');
        }

        $meta = $this->backend->get(self::META_KEY);
        $etag = is_array($meta) && isset($meta['etag']) ? (string) $meta['etag'] : '';
        $lastModified = is_array($meta) && isset($meta['last_modified']) ? (string) $meta['last_modified'] : '';

        $headers = array('Accept: application/octet-stream');
        if ($etag !== '') {
            $headers[] = 'If-None-Match: ' . $etag;
        }
        if ($lastModified !== '') {
            $headers[] = 'If-Modified-Since: ' . $lastModified;
        }

        try {
            $res = $this->transport->get($this->dbUrl, $headers);
        } catch (\Throwable $e) {
            return array('refreshed' => false, 'reason' => 'transport-error'); // fail-open
        }

        $status = isset($res['status']) ? (int) $res['status'] : 0;

        if ($status === 304) {
            $this->storeMeta($etag, $lastModified);

            return array('refreshed' => true, 'reason' => 'not-modified');
        }

        if ($status === 200) {
            $body = isset($res['body']) ? (string) $res['body'] : '';
            if ($body === '') {
                return array('refreshed' => false, 'reason' => 'empty-body');
            }
            $ok = false;
            try {
                $ok = (bool) call_user_func($this->writer, $body);
            } catch (\Throwable $e) {
                $ok = false;
            }
            if (!$ok) {
                return array('refreshed' => false, 'reason' => 'write-failed'); // leave existing DB
            }
            $this->storeMeta($this->headerValue($res, 'etag'), $this->headerValue($res, 'last-modified'));

            return array('refreshed' => true, 'reason' => 'refreshed');
        }

        return array('refreshed' => false, 'reason' => 'status-' . $status); // fail-open, existing DB kept
    }

    private function storeMeta($etag, $lastModified)
    {
        $this->backend->set(self::META_KEY, array(
            'etag' => (string) $etag,
            'last_modified' => (string) $lastModified,
            'generated_at' => (int) call_user_func($this->clock),
        ), 0);
    }

    private function headerValue(array $res, $name)
    {
        if (!isset($res['headers']) || !is_array($res['headers'])) {
            return '';
        }
        $name = strtolower($name);

        return isset($res['headers'][$name]) ? trim((string) $res['headers'][$name], '"') : '';
    }
}
