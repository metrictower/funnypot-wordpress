<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Rules;

use Funnypot\Core\Rules\HttpFetcher;
use Funnypot\Core\Rules\RulesUpdateException;

/**
 * An exec-free HttpFetcher over WordPress's HTTP API (wp_remote_get), for hosts where ext-curl is
 * unavailable or where the operator wants the fetch to honour WordPress's own HTTP config. It stands
 * in for core's CurlFetcher and holds the SAME anti-SSRF posture the HttpFetcher contract requires:
 *
 *   - HTTPS only; any other scheme is refused.
 *   - A pinned host allow-list (the GitHub release hosts) — never the request, never a fetched doc.
 *   - No auto-follow (redirection => 0); every redirect Location is re-validated against the
 *     allow-list before the next hop, with a bounded hop count.
 *   - A bounded response size and a timeout.
 *
 * Where the bytes came from is NOT the trust anchor — RulesUpdater's ed25519 + per-file sha256 +
 * array-literal verification is. This class only refuses the obvious footguns before the bytes ever
 * reach that verification. The wp_remote_get callable is injected so this is unit-testable. 7.3-clean.
 */
final class WpRemoteRulesFetcher implements HttpFetcher
{
    /** @var string[] lower-case hosts this fetcher will talk to */
    private $allowedHosts;

    /** @var int */
    private $maxBytes;

    /** @var int seconds */
    private $timeoutSeconds;

    /** @var int */
    private $maxRedirects;

    /** @var callable fn(string $url, array $args): array|WP_Error — wp_remote_get */
    private $getFn;

    /**
     * @param string[]      $allowedHosts
     * @param int           $maxBytes       response cap (the real release is ~6 MB)
     * @param int           $timeoutSeconds
     * @param int           $maxRedirects
     * @param callable|null $getFn          defaults to the real wp_remote_get
     */
    public function __construct(
        array $allowedHosts = array('github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com'),
        int $maxBytes = 33554432,
        int $timeoutSeconds = 30,
        int $maxRedirects = 5,
        $getFn = null
    ) {
        $this->allowedHosts = array_map('strtolower', $allowedHosts);
        $this->maxBytes = $maxBytes;
        $this->timeoutSeconds = $timeoutSeconds;
        $this->maxRedirects = $maxRedirects;
        $this->getFn = $getFn !== null ? $getFn : 'wp_remote_get';
    }

    public function get(string $url): string
    {
        $this->assertAllowed($url);

        $redirects = 0;
        while (true) {
            $response = call_user_func($this->getFn, $url, array(
                'timeout' => $this->timeoutSeconds,
                'redirection' => 0, // we follow manually so every hop is re-checked
                'limit_response_size' => $this->maxBytes,
                'sslverify' => true,
                'httpversion' => '1.1',
                'user-agent' => 'funnypot-rules-updater',
            ));

            if (is_object($response) && method_exists($response, 'get_error_message')) {
                throw new RulesUpdateException(
                    RulesUpdateException::REASON_FETCH_FAILED,
                    'wp_remote_get failed: ' . (string) $response->get_error_message()
                );
            }
            if (!is_array($response)) {
                throw new RulesUpdateException(RulesUpdateException::REASON_NO_TRANSPORT, 'wp_remote_get returned no response.');
            }

            $status = isset($response['response']['code']) ? (int) $response['response']['code'] : 0;

            if ($status >= 300 && $status < 400) {
                $location = $this->header($response, 'location');
                if ($location === '' || ++$redirects > $this->maxRedirects) {
                    throw new RulesUpdateException(RulesUpdateException::REASON_FETCH_FAILED, 'Too many/invalid redirects.');
                }
                $this->assertAllowed($location); // re-check EVERY hop against the allow-list
                $url = $location;
                continue;
            }

            if ($status !== 200) {
                throw new RulesUpdateException(RulesUpdateException::REASON_FETCH_FAILED, "GET returned HTTP {$status}.");
            }

            $body = isset($response['body']) ? (string) $response['body'] : '';
            if (strlen($body) > $this->maxBytes) {
                throw new RulesUpdateException(RulesUpdateException::REASON_FETCH_FAILED, 'Response exceeded the size cap.');
            }

            return $body;
        }
    }

    /** HTTPS-only + pinned host allow-list. A loopback/private/metadata host is refused by default. */
    private function assertAllowed(string $url): void
    {
        $parts = parse_url($url);
        if ($parts === false || ($parts['scheme'] ?? '') !== 'https') {
            throw new RulesUpdateException(RulesUpdateException::REASON_FETCH_FAILED, "Refusing non-HTTPS URL: {$url}");
        }
        $host = strtolower((string) ($parts['host'] ?? ''));
        if (!in_array($host, $this->allowedHosts, true)) {
            throw new RulesUpdateException(
                RulesUpdateException::REASON_FETCH_FAILED,
                "Host '{$host}' is not on the rules-update allow-list."
            );
        }
    }

    /**
     * Read a header case-insensitively from a wp_remote_get response. WP normally hands back a
     * CaseInsensitiveDictionary, but a lower-cased plain array is also accepted.
     */
    private function header(array $response, string $name): string
    {
        if (!isset($response['headers'])) {
            return '';
        }
        $name = strtolower($name);
        $headers = $response['headers'];

        if (is_array($headers)) {
            foreach ($headers as $k => $v) {
                if (strtolower((string) $k) === $name) {
                    return is_array($v) ? (string) reset($v) : (string) $v;
                }
            }

            return '';
        }
        if (is_object($headers) && method_exists($headers, 'getAll')) {
            foreach ($headers->getAll() as $k => $v) {
                if (strtolower((string) $k) === $name) {
                    return is_array($v) ? (string) reset($v) : (string) $v;
                }
            }
        }

        return '';
    }
}
