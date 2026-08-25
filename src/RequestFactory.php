<?php

declare(strict_types=1);

namespace Funnypot\WordPress;

use Funnypot\Policy\Net;
use Funnypot\Policy\RequestEvidence;

/**
 * Builds the policy's neutral RequestEvidence from WP superglobals (design §4.4). Takes $server as an
 * array (injected, not the superglobal) so it is unit-testable. NEVER reflects the raw body — only a
 * body-SHAPE descriptor, so nothing here can carry an attacker payload verbatim into a log/report
 * (OAST hygiene). The resolved client IP is the policy's actor id. 7.3-clean.
 */
final class RequestFactory
{
    /**
     * @param array       $server  a $_SERVER-shaped array
     * @param string|null $rawBody the raw request body (used ONLY for its shape, never reflected)
     * @param Settings    $s
     * @return RequestEvidence
     */
    public static function evidence(array $server, $rawBody, Settings $s)
    {
        $method = isset($server['REQUEST_METHOD']) ? strtoupper((string) $server['REQUEST_METHOD']) : 'GET';
        $target = isset($server['REQUEST_URI']) ? (string) $server['REQUEST_URI'] : '/';

        $path = $target;
        $queryString = isset($server['QUERY_STRING']) ? (string) $server['QUERY_STRING'] : '';
        $qpos = strpos($target, '?');
        if ($qpos !== false) {
            $path = substr($target, 0, $qpos);
            if ($queryString === '') {
                $queryString = substr($target, $qpos + 1);
            }
        }
        if ($path === '') {
            $path = '/';
        }

        $query = array();
        if ($queryString !== '') {
            parse_str($queryString, $query);
        }

        $headers = self::headers($server);
        $bodyShape = self::bodyShape($rawBody, $headers);
        $ip = self::clientIp($server, $s);

        return new RequestEvidence($method, $path, $query, $headers, $bodyShape, $ip);
    }

    /**
     * The coarsened real client IP (the actor id). Defaults to REMOTE_ADDR (the socket peer);
     * X-Forwarded-For is consulted ONLY when REMOTE_ADDR is inside a configured trusted-proxy CIDR —
     * never the spoofable raw header (D7, a v1 requirement).
     *
     * @param array    $server
     * @param Settings $s
     * @return string
     */
    public static function clientIp(array $server, Settings $s)
    {
        $remote = isset($server['REMOTE_ADDR']) ? trim((string) $server['REMOTE_ADDR']) : '';
        if ($remote === '') {
            return '';
        }

        $proxies = $s->trustedProxies();
        if ($proxies === array() || !self::peerIsTrusted($remote, $proxies)) {
            return $remote; // no trusted proxy in front -> the socket peer IS the client
        }

        $xff = isset($server['HTTP_X_FORWARDED_FOR']) ? (string) $server['HTTP_X_FORWARDED_FOR'] : '';
        if ($xff === '') {
            return $remote;
        }
        // Leftmost entry is the claimed original client; trust it only because a trusted proxy set it.
        $parts = explode(',', $xff);
        $candidate = trim($parts[0]);
        if ($candidate !== '' && filter_var($candidate, FILTER_VALIDATE_IP) !== false) {
            return $candidate;
        }

        return $remote;
    }

    // ---------------------------------------------------------------------------------------------

    private static function peerIsTrusted($remote, array $proxies)
    {
        foreach ($proxies as $cidr) {
            $cidr = (string) $cidr;
            if ($cidr === '') {
                continue;
            }
            if (strpos($cidr, '/') === false) {
                if ($cidr === $remote) {
                    return true;
                }
                continue;
            }
            if (Net::contains($cidr, $remote)) {
                return true;
            }
        }

        return false;
    }

    /** Extract request headers (lower-cased dashed names) from a $_SERVER-shaped array. */
    private static function headers(array $server)
    {
        $headers = array();
        foreach ($server as $key => $value) {
            $key = (string) $key;
            if (strncmp($key, 'HTTP_', 5) === 0) {
                $name = strtolower(str_replace('_', '-', substr($key, 5)));
                $headers[$name] = (string) $value;
            }
        }
        if (isset($server['CONTENT_TYPE'])) {
            $headers['content-type'] = (string) $server['CONTENT_TYPE'];
        }
        if (isset($server['CONTENT_LENGTH'])) {
            $headers['content-length'] = (string) $server['CONTENT_LENGTH'];
        }

        return $headers;
    }

    /** Body SHAPE only — never the bytes. */
    private static function bodyShape($rawBody, array $headers)
    {
        $len = ($rawBody === null) ? 0 : strlen((string) $rawBody);
        $contentType = isset($headers['content-type']) ? $headers['content-type'] : '';

        return array(
            'present' => $len > 0,
            'length' => $len,
            'content_type' => $contentType,
        );
    }
}
