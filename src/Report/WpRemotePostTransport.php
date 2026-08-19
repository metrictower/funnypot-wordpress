<?php

declare(strict_types=1);

namespace Honeypot\WP\Report;

use Funnypot\Mainnet\Transport\Transport;

/**
 * A mainnet-client Transport over WordPress's HTTP API (wp_remote_get / wp_remote_post). Returns the
 * package's uniform {status, body, headers} shape; a transport fault yields status 0 (never an
 * exception — the client/reporter degrade to fail-open). The WP HTTP calls are injected so this is
 * unit-testable, though in prod it defaults to the real wp_remote_* functions. 7.3-clean.
 */
final class WpRemotePostTransport implements Transport
{
    /** @var callable */
    private $getFn;
    /** @var callable */
    private $postFn;
    /** @var int */
    private $timeoutMs;

    /**
     * @param int           $timeoutMs
     * @param callable|null $getFn  fn(string $url, array $args): array|WP_Error — wp_remote_get
     * @param callable|null $postFn fn(string $url, array $args): array|WP_Error — wp_remote_post
     */
    public function __construct(int $timeoutMs = 1500, $getFn = null, $postFn = null)
    {
        $this->timeoutMs = $timeoutMs;
        $this->getFn = $getFn !== null ? $getFn : 'wp_remote_get';
        $this->postFn = $postFn !== null ? $postFn : 'wp_remote_post';
    }

    public function get(string $url, array $headers)
    {
        return $this->normalize(call_user_func($this->getFn, $url, array(
            'headers' => $this->headerMap($headers),
            'timeout' => $this->timeoutMs / 1000,
        )));
    }

    public function post(string $url, array $headers, string $body)
    {
        return $this->normalize(call_user_func($this->postFn, $url, array(
            'headers' => $this->headerMap($headers),
            'body' => $body,
            'timeout' => $this->timeoutMs / 1000,
        )));
    }

    /** Convert ['Key: abc', 'Accept: application/json'] to a name=>value map for wp_remote_*. */
    private function headerMap(array $headers)
    {
        $map = array();
        foreach ($headers as $line) {
            $pos = strpos((string) $line, ':');
            if ($pos === false) {
                continue;
            }
            $map[trim(substr($line, 0, $pos))] = trim(substr($line, $pos + 1));
        }

        return $map;
    }

    /** WP_Error / response array -> {status, body, headers}. Status 0 on any transport fault. */
    private function normalize($response)
    {
        if (is_object($response) && method_exists($response, 'get_error_message')) {
            return array('status' => 0, 'body' => '', 'headers' => array());
        }
        if (!is_array($response)) {
            return array('status' => 0, 'body' => '', 'headers' => array());
        }

        $status = 0;
        if (isset($response['response']['code'])) {
            $status = (int) $response['response']['code'];
        }
        $body = isset($response['body']) ? (string) $response['body'] : '';
        $headers = array();
        if (isset($response['headers'])) {
            $h = $response['headers'];
            // WP passes a Requests_Utility_CaseInsensitiveDictionary (ArrayAccess/Iterator) or an array.
            if (is_array($h)) {
                foreach ($h as $k => $v) {
                    $headers[strtolower((string) $k)] = is_array($v) ? implode(', ', $v) : (string) $v;
                }
            } elseif (is_object($h) && method_exists($h, 'getAll')) {
                foreach ($h->getAll() as $k => $v) {
                    $headers[strtolower((string) $k)] = is_array($v) ? implode(', ', $v) : (string) $v;
                }
            }
        }

        return array('status' => $status, 'body' => $body, 'headers' => $headers);
    }
}
