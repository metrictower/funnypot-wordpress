<?php

declare(strict_types=1);

namespace Honeypot\WP\Tests\Fakes;

use Funnypot\Mainnet\Transport\Transport;

/** A Transport that records requests and replays a scripted queue of responses. */
final class RecordingTransport implements Transport
{
    /** @var array<int,array> the recorded POSTs {url, headers, body} */
    public $posts = array();
    /** @var array<int,array> the recorded GETs {url, headers} */
    public $gets = array();
    /** @var array<int,array> scripted responses; falls back to the default when exhausted */
    private $responses;
    /** @var array */
    private $default;

    /**
     * @param array $responses scripted {status, body, headers} responses, consumed in order
     * @param array $default   returned once the scripted queue is exhausted
     */
    public function __construct(array $responses = array(), array $default = array('status' => 200, 'body' => '{"data":{}}', 'headers' => array()))
    {
        $this->responses = $responses;
        $this->default = $default;
    }

    public function get(string $url, array $headers)
    {
        $this->gets[] = array('url' => $url, 'headers' => $headers);

        return $this->next();
    }

    public function post(string $url, array $headers, string $body)
    {
        $this->posts[] = array('url' => $url, 'headers' => $headers, 'body' => $body);

        return $this->next();
    }

    private function next()
    {
        if ($this->responses !== array()) {
            return array_shift($this->responses);
        }

        return $this->default;
    }
}
