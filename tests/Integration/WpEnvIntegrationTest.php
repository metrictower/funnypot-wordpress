<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Integration;

use PHPUnit\Framework\TestCase;

/**
 * Live end-to-end integration against a REAL WordPress booted by @wordpress/env (Docker). Unlike
 * the unit suite (Brain Monkey, no WordPress), this drives the plugin exactly as an attacker or a
 * visitor would: real HTTP requests to the booted site, asserting the response the plugin actually
 * produces at request time.
 *
 * Preconditions the harness provides (see docs/INTEGRATION.md + bin/wp-env-provision.sh):
 *   - the site is booted (`npx wp-env start`),
 *   - pretty permalinks are on (so an unknown URL reaches WordPress' template_redirect, where the
 *     honeypot's FALLBACK position lives — with plain permalinks Apache 404s first),
 *   - the plugin is enabled in honeypot posture (it ships INERT by default).
 *
 * The ONLY sanctioned skip is an unreachable base URL (WP not booted), so the suite stays safe in a
 * CI stage without Docker. Override the target with HONEYPOT_WP_BASE_URL (default http://localhost:8888).
 *
 * Observed real behavior this asserts:
 *   - GET /.env (a scanner probe for a leaked secrets file) -> the honeypot UPGRADES the 404 into a
 *     fake-vulnerable 200 carrying a synthetic .env body — the deception.
 *   - GET a benign unknown path -> WordPress' own 404, untouched — no false positive.
 *   - GET / (the homepage) -> served normally, untouched.
 */
final class WpEnvIntegrationTest extends TestCase
{
    /** A response header the honeypot fake carries but WordPress' own 404 / homepage does not. */
    private const DECEPTION_HEADER = 'x-request-id';

    /** A marker string present in the synthetic .env body the honeypot serves to a probe. */
    private const FAKE_ENV_MARKER = 'DB_PASSWORD';

    /** @var string */
    private static $baseUrl;

    /** @var bool provision (permalinks + enable) attempted once per run */
    private static $provisioned = false;

    protected function setUp(): void
    {
        parent::setUp();
        self::$baseUrl = rtrim((string) (getenv('HONEYPOT_WP_BASE_URL') ?: 'http://localhost:8888'), '/');

        // Reachability preflight — the only sanctioned skip. A connection failure (status 0) means
        // there is no booted WordPress to talk to; everything else is a real assertion.
        list($status) = $this->httpGet('/');
        if ($status === 0) {
            $this->markTestSkipped(
                'wp-env base URL ' . self::$baseUrl . ' is not reachable. '
                . 'Run `npm install && npx wp-env start` (Docker required), then re-run this suite.'
            );
        }

        // Best-effort, idempotent provisioning so a bare `phpunit --testsuite integration` right
        // after a fresh boot still finds pretty permalinks + the plugin enabled. Swallows failure:
        // a harness that already provisioned (or lacks npx on PATH) is fine — the assertions decide.
        if (!self::$provisioned) {
            self::$provisioned = true;
            $script = dirname(__DIR__, 2) . '/bin/wp-env-provision.sh';
            if (is_file($script) && function_exists('shell_exec')) {
                @shell_exec('bash ' . escapeshellarg($script) . ' 2>&1');
            }
        }
    }

    /**
     * A scanner probing for a leaked Laravel/dotenv secrets file gets DECEIVED: the honeypot upgrades
     * what would be a 404 into a fake-vulnerable 200 serving a synthetic .env, so the scanner logs a
     * false "hit". This is the plugin's flagship request-time behavior.
     */
    public function testScannerProbeForEnvFileIsDeceived(): void
    {
        list($status, $headers, $body) = $this->httpGet('/.env');

        $this->assertSame(
            200,
            $status,
            'the honeypot should upgrade the /.env 404 into a fake-vulnerable 200 (got ' . $status . ')'
        );
        $this->assertArrayHasKey(
            self::DECEPTION_HEADER,
            $headers,
            'the deception response carries the honeypot fake-response header'
        );
        $this->assertStringContainsString(
            self::FAKE_ENV_MARKER,
            $body,
            'the deception body is a synthetic .env (contains ' . self::FAKE_ENV_MARKER . ')'
        );
        // A deceived probe must not be handed the real WordPress theme/HTML surface.
        $this->assertStringNotContainsStringIgnoringCase('<html', $body, 'a probe never gets a rendered WP page');
    }

    /**
     * An ordinary visitor hitting a URL that simply does not exist gets WordPress' own 404 — the
     * plugin passes it straight through. Proves the honeypot does not false-positive benign traffic.
     */
    public function testBenignMissingPathPassesThroughAsWordPressNotFound(): void
    {
        list($status, $headers, $body) = $this->httpGet('/no-such-page-' . uniqid('', true));

        $this->assertSame(404, $status, 'a benign unknown path stays a 404 (passthrough)');
        $this->assertArrayNotHasKey(
            self::DECEPTION_HEADER,
            $headers,
            'a benign 404 is untouched — no honeypot fake header'
        );
        $this->assertStringNotContainsString(
            self::FAKE_ENV_MARKER,
            $body,
            'a benign 404 is never handed a synthetic secrets body'
        );
    }

    /**
     * The homepage is served normally. The honeypot only ever upgrades a genuine 404, so real,
     * resolvable routes are never touched.
     */
    public function testHomepageIsServedNormallyAndUntouched(): void
    {
        list($status, $headers) = $this->httpGet('/');

        $this->assertSame(200, $status, 'the homepage is served normally');
        $this->assertArrayNotHasKey(
            self::DECEPTION_HEADER,
            $headers,
            'a real route is never touched by the honeypot'
        );
    }

    // ---------------------------------------------------------------------------------------------

    /**
     * GET $path on the booted site. Returns [statusCode, headers, body] where headers is a
     * lower-cased name => value map (last value wins) and statusCode is 0 on a connection failure.
     *
     * @param string $path
     * @return array{0:int,1:array<string,string>,2:string}
     */
    private function httpGet(string $path): array
    {
        $ctx = stream_context_create(array('http' => array(
            'method' => 'GET',
            'ignore_errors' => true, // capture the body + headers of a non-2xx (e.g. a 404) too
            'timeout' => 10,
            'header' => "User-Agent: funnypot-integration-test\r\n",
        )));

        $body = @file_get_contents(self::$baseUrl . $path, false, $ctx);
        if ($body === false && !isset($http_response_header)) {
            return array(0, array(), '');
        }

        $rawHeaders = isset($http_response_header) ? $http_response_header : array();

        return array(
            self::statusFrom($rawHeaders),
            self::parseHeaders($rawHeaders),
            (string) $body,
        );
    }

    /** Parse the status code out of the status line(s); the last one wins (redirect chains). */
    private static function statusFrom(array $rawHeaders): int
    {
        $status = 0;
        foreach ($rawHeaders as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m) === 1) {
                $status = (int) $m[1];
            }
        }

        return $status;
    }

    /** @return array<string,string> lower-cased header name => value (last value wins) */
    private static function parseHeaders(array $rawHeaders): array
    {
        $out = array();
        foreach ($rawHeaders as $line) {
            $pos = strpos($line, ':');
            if ($pos === false) {
                continue; // a status line, not a header
            }
            $name = strtolower(trim(substr($line, 0, $pos)));
            $out[$name] = trim(substr($line, $pos + 1));
        }

        return $out;
    }
}
