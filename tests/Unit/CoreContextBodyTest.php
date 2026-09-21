<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\WordPress\CoreEvaluator;
use Funnypot\WordPress\RequestFactory;
use Funnypot\WordPress\Settings;
use PHPUnit\Framework\TestCase;

/**
 * FP-0513: the core RequestContext must carry the raw body when the adapter supplies it, so core can
 * MATCH body-borne rules (decoy-session login mint, FP-0086 payloadInspection, FP-0369 body fields).
 * The default (no body) stays null so the ownership/bot-signal callers are unchanged.
 */
final class CoreContextBodyTest extends TestCase
{
    private function evidence(string $method, string $body)
    {
        $server = array(
            'REQUEST_METHOD' => $method,
            'REQUEST_URI' => '/phpmyadmin/index.php',
            'REMOTE_ADDR' => '203.0.113.7',
            'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
        );
        $s = Settings::fromArray(array('enabled' => true), static function () {
            return null;
        });

        return RequestFactory::evidence($server, $body, $s);
    }

    public function test_body_is_threaded_into_the_core_context(): void
    {
        $ctx = CoreEvaluator::contextFromEvidence($this->evidence('POST', 'pma_username=root&pma_password=x'), 'pma_username=root&pma_password=x');
        self::assertSame('pma_username=root&pma_password=x', $ctx->rawBody, 'the raw body must reach core for body-rule matching');
    }

    public function test_body_defaults_to_null_when_omitted(): void
    {
        // Backward-compatible: the ownership counterfactual + bot-signal callers pass no body.
        $ctx = CoreEvaluator::contextFromEvidence($this->evidence('GET', ''));
        self::assertNull($ctx->rawBody, 'omitting the body keeps the pre-FP-0513 null (no behavior change)');
    }
}
