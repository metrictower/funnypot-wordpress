<?php

declare(strict_types=1);

namespace Honeypot\WP\Tests\Integration;

use PHPUnit\Framework\TestCase;

/**
 * Integration against a REAL WordPress (wp-env / Docker) is the deferred step — it needs a running
 * WP install which is not available in this environment. See README "Deferred: wp-env integration".
 *
 * The whole adapter surface is exercised by the unit suite (Brain Monkey), including an end-to-end
 * scanner-probe -> deceive Decision through the real wired policy ports (WiredPortsTest).
 */
final class DeferredWpEnvTest extends TestCase
{
    public function testWpEnvIntegrationIsDeferred(): void
    {
        $this->markTestSkipped('Real-WordPress (wp-env) integration is deferred — see README.');
    }
}
