<?php

declare(strict_types=1);

namespace Honeypot\WP\Tests\Unit;

use Funnypot\Policy\PolicyEngine;
use Funnypot\Mainnet\Client;
use Funnypot\Honeypot;
use Honeypot\WP\Version;

/**
 * Phase 0: the Composer autoloader resolves the plugin namespace AND the three bundled
 * dependency packages, and the Brain Monkey setUp/tearDown cycle (from the base TestCase) runs.
 */
final class ScaffoldTest extends TestCase
{
    public function testPluginNamespaceAutoloads(): void
    {
        $this->assertSame('0.1.0-dev', Version::STRING);
    }

    public function testDependencyPackagesResolveViaPathRepos(): void
    {
        $this->assertTrue(class_exists(PolicyEngine::class), 'funnypot-policy must resolve');
        $this->assertTrue(class_exists(Client::class), 'mainnet-client must resolve');
        $this->assertTrue(class_exists(Honeypot::class), 'funnypot-core must resolve');
    }

    public function testBrainMonkeyCycleRuns(): void
    {
        // If Monkey\setUp() in the base TestCase failed, this test would not reach here.
        $this->assertTrue(function_exists('Brain\\Monkey\\setUp'));
    }
}
