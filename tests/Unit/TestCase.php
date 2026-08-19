<?php

declare(strict_types=1);

namespace Honeypot\WP\Tests\Unit;

use Brain\Monkey;
use PHPUnit\Framework\TestCase as BaseTestCase;

/**
 * Base unit test case: sets up / tears down Brain Monkey so WP functions can be
 * stubbed/expected per test without a real WordPress install.
 */
abstract class TestCase extends BaseTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Monkey\setUp();
    }

    protected function tearDown(): void
    {
        Monkey\tearDown();
        parent::tearDown();
    }
}
