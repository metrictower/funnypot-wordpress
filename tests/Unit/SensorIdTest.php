<?php

declare(strict_types=1);

namespace Honeypot\WP\Tests\Unit;

use Honeypot\WP\SensorId;

final class SensorIdTest extends TestCase
{
    public function testGeneratesAndPersistsWhenMissing(): void
    {
        $stored = null;
        $generated = 0;
        $get = static function () use (&$stored) {
            return $stored;
        };
        $set = static function ($id) use (&$stored) {
            $stored = $id;
        };
        $gen = static function () use (&$generated) {
            $generated++;
            return 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
        };

        $id = SensorId::resolve($get, $set, $gen);
        $this->assertSame('aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', $id);
        $this->assertSame($id, $stored, 'must persist exactly once');
        $this->assertSame(1, $generated);
    }

    public function testReturnsStoredWithoutRegenerating(): void
    {
        $stored = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
        $generated = 0;
        $persisted = 0;
        $get = static function () use (&$stored) {
            return $stored;
        };
        $set = static function ($id) use (&$persisted, &$stored) {
            $persisted++;
            $stored = $id;
        };
        $gen = static function () use (&$generated) {
            $generated++;
            return 'ffffffff-ffff-4fff-8fff-ffffffffffff';
        };

        $id = SensorId::resolve($get, $set, $gen);
        $this->assertSame('aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', $id);
        $this->assertSame(0, $generated, 'must not regenerate a valid stored id');
        $this->assertSame(0, $persisted, 'must not re-persist a valid stored id');
    }

    public function testMalformedStoredValueIsReplaced(): void
    {
        $stored = 'not-a-uuid';
        $get = static function () use (&$stored) {
            return $stored;
        };
        $set = static function ($id) use (&$stored) {
            $stored = $id;
        };
        $gen = static function () {
            return '11111111-2222-4333-8444-555555555555';
        };

        $id = SensorId::resolve($get, $set, $gen);
        $this->assertSame('11111111-2222-4333-8444-555555555555', $id);
        $this->assertTrue(SensorId::isValidUuid($id));
    }

    public function testFallbackGeneratorProducesValidV4WhenInjectedOneReturnsJunk(): void
    {
        $stored = null;
        $get = static function () use (&$stored) {
            return $stored;
        };
        $set = static function ($id) use (&$stored) {
            $stored = $id;
        };
        $gen = static function () {
            return 'garbage';
        };

        $id = SensorId::resolve($get, $set, $gen);
        $this->assertTrue(SensorId::isValidUuid($id));
        $this->assertSame('4', $id[14], 'version nibble must be 4');
    }
}
