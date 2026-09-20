<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\WordPress\WpInstalledSet;

final class WpInstalledSetTest extends TestCase
{
    /** @var array<string,mixed> fake transient store */
    private $transients;
    /** @var int */
    private $listPluginsCalls;
    /** @var int */
    private $listThemesCalls;

    protected function setUp(): void
    {
        parent::setUp();
        $this->transients = array();
        $this->listPluginsCalls = 0;
        $this->listThemesCalls = 0;
    }

    private function make(): WpInstalledSet
    {
        $store =& $this->transients;
        $pc =& $this->listPluginsCalls;
        $tc =& $this->listThemesCalls;

        return new WpInstalledSet(
            static function ($key) use (&$store) {
                return array_key_exists($key, $store) ? $store[$key] : false;
            },
            static function ($key, $value, $ttl) use (&$store) {
                $store[$key] = $value;
            },
            static function () use (&$pc) {
                $pc++;
                return array('akismet', 'Hello-Dolly');
            },
            static function () use (&$tc) {
                $tc++;
                return array('twentytwentyfour');
            }
        );
    }

    public function testColdCacheIsNotKnownAndReadsNoList(): void
    {
        $set = $this->make();

        $this->assertFalse($set->isKnown());
        $this->assertSame(array(), $set->plugins());
        $this->assertSame(array(), $set->themes());
        // The read path must NEVER call get_plugins()/wp_get_themes().
        $this->assertSame(0, $this->listPluginsCalls);
        $this->assertSame(0, $this->listThemesCalls);
    }

    public function testRefreshPopulatesTransientAndNormalizesSlugs(): void
    {
        $set = $this->make();
        $set->refresh();

        $this->assertSame(1, $this->listPluginsCalls);
        $this->assertSame(1, $this->listThemesCalls);
        $this->assertTrue($set->isKnown());
        // Slugs are lower-cased + de-duped.
        $this->assertSame(array('akismet', 'hello-dolly'), $set->plugins());
        $this->assertSame(array('twentytwentyfour'), $set->themes());
    }

    public function testReadPathAfterWarmStillCallsNoList(): void
    {
        $set = $this->make();
        $set->refresh();
        $this->listPluginsCalls = 0;
        $this->listThemesCalls = 0;

        $data = $set->data();

        $this->assertTrue($data['known']);
        $this->assertSame(array('akismet', 'hello-dolly'), $data['plugins']);
        $this->assertSame(0, $this->listPluginsCalls);
        $this->assertSame(0, $this->listThemesCalls);
    }

    public function testMalformedTransientTreatedAsCold(): void
    {
        $set = $this->make();
        $this->transients[WpInstalledSet::TRANSIENT] = 'garbage';
        $this->assertFalse($set->isKnown());
        $this->assertSame(array(), $set->plugins());
    }
}
