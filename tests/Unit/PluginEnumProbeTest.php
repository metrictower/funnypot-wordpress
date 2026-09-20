<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\WordPress\PluginEnumProbe;

final class PluginEnumProbeTest extends TestCase
{
    public function testMatchesPluginReadme(): void
    {
        $m = PluginEnumProbe::matchesMetadataPath('/wp-content/plugins/tutor/readme.txt');
        $this->assertSame(array('kind' => 'plugin', 'slug' => 'tutor'), $m);
    }

    public function testMatchesThemeStyle(): void
    {
        $m = PluginEnumProbe::matchesMetadataPath('/wp-content/themes/twentytwentyfour/style.css');
        $this->assertSame(array('kind' => 'theme', 'slug' => 'twentytwentyfour'), $m);
    }

    public function testCaseInsensitive(): void
    {
        $m = PluginEnumProbe::matchesMetadataPath('/WP-CONTENT/Plugins/Tutor/README.TXT');
        $this->assertSame(array('kind' => 'plugin', 'slug' => 'tutor'), $m);
    }

    public function testNonMetadataAssetsAreNotMatched(): void
    {
        $this->assertNull(PluginEnumProbe::matchesMetadataPath('/wp-content/plugins/tutor/tutor.js'));
        $this->assertNull(PluginEnumProbe::matchesMetadataPath('/wp-content/plugins/tutor/'));
        $this->assertNull(PluginEnumProbe::matchesMetadataPath('/wp-content/plugins/tutor'));
        $this->assertNull(PluginEnumProbe::matchesMetadataPath('/wp-content/uploads/readme.txt'));
        $this->assertNull(PluginEnumProbe::matchesMetadataPath('/readme.txt'));
        // readme.txt one level too deep is not the metadata-probe shape.
        $this->assertNull(PluginEnumProbe::matchesMetadataPath('/wp-content/plugins/tutor/sub/readme.txt'));
    }

    public function testRejectsTraversalAndEmptySlug(): void
    {
        $this->assertNull(PluginEnumProbe::matchesMetadataPath('/wp-content/plugins/../readme.txt'));
        $this->assertNull(PluginEnumProbe::matchesMetadataPath('/wp-content/plugins//readme.txt'));
        $this->assertNull(PluginEnumProbe::matchesMetadataPath('/wp-content/plugins/.hidden/readme.txt'));
    }
}
