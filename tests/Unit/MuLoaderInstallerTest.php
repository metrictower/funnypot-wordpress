<?php

declare(strict_types=1);

namespace Honeypot\WP\Tests\Unit;

use Honeypot\WP\MuLoaderInstaller;

final class MuLoaderInstallerTest extends TestCase
{
    private $tmp;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tmp = sys_get_temp_dir() . '/hpwp_mu_' . uniqid();
        @mkdir($this->tmp, 0755, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->tmp . '/*') ?: array() as $f) {
            @unlink($f);
        }
        @rmdir($this->tmp);
        parent::tearDown();
    }

    public function testPlan(): void
    {
        $this->assertSame('mu', MuLoaderInstaller::plan(true));
        $this->assertSame('fallback', MuLoaderInstaller::plan(false));
    }

    public function testShimBodyIsGuarded(): void
    {
        $body = MuLoaderInstaller::shimBody('/some/plugin/mu-entry.php');
        $this->assertStringContainsString('if (!is_file($honeypot_wp_bootstrap)) { return; }', $body);
        $this->assertStringContainsString("class_exists('Honeypot\\\\WP\\\\MuEntry')", $body);
        $this->assertStringContainsString('method_exists', $body);
        $this->assertStringContainsString('catch (\\Throwable', $body);
    }

    public function testIsStale(): void
    {
        $a = MuLoaderInstaller::shimBody('/x/mu-entry.php');
        $this->assertFalse(MuLoaderInstaller::isStale($a, $a));
        $this->assertTrue(MuLoaderInstaller::isStale($a, MuLoaderInstaller::shimBody('/y/mu-entry.php')));
    }

    /**
     * The load-path takedown test (SF-4): a shim whose bootstrap is absent (plugin dir removed WITHOUT
     * deactivation) is inert — including it serves normally, never a fatal.
     */
    public function testShimWithMissingBootstrapIsInertNeverFatal(): void
    {
        $shimFile = $this->tmp . '/shim.php';
        file_put_contents($shimFile, MuLoaderInstaller::shimBody($this->tmp . '/does-not-exist-mu-entry.php'));

        ob_start();
        $result = include $shimFile; // must return cleanly (the is_file guard fires)
        $output = ob_get_clean();

        $this->assertSame('', $output, 'a missing bootstrap emits nothing');
        // Reaching here at all proves no fatal was raised.
        $this->assertTrue(true);
    }

    public function testInstallSelfHealAndUninstall(): void
    {
        $bootstrap = '/does/not/matter/mu-entry.php';
        $this->assertTrue(MuLoaderInstaller::install($this->tmp, $bootstrap));
        $target = $this->tmp . '/' . MuLoaderInstaller::SHIM_FILENAME;
        $this->assertFileExists($target);

        // Re-install with the same bootstrap is a no-op success (already current).
        $this->assertTrue(MuLoaderInstaller::install($this->tmp, $bootstrap));

        // Corrupt the shim -> install self-heals it back to the expected body.
        file_put_contents($target, '<?php // stale');
        $this->assertTrue(MuLoaderInstaller::install($this->tmp, $bootstrap));
        $this->assertSame(MuLoaderInstaller::shimBody($bootstrap), file_get_contents($target));

        // Uninstall removes it.
        $this->assertTrue(MuLoaderInstaller::uninstall($this->tmp));
        $this->assertFileDoesNotExist($target);
    }

    public function testInstallReturnsFalseOnUnwritableDir(): void
    {
        // A path that is not a directory and cannot be created as one.
        $notADir = $this->tmp . '/afile';
        file_put_contents($notADir, 'x');
        $this->assertFalse(MuLoaderInstaller::install($notADir, '/x/mu-entry.php'));
    }
}
