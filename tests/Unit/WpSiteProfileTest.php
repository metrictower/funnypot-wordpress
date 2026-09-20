<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\Policy\SiteProfile;
use Funnypot\WordPress\WpSiteProfile;

final class WpSiteProfileTest extends TestCase
{
    public function testStackIsWordpress(): void
    {
        $this->assertSame('wordpress', (new WpSiteProfile())->stack());
    }

    public function testRouteExistsForGenuineSurfaces(): void
    {
        $p = new WpSiteProfile();
        $this->assertTrue($p->routeExists('/'));
        $this->assertTrue($p->routeExists('/wp-cron.php'));
        $this->assertTrue($p->routeExists('/wp-admin/'));
        $this->assertTrue($p->routeExists('/wp-admin/options-general.php'));
        $this->assertTrue($p->routeExists('/wp-json/wp/v2/posts'));
        $this->assertTrue($p->routeExists('/wp-content/uploads/2026/08/a.png'));
    }

    public function testScannerPathsAreNotRoutesAndAreSacrificial(): void
    {
        $p = new WpSiteProfile();
        foreach (array('/.env', '/.git/config', '/wp-config.php.bak', '/wp-content/debug.log') as $path) {
            $this->assertFalse($p->routeExists($path), "$path should not be a real route");
            $this->assertTrue($p->isSacrificialPath($path), "$path should be sacrificial");
        }
        $this->assertFalse($p->isSacrificialPath('/'));
        $this->assertFalse($p->isSacrificialPath('/wp-login.php'));
    }

    public function testXmlrpcAndWpLoginRealRouteByDefault(): void
    {
        $p = new WpSiteProfile();
        $this->assertTrue($p->routeExists('/xmlrpc.php'));
        $this->assertTrue($p->routeExists('/wp-login.php'));
        $this->assertFalse($p->isSacrificialPath('/xmlrpc.php'));
        $this->assertFalse($p->isSacrificialPath('/wp-login.php'));
    }

    public function testXmlrpcAndWpLoginSacrificialOnlyWhenDecoyOptedIn(): void
    {
        $p = new WpSiteProfile(null, true, true);
        $this->assertFalse($p->routeExists('/xmlrpc.php'));
        $this->assertTrue($p->isSacrificialPath('/xmlrpc.php'));
        $this->assertFalse($p->routeExists('/wp-login.php'));
        $this->assertTrue($p->isSacrificialPath('/wp-login.php'));
    }

    public function testIs404SeamFlipsRouteExistsForResolvedPost(): void
    {
        // FALLBACK position: WP resolved a real post (is_404 === false) -> route exists.
        $resolved = new WpSiteProfile(false);
        $this->assertTrue($resolved->routeExists('/hello-world'));

        // Genuine 404 (is_404 === true) -> not a real route.
        $notFound = new WpSiteProfile(true);
        $this->assertFalse($notFound->routeExists('/hello-world'));

        // BEFORE position (null): unknown non-reserved path -> not a real route (covered set only).
        $before = new WpSiteProfile(null);
        $this->assertFalse($before->routeExists('/hello-world'));
    }

    public function testIs404AcceptsCallable(): void
    {
        $calls = 0;
        $p = new WpSiteProfile(static function () use (&$calls) {
            $calls++;
            return false;
        });
        $this->assertTrue($p->routeExists('/some-page'));
        $this->assertSame(1, $calls);
    }

    public function testCaseAndTrailingSlashVariants(): void
    {
        $p = new WpSiteProfile();
        $this->assertTrue($p->routeExists('/WP-ADMIN/'));
        $this->assertTrue($p->isSacrificialPath('/.ENV'));
        $this->assertTrue($p->routeExists('/wp-json/'));
    }

    public function testInstalledSlugStaysRealRouteNotSacrificial(): void
    {
        $set = array('plugins' => array('akismet'), 'themes' => array('twentytwentyfour'), 'known' => true);
        $p = new WpSiteProfile(null, false, false, $set);

        $this->assertTrue($p->routeExists('/wp-content/plugins/akismet/readme.txt'));
        $this->assertFalse($p->isSacrificialPath('/wp-content/plugins/akismet/readme.txt'));
        $this->assertTrue($p->routeExists('/wp-content/themes/twentytwentyfour/style.css'));
        $this->assertFalse($p->isSacrificialPath('/wp-content/themes/twentytwentyfour/style.css'));
    }

    public function testUninstalledSlugIsEnumerationProbe(): void
    {
        $set = array('plugins' => array('akismet'), 'themes' => array('twentytwentyfour'), 'known' => true);
        $p = new WpSiteProfile(null, false, false, $set);

        $this->assertFalse($p->routeExists('/wp-content/plugins/tutor/readme.txt'));
        $this->assertTrue($p->isSacrificialPath('/wp-content/plugins/tutor/readme.txt'));
        // Any path under an uninstalled slug is not a real route (the plugin genuinely does not exist).
        $this->assertFalse($p->routeExists('/wp-content/plugins/tutor/assets/x.js'));
        $this->assertTrue($p->isSacrificialPath('/wp-content/plugins/tutor/assets/x.js'));
        $this->assertTrue($p->isSacrificialPath('/wp-content/themes/some-theme/style.css'));
    }

    public function testColdInstalledSetFailsSafeToBlanketBehavior(): void
    {
        // known=false => we do not know our own routes -> exact historical blanket behavior.
        $cold = new WpSiteProfile(null, false, false, array('plugins' => array(), 'themes' => array(), 'known' => false));
        $this->assertTrue($cold->routeExists('/wp-content/plugins/tutor/readme.txt'));
        $this->assertFalse($cold->isSacrificialPath('/wp-content/plugins/tutor/readme.txt'));

        // No installed set at all (default ctor) is likewise blanket.
        $none = new WpSiteProfile();
        $this->assertTrue($none->routeExists('/wp-content/plugins/tutor/readme.txt'));
        $this->assertFalse($none->isSacrificialPath('/wp-content/plugins/tutor/readme.txt'));
    }

    public function testBareExtensionDirAndUploadsStayRealWithKnownSet(): void
    {
        $set = array('plugins' => array('akismet'), 'themes' => array(), 'known' => true);
        $p = new WpSiteProfile(null, false, false, $set);

        // The bare directory listing surface is not slug-scoped -> still a real route.
        $this->assertTrue($p->routeExists('/wp-content/plugins/'));
        $this->assertTrue($p->routeExists('/wp-content/themes/'));
        // Uploads are untouched by the narrowing.
        $this->assertTrue($p->routeExists('/wp-content/uploads/2026/08/a.png'));
    }

    public function testToPolicyProfileProjectsExactPath(): void
    {
        $p = new WpSiteProfile();

        $sac = $p->toPolicyProfile('/.env');
        $this->assertInstanceOf(SiteProfile::class, $sac);
        $this->assertSame('wordpress', $sac->stack());
        $this->assertTrue($sac->isSacrificialPath('/.env'));
        $this->assertFalse($sac->routeExists('/.env'));

        $real = $p->toPolicyProfile('/wp-login.php');
        $this->assertTrue($real->routeExists('/wp-login.php'));
        $this->assertFalse($real->isSacrificialPath('/wp-login.php'));
    }
}
