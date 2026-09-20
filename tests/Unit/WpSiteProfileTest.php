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

    public function testRealRouteSeamDrivesRouteExistsForNonReservedPath(): void
    {
        // FALLBACK position: WP resolved a genuine content object -> route exists.
        $resolved = new WpSiteProfile(true);
        $this->assertTrue($resolved->routeExists('/hello-world'));

        // Counterfactual-404 (no genuine object: a hard 404 or a WP-preempted soft-404) -> not a route.
        $notFound = new WpSiteProfile(false);
        $this->assertFalse($notFound->routeExists('/hello-world'));

        // BEFORE position (null): unknown non-reserved path -> not a real route (covered set only).
        $before = new WpSiteProfile(null);
        $this->assertFalse($before->routeExists('/hello-world'));
    }

    public function testPanelRootRouteExistsFollowsRealRouteSeam(): void
    {
        // FP-0504: a WP-preempted panel-root path is counterfactual-404 (false) -> not a real route,
        // so the engine can serve the owned decoy; a genuinely-resolved slug (true) stays a real route.
        $this->assertFalse((new WpSiteProfile(false))->routeExists('/phpmyadmin'));
        $this->assertTrue((new WpSiteProfile(true))->routeExists('/phpmyadmin'));
        // BEFORE (null) -> not a real route (only the reserved set is known).
        $this->assertFalse((new WpSiteProfile(null))->routeExists('/phpmyadmin'));
        // Reserved prefixes stay real regardless of the seam.
        $this->assertTrue((new WpSiteProfile(false))->routeExists('/wp-admin/'));
    }

    public function testRealRouteSeamAcceptsCallable(): void
    {
        $calls = 0;
        $p = new WpSiteProfile(static function () use (&$calls) {
            $calls++;
            return true;
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

    public function testIsReservedSlugForGenuineSurfaces(): void
    {
        // The one source of truth for slug validation (FP-0490).
        $this->assertTrue(WpSiteProfile::isReservedSlug('wp-login.php'));
        $this->assertTrue(WpSiteProfile::isReservedSlug('xmlrpc.php'));
        $this->assertTrue(WpSiteProfile::isReservedSlug('wp-cron.php'));
        $this->assertTrue(WpSiteProfile::isReservedSlug('wp-admin'));
        $this->assertTrue(WpSiteProfile::isReservedSlug('wp-json'));
        $this->assertTrue(WpSiteProfile::isReservedSlug('wp-signup.php'));
        $this->assertTrue(WpSiteProfile::isReservedSlug('WP-ADMIN')); // case-insensitive
    }

    public function testIsReservedSlugFalseForCustomSlug(): void
    {
        $this->assertFalse(WpSiteProfile::isReservedSlug('secret-login'));
        $this->assertFalse(WpSiteProfile::isReservedSlug('my-door'));
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
