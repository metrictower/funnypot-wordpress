<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\WordPress\LoginRelocator;
use Funnypot\WordPress\Settings;

/**
 * FP-0490 — the login relocator: the pure routing classifier, the scoped URL-rewrite slug-leak guard,
 * and the fail-open hook bodies. Pure logic is asserted without WordPress; the hook bodies use injected
 * seams so a throwing seam proves the fail-open-to-real-login invariant.
 */
final class LoginRelocatorTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        LoginRelocator::reset();
    }

    protected function tearDown(): void
    {
        LoginRelocator::$settingsProvider = null;
        LoginRelocator::$serverProvider = null;
        LoginRelocator::$isUserLoggedInProvider = null;
        LoginRelocator::$requireRealLogin = null;
        LoginRelocator::$redirectToAdmin = null;
        LoginRelocator::reset();
        parent::tearDown();
    }

    private function settings(array $overrides = array())
    {
        $raw = array_merge(array(
            'enabled' => true,
            'login_relocation_enabled' => true,
            'login_slug' => 'secret-login',
            'response_mode' => 'realistic',
        ), $overrides);

        return Settings::fromArray($raw, static function () {
            return null;
        });
    }

    // --- routing decision ------------------------------------------------------------------------

    public function testSlugPrettyFormRoutesToRealLogin(): void
    {
        $s = $this->settings();
        $this->assertSame('real_login', LoginRelocator::route('/secret-login', array(), false, true, $s));
    }

    public function testSlugTrailingSlashRoutesToRealLogin(): void
    {
        $s = $this->settings();
        $this->assertSame('real_login', LoginRelocator::route('/secret-login/', array(), false, true, $s));
    }

    public function testSlugPlainPermalinkFormRoutesToRealLogin(): void
    {
        $s = $this->settings();
        // example.com/?secret-login -> path '/', slug present as a query var key.
        $this->assertSame('real_login', LoginRelocator::route('/', array('secret-login' => ''), false, false, $s));
    }

    public function testDefaultLoginAnonRoutesToDecoy(): void
    {
        $s = $this->settings();
        $this->assertSame('decoy_default', LoginRelocator::route('/wp-login.php', array(), false, true, $s));
    }

    public function testDefaultLoginPostpassIsCarvedOut(): void
    {
        $s = $this->settings();
        $this->assertSame(
            'passthrough_default',
            LoginRelocator::route('/wp-login.php', array('action' => 'postpass'), false, true, $s)
        );
    }

    public function testDefaultLoginWhileLoggedInIsCarvedOut(): void
    {
        $s = $this->settings();
        $this->assertSame('passthrough_default', LoginRelocator::route('/wp-login.php', array(), true, true, $s));
    }

    public function testUnrelatedPathPassesThrough(): void
    {
        $s = $this->settings();
        $this->assertSame('passthrough', LoginRelocator::route('/about', array(), false, true, $s));
    }

    public function testInactiveRelocationPassesEverythingThrough(): void
    {
        $off = $this->settings(array('enabled' => false));
        $this->assertSame('passthrough', LoginRelocator::route('/secret-login', array(), false, true, $off));
        $this->assertSame('passthrough', LoginRelocator::route('/wp-login.php', array(), false, true, $off));

        // Invalid slug -> stored '' -> inactive -> real login everywhere.
        $bad = $this->settings(array('login_slug' => 'wp-admin'));
        $this->assertSame('passthrough', LoginRelocator::route('/wp-login.php', array(), false, true, $bad));
    }

    // --- rewrite scoping / SLUG-LEAK GUARD -------------------------------------------------------

    public function testRewriteOnSlugContextSwapsToSlugPreservingQuery(): void
    {
        $out = LoginRelocator::rewriteLoginUrl(
            'https://ex.com/wp-login.php?action=lostpassword',
            'login',
            'secret-login',
            true,
            false
        );
        $this->assertSame('https://ex.com/secret-login?action=lostpassword', $out);
        $this->assertStringContainsString('secret-login', $out);
        $this->assertStringNotContainsString('wp-login.php', $out);
    }

    public function testRewriteAnonNonSlugContextDoesNotLeakSlug(): void
    {
        // The load-bearing no-leak assertion: an anonymous, non-slug request keeps wp-login.php and
        // NEVER receives the secret slug.
        $out = LoginRelocator::rewriteLoginUrl(
            'https://ex.com/wp-login.php',
            'login',
            'secret-login',
            false,
            false
        );
        $this->assertSame('https://ex.com/wp-login.php', $out);
        $this->assertStringContainsString('wp-login.php', $out);
        $this->assertStringNotContainsString('secret-login', $out);
    }

    public function testRewriteAuthedContextSwapsToSlug(): void
    {
        $out = LoginRelocator::rewriteLoginUrl(
            'https://ex.com/wp-login.php?action=logout&_wpnonce=abc',
            'logout',
            'secret-login',
            false,
            true
        );
        $this->assertStringContainsString('secret-login', $out);
        $this->assertStringNotContainsString('wp-login.php', $out);
    }

    public function testRewriteSwapsOnlyFirstOccurrencePreservingRedirectTo(): void
    {
        // A nested "wp-login.php" inside a redirect_to query value must survive the rewrite.
        $out = LoginRelocator::rewriteLoginUrl(
            'https://ex.com/wp-login.php?redirect_to=https%3A%2F%2Fex.com%2Fwp-login.php%3Faction%3Dlogout',
            'login',
            'secret-login',
            true,
            false
        );
        $this->assertSame(
            'https://ex.com/secret-login?redirect_to=https%3A%2F%2Fex.com%2Fwp-login.php%3Faction%3Dlogout',
            $out
        );
    }

    public function testRewriteEmptySlugOrNonLoginUrlUnchanged(): void
    {
        $this->assertSame(
            'https://ex.com/wp-login.php',
            LoginRelocator::rewriteLoginUrl('https://ex.com/wp-login.php', 'login', '', true, true)
        );
        $this->assertSame(
            'https://ex.com/some/page',
            LoginRelocator::rewriteLoginUrl('https://ex.com/some/page', 'login', 'secret-login', true, true)
        );
    }

    // --- hook dispatch + fail-open ---------------------------------------------------------------

    public function testCaptureSlugMarksRenderingSlugOnSlugRequest(): void
    {
        $s = $this->settings();
        LoginRelocator::$settingsProvider = static function () use ($s) {
            return $s;
        };
        LoginRelocator::$serverProvider = static function () {
            return array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/secret-login');
        };
        LoginRelocator::$isUserLoggedInProvider = static function () {
            return false;
        };

        $this->assertFalse(LoginRelocator::isRenderingSlug());
        LoginRelocator::captureSlug();
        $this->assertTrue(LoginRelocator::isRenderingSlug());
    }

    public function testCaptureSlugIgnoresNonSlugRequest(): void
    {
        $s = $this->settings();
        LoginRelocator::$settingsProvider = static function () use ($s) {
            return $s;
        };
        LoginRelocator::$serverProvider = static function () {
            return array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/wp-login.php');
        };
        LoginRelocator::$isUserLoggedInProvider = static function () {
            return false;
        };

        LoginRelocator::captureSlug();
        $this->assertFalse(LoginRelocator::isRenderingSlug());
    }

    public function testServeSlugRunsRealLoginForAnon(): void
    {
        $s = $this->settings();
        $calls = array();
        LoginRelocator::$settingsProvider = static function () use ($s) {
            return $s;
        };
        LoginRelocator::$isUserLoggedInProvider = static function () {
            return false;
        };
        LoginRelocator::$requireRealLogin = static function () use (&$calls) {
            $calls[] = 'login';
        };
        LoginRelocator::$redirectToAdmin = static function () use (&$calls) {
            $calls[] = 'admin';
        };
        LoginRelocator::$serverProvider = static function () {
            return array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/secret-login');
        };

        LoginRelocator::captureSlug();
        LoginRelocator::serveSlug();
        $this->assertSame(array('login'), $calls);
    }

    public function testServeSlugRedirectsAuthedOperatorToDashboard(): void
    {
        $s = $this->settings();
        $calls = array();
        LoginRelocator::$settingsProvider = static function () use ($s) {
            return $s;
        };
        LoginRelocator::$isUserLoggedInProvider = static function () {
            return true;
        };
        LoginRelocator::$requireRealLogin = static function () use (&$calls) {
            $calls[] = 'login';
        };
        LoginRelocator::$redirectToAdmin = static function () use (&$calls) {
            $calls[] = 'admin';
        };
        LoginRelocator::$serverProvider = static function () {
            return array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/secret-login');
        };

        // Force the render flag on (captureSlug would set it) then serve while authed.
        LoginRelocator::captureSlug();
        LoginRelocator::serveSlug();
        $this->assertSame(array('admin'), $calls);
    }

    public function testCaptureSlugFailOpenSwallowsThrow(): void
    {
        LoginRelocator::$settingsProvider = static function () {
            throw new \RuntimeException('boom');
        };
        // Must not throw and must not mark the render flag (fail-open to the real login).
        LoginRelocator::captureSlug();
        $this->assertFalse(LoginRelocator::isRenderingSlug());
    }

    public function testServeSlugFailOpenSwallowsThrow(): void
    {
        $s = $this->settings();
        LoginRelocator::$settingsProvider = static function () use ($s) {
            return $s;
        };
        LoginRelocator::$isUserLoggedInProvider = static function () {
            return false;
        };
        LoginRelocator::$serverProvider = static function () {
            return array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/secret-login');
        };
        LoginRelocator::$requireRealLogin = static function () {
            throw new \RuntimeException('boom');
        };

        LoginRelocator::captureSlug();
        // The throwing seam is swallowed -> no fatal, WP proceeds to the real login.
        LoginRelocator::serveSlug();
        $this->assertTrue(true);
    }

    public function testServeVacatedDefaultFailOpenSwallowsThrow(): void
    {
        LoginRelocator::$settingsProvider = static function () {
            throw new \RuntimeException('boom');
        };
        LoginRelocator::$serverProvider = static function () {
            return array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/wp-login.php');
        };
        LoginRelocator::serveVacatedDefault();
        $this->assertTrue(true);
    }
}
