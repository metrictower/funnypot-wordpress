<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit {

    use Brain\Monkey\Functions;
    use Funnypot\Core\RequestContext;
    use Funnypot\Core\Support\LoginDecoyField;
    use Funnypot\WordPress\Capture\WpNativeCapture;
    use Funnypot\WordPress\EvaluatorConfig;
    use Funnypot\WordPress\Log\HitLogWriter;
    use Funnypot\WordPress\Settings;
    use Funnypot\WordPress\Tests\Fakes\InMemoryBackend;
    use Funnypot\WordPress\Tests\Fakes\MutableClock;
    use Funnypot\WordPress\Tests\Fakes\SpyHitLogWriter;
    use Funnypot\WordPress\WpStateStore;

    /**
     * FP-0505 — the invisible honeypot field on the REAL WP login form. Plugin-only; reuses the
     * vendored core LoginDecoyField for the name. WP-fn-stubbed (Brain Monkey), no live WordPress.
     */
    final class WpLoginHoneypotFieldTest extends TestCase
    {
        const HOST = 'example.test';

        /** @var MutableClock */
        private $clock;
        /** @var InMemoryBackend */
        private $backend;
        /** @var WpStateStore */
        private $store;
        /** @var SpyHitLogWriter */
        private $inner;
        /** @var array */
        private $server;

        protected function setUp(): void
        {
            parent::setUp();
            $this->clock = new MutableClock(1000000);
            $this->backend = new InMemoryBackend($this->clock->asCallable());
            $this->store = new WpStateStore($this->backend, $this->clock);
            $this->inner = new SpyHitLogWriter();
            $this->server = array(
                'REMOTE_ADDR' => '203.0.113.9',
                'REQUEST_METHOD' => 'POST',
                'HTTP_USER_AGENT' => 'evil-scanner/1.0',
            );
        }

        private function settings($honeypotOn, $nativeOn = false, $enabled = true)
        {
            return Settings::fromArray(
                array(
                    'enabled' => $enabled,
                    'login_honeypot_field' => $honeypotOn,
                    'wp_native_capture' => $nativeOn,
                ),
                static function ($name) {
                    return null;
                }
            );
        }

        /** Wire the static seams with the in-memory fakes; host + $_POST + hitlog overridable per test. */
        private function wire($settings, $host = self::HOST, array $post = array(), $hitlog = null)
        {
            $log = $hitlog !== null ? $hitlog : $this->inner;
            $store = $this->store;
            $server = $this->server;

            WpNativeCapture::$settingsProvider = static function () use ($settings) {
                return $settings;
            };
            WpNativeCapture::$serverProvider = static function () use (&$server) {
                return $server;
            };
            WpNativeCapture::$depsProvider = static function () use ($log, $store) {
                return array('hitlog' => $log, 'store' => $store);
            };
            WpNativeCapture::$hostProvider = static function () use ($host) {
                return $host;
            };
            WpNativeCapture::$postProvider = static function () use ($post) {
                return $post;
            };
        }

        /** Independently derive the expected field name via the core helper, for GET==POST assertions. */
        private function expectedName($host = self::HOST)
        {
            $r = new RequestContext('GET', '/wp-login.php', '', array(), null, $host);
            $c = EvaluatorConfig::fromSettings($this->settings(true));

            return LoginDecoyField::expectedName($r, $c);
        }

        private function render()
        {
            ob_start();
            WpNativeCapture::renderLoginField();

            return (string) ob_get_clean();
        }

        private function agg($ip = '203.0.113.9')
        {
            return $this->backend->get('capture_agg:login:' . $ip);
        }

        // --- RENDER: hidden field, real users can't fill it --------------------------------------

        public function testRendersHiddenFieldWithDerivedName(): void
        {
            $this->wire($this->settings(true));
            $html = $this->render();

            $name = $this->expectedName();
            $this->assertStringContainsString('name="' . $name . '"', $html, 'the rendered name must equal the derived name');
            $this->assertStringContainsString('display:none', $html);
            $this->assertStringContainsString('aria-hidden', $html);
            $this->assertStringContainsString('tabindex="-1"', $html);
            $this->assertStringContainsString('autocomplete="off"', $html);
            $this->assertStringContainsString('type="text"', $html);
            $this->assertStringContainsString('value=""', $html);
        }

        // --- DEFAULT OFF / inert -----------------------------------------------------------------

        public function testDefaultsOffRendersNothingAndDetectsNothing(): void
        {
            $s = Settings::fromArray(array(), static function ($n) {
                return null;
            });
            $this->assertFalse($s->loginHoneypotField(), 'the toggle defaults off');

            $name = $this->expectedName();
            $this->wire($s, self::HOST, array($name => 'filled', 'log' => 'admin'));
            $this->assertSame('', $this->render(), 'off => nothing rendered');

            Functions\when('username_exists')->justReturn(false);
            WpNativeCapture::onLoginFailed('admin');
            $this->assertCount(0, $this->inner->rows, 'off => a filled field records nothing');
        }

        // --- DETECT: non-empty submit flags ------------------------------------------------------

        public function testNonEmptySubmitFlags(): void
        {
            Functions\when('username_exists')->justReturn(false);
            $name = $this->expectedName();
            $this->wire($this->settings(true), self::HOST, array($name => 'x', 'log' => 'admin', 'pwd' => 'p'));

            WpNativeCapture::onLoginFailed('admin');

            $this->assertCount(1, $this->inner->rows);
            $row = $this->inner->rows[0];
            $this->assertSame('login_honeypot_field', $row['reason']);
            $this->assertSame('/wp-login.php', $row['path']);
            $this->assertSame('log', $row['action']);
        }

        public function testEmptyWhitespaceOrAbsentIgnored(): void
        {
            Functions\when('username_exists')->justReturn(false);
            $name = $this->expectedName();

            // empty string
            $this->wire($this->settings(true), self::HOST, array($name => '', 'log' => 'admin'));
            WpNativeCapture::onLoginFailed('admin');
            // whitespace only
            $this->wire($this->settings(true), self::HOST, array($name => "   \t", 'log' => 'admin'));
            WpNativeCapture::onLoginFailed('admin');
            // field absent entirely
            $this->wire($this->settings(true), self::HOST, array('log' => 'admin', 'pwd' => 'p'));
            WpNativeCapture::onLoginFailed('admin');

            $this->assertCount(0, $this->inner->rows, 'empty / whitespace / absent must never be a false positive');
        }

        // --- MAKE-OR-BREAK: GET render name == POST detect name; Host-header invariant -----------

        public function testGetRenderNameEqualsPostDetectNameAndIsHostHeaderInvariant(): void
        {
            Functions\when('username_exists')->justReturn(false);
            $name = $this->expectedName(self::HOST);

            // RENDER with one client Host header.
            $this->server['HTTP_HOST'] = 'attacker-spoof.example';
            $this->wire($this->settings(true), self::HOST, array($name => 'bot'));
            $html = $this->render();
            $this->assertStringContainsString('name="' . $name . '"', $html);

            // DETECT with a DIFFERENT spoofed client Host header — the name must not shift (it is
            // derived from the server-side hostProvider, not the request Host), so detection still fires.
            $this->server['HTTP_HOST'] = 'another-spoof.example';
            $this->wire($this->settings(true), self::HOST, array($name => 'bot', 'log' => 'admin'));
            WpNativeCapture::onLoginFailed('admin');

            $this->assertCount(1, $this->inner->rows, 'render name and detect name must agree despite a spoofed Host header');
            $this->assertSame('login_honeypot_field', $this->inner->rows[0]['reason']);
        }

        // --- NOT A TELL --------------------------------------------------------------------------

        public function testNameAndMarkupAreNotATell(): void
        {
            $this->wire($this->settings(true));
            $html = strtolower($this->render());

            foreach (array('honeypot', 'trap', 'spam', 'leave this', 'leave blank', 'do not fill') as $tell) {
                $this->assertStringNotContainsString($tell, $html, "markup must not carry the tell token '$tell'");
            }
            $this->assertStringNotContainsString('website', $html);
            $this->assertStringNotContainsString('homepage', $html);

            $closed = array('contact_phone', 'company_fax', 'alt_email', 'secondary_email', 'office_ext', 'mobile_alt');
            $this->assertContains($this->expectedName(), $closed, 'the name must come from the core closed list');
            $this->assertNotContains($this->expectedName(), array('website', 'url', 'homepage'), 'never a known bait field name');
        }

        // --- CONDITION (a): honeypot detects even when wp_native_capture is OFF -------------------

        public function testHoneypotDetectsWhenNativeCaptureOff(): void
        {
            Functions\when('username_exists')->justReturn(false);
            $name = $this->expectedName();
            // login_honeypot_field ON, wp_native_capture OFF.
            $this->wire($this->settings(true, false), self::HOST, array($name => 'bot', 'log' => 'admin'));

            WpNativeCapture::onLoginFailed('admin');

            $this->assertCount(1, $this->inner->rows, 'the honeypot must fire independently of wp_native_capture');
            $this->assertSame('login_honeypot_field', $this->inner->rows[0]['reason']);
        }

        // --- CONDITION (b): honeypot reason owns the durable row when BOTH toggles are on ---------

        public function testHoneypotOwnsDurableRowWhenBothOn(): void
        {
            Functions\when('username_exists')->justReturn(false);
            $name = $this->expectedName();
            // BOTH on; the field is tripped on a failed login.
            $this->wire($this->settings(true, true), self::HOST, array($name => 'bot', 'log' => 'admin', 'pwd' => 'p'));

            WpNativeCapture::onLoginFailed('admin');

            $this->assertCount(1, $this->inner->rows, 'both captures collapse to ONE durable row per window');
            $this->assertSame('login_honeypot_field', $this->inner->rows[0]['reason'], 'the high-confidence honeypot reason owns the row');

            $agg = $this->agg();
            $this->assertSame(2, $agg['count'], 'both captures bump the velocity');
            $this->assertContains('login_honeypot_field', $agg['reasons_sample']);
            $this->assertContains('login_failed', $agg['reasons_sample'], 'the native reason is retained in the aggregate sample');
        }

        // --- never blocks / fault-safe -----------------------------------------------------------

        public function testRenderAndDetectAreFaultSafe(): void
        {
            $throwing = new class implements HitLogWriter {
                public function record(array $row)
                {
                    throw new \RuntimeException('boom');
                }
            };
            Functions\when('username_exists')->justReturn(false);
            $name = $this->expectedName();
            $this->wire($this->settings(true, true), self::HOST, array($name => 'bot', 'log' => 'admin'), $throwing);

            // A hitlog fault during detection must be swallowed (login unaffected).
            WpNativeCapture::onLoginFailed('admin');
            // Render must never throw either.
            $this->assertIsString($this->render());
            $this->assertTrue(true, 'no fault escaped render or detect');
        }

        public function testEmptyHostNoOps(): void
        {
            Functions\when('username_exists')->justReturn(false);
            // hostProvider returns '' (WP not fully loaded) => name '' => render + detect both no-op.
            $this->wire($this->settings(true), '', array('anything' => 'x', 'log' => 'admin'));

            $this->assertSame('', $this->render(), 'empty host => nothing rendered');
            WpNativeCapture::onLoginFailed('admin');
            $this->assertCount(0, $this->inner->rows, 'empty host => nothing detected');
        }

        // --- no PII: the submitted value is never persisted --------------------------------------

        public function testSubmittedValueNeverPersisted(): void
        {
            Functions\when('username_exists')->justReturn(false);
            $name = $this->expectedName();
            $secret = 'sekret-bot-value-42';
            $this->wire($this->settings(true), self::HOST, array($name => $secret, 'log' => 'admin', 'pwd' => 'hunter2'));

            WpNativeCapture::onLoginFailed('admin');

            $this->assertCount(1, $this->inner->rows);
            $row = $this->inner->rows[0];
            foreach ($row as $value) {
                $this->assertNotSame($secret, $value, 'the submitted honeypot value must never reach the row');
            }
            $this->assertNotContains($secret, $this->agg(), 'the submitted honeypot value must never reach the aggregate');
        }

        // --- hook registration + settings round-trip ---------------------------------------------

        public function testLoginFormHookRegistered(): void
        {
            $actions = array();
            Functions\when('add_action')->alias(static function ($hook, $cb, $prio = 10, $args = 1) use (&$actions) {
                $actions[] = $hook;
            });
            Functions\when('add_filter')->justReturn(true);

            WpNativeCapture::register();

            $this->assertContains('login_form', $actions, 'the render must hook login_form');
        }

        public function testSettingRoundTripsThroughSanitizer(): void
        {
            $out = \Funnypot\WordPress\Admin\SettingsSanitizer::sanitize(array('login_honeypot_field' => '1'));
            $this->assertTrue($out['login_honeypot_field']);

            $off = \Funnypot\WordPress\Admin\SettingsSanitizer::sanitize(array());
            $this->assertFalse($off['login_honeypot_field'], 'an absent checkbox means off');
        }
    }
}
