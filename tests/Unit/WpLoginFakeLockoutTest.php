<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit {

    use Brain\Monkey\Functions;
    use Funnypot\Core\RequestContext;
    use Funnypot\Core\Support\LoginDecoyField;
    use Funnypot\Policy\FakeResponse;
    use Funnypot\WordPress\Capture\WpNativeCapture;
    use Funnypot\WordPress\EvaluatorConfig;
    use Funnypot\WordPress\Log\HitLogWriter;
    use Funnypot\WordPress\Settings;
    use Funnypot\WordPress\Tests\Fakes\InMemoryBackend;
    use Funnypot\WordPress\Tests\Fakes\MutableClock;
    use Funnypot\WordPress\Tests\Fakes\SpyHitLogWriter;
    use Funnypot\WordPress\WpStateStore;

    /**
     * FP-0506 — bot-gated fake lockout on the REAL WP login form. Plugin-only; reuses the vendored core
     * WordpressSkin::renderLockout (no core change). WP-fn-stubbed (Brain Monkey), no live WordPress. The
     * $responder seam is captured (not exited) so the serve is unit-testable. The make-or-break property is
     * NEVER LOCK A REAL USER: proven structurally (no auth hook, no persistent lock, cosmetic per-request).
     */
    final class WpLoginFakeLockoutTest extends TestCase
    {
        const HOST = 'example.test';
        const IP = '203.0.113.9';

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
        /** @var array<int,FakeResponse> */
        private $served;

        protected function setUp(): void
        {
            parent::setUp();
            $this->clock = new MutableClock(1000000);
            $this->backend = new InMemoryBackend($this->clock->asCallable());
            $this->store = new WpStateStore($this->backend, $this->clock);
            $this->inner = new SpyHitLogWriter();
            $this->server = array(
                'REMOTE_ADDR' => self::IP,
                'REQUEST_METHOD' => 'POST',
                'HTTP_USER_AGENT' => 'evil-scanner/1.0',
            );
            $this->served = array();
        }

        protected function tearDown(): void
        {
            // The serve seams are static; clear them so nothing leaks into another test file.
            WpNativeCapture::$responder = null;
            WpNativeCapture::$siteNameProvider = null;
            parent::tearDown();
        }

        /**
         * @param array $overrides extra settings keys (response_mode, velocity, toggles)
         */
        private function settings(array $overrides = array())
        {
            $base = array(
                'enabled' => true,
                'login_fake_lockout' => true,
                'login_honeypot_field' => false,
                'wp_native_capture' => false,
                'response_mode' => 'realistic',
            );

            return Settings::fromArray(
                array_merge($base, $overrides),
                static function ($name) {
                    return null;
                }
            );
        }

        /** Wire the static seams with the in-memory fakes; the responder captures WITHOUT exiting. */
        private function wire($settings, $host = self::HOST, array $post = array(), $hitlog = null)
        {
            $log = $hitlog !== null ? $hitlog : $this->inner;
            $store = $this->store;
            $server = $this->server;
            $served =& $this->served;

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
            WpNativeCapture::$responder = static function ($fake) use (&$served) {
                $served[] = $fake;
            };
            WpNativeCapture::$siteNameProvider = static function () {
                return 'Acme Blog';
            };
        }

        /** Independently derive the FP-0505 decoy field name via the core helper (for honeypot fixtures). */
        private function decoyName($host = self::HOST)
        {
            $r = new RequestContext('GET', '/wp-login.php', '', array(), null, $host);
            $c = EvaluatorConfig::fromSettings($this->settings());

            return LoginDecoyField::expectedName($r, $c);
        }

        private function failLogin($username = 'admin')
        {
            Functions\when('username_exists')->justReturn(false);
            WpNativeCapture::onLoginFailed($username);
        }

        // --- SIGNAL 1: honeypot trip => served ---------------------------------------------------

        public function testHoneypotTripServesLockout(): void
        {
            $name = $this->decoyName();
            $this->wire($this->settings(array('login_honeypot_field' => true)), self::HOST, array($name => 'bot', 'log' => 'admin', 'pwd' => 'p'));

            $this->failLogin();

            $this->assertCount(1, $this->served, 'a honeypot trip must serve the fake lockout');
            $fake = $this->served[0];
            $this->assertInstanceOf(FakeResponse::class, $fake);
            $this->assertSame(200, $fake->status(), 'status is app-chosen 200, never a tell');
            $this->assertSame('text/html; charset=UTF-8', $fake->contentType());
            $body = $fake->body();
            $this->assertStringContainsString('Too many failed login attempts', $body, 'the lockout notice must be present');
            $this->assertStringContainsString('id="loginform"', $body, 'it is the login card, byte-coherent with the real page');
            $this->assertStringContainsString('class="login"', $body);
        }

        // --- SIGNAL 2: conservative velocity => served (and NOT before threshold) -----------------

        public function testVelocityThresholdServesOnlyAtThreshold(): void
        {
            // Threshold at the clamp floor of 5, no honeypot, no native capture: the counter is the only signal.
            $this->wire($this->settings(array('login_lockout_velocity' => 5)), self::HOST, array('log' => 'admin', 'pwd' => 'wrong'));

            for ($i = 1; $i <= 4; $i++) {
                $this->failLogin();
                $this->assertCount(0, $this->served, "attempt $i is below the threshold => no serve (a real user mistyping is safe)");
            }
            $this->failLogin(); // 5th -> reaches threshold
            $this->assertCount(1, $this->served, 'reaching the threshold arms the cosmetic lockout');
            $this->assertStringContainsString('Too many failed login attempts', $this->served[0]->body());
        }

        // --- PLAIN FAILED-COUNT, NO SIGNAL => NO SERVE (the real-user path) -----------------------

        public function testPlainFailedCountNeverServes(): void
        {
            // Honeypot off; velocity threshold high; a handful of ordinary failures.
            $this->wire($this->settings(array('login_lockout_velocity' => 50)), self::HOST, array('log' => 'admin', 'pwd' => 'typo'));

            for ($i = 0; $i < 6; $i++) {
                $this->failLogin();
            }

            $this->assertCount(0, $this->served, 'a plain failed-login count with no bot signal must NEVER serve the lockout');
        }

        // --- DEFAULT OFF => inert even under a bot signal + high velocity -------------------------

        public function testDefaultOffIsInert(): void
        {
            $s = Settings::fromArray(array('enabled' => true, 'login_honeypot_field' => true), static function ($n) {
                return null;
            });
            $this->assertFalse($s->loginFakeLockout(), 'the toggle defaults off');

            $name = $this->decoyName();
            // Preseed a high velocity AND trip the honeypot; with the toggle off, nothing serves.
            $this->backend->set('ctr:login_lockout:' . self::IP, 999, 60);
            $this->wire($s, self::HOST, array($name => 'bot', 'log' => 'admin'));

            $this->failLogin();

            $this->assertCount(0, $this->served, 'toggle off => never served, whatever the signal');
        }

        // --- DECOUPLED: works with wp_native_capture OFF -----------------------------------------

        public function testServesWithNativeCaptureOff(): void
        {
            $name = $this->decoyName();
            // login_fake_lockout ON, login_honeypot_field ON, wp_native_capture OFF.
            $this->wire($this->settings(array('login_honeypot_field' => true, 'wp_native_capture' => false)), self::HOST, array($name => 'bot', 'log' => 'admin'));

            $this->failLogin();

            $this->assertCount(1, $this->served, 'the lockout must serve independently of wp_native_capture');
        }

        // --- RESPONSE-MODE GATE ------------------------------------------------------------------

        public function testStealthAndBlockedNeverServe(): void
        {
            $name = $this->decoyName();

            foreach (array('stealth', 'blocked') as $mode) {
                $this->served = array();
                $this->wire($this->settings(array('login_honeypot_field' => true, 'response_mode' => $mode)), self::HOST, array($name => 'bot', 'log' => 'admin'));
                $this->failLogin();
                $this->assertCount(0, $this->served, "$mode must never serve a decoy, even on a bot signal");
            }
        }

        public function testTauntServesTauntCopy(): void
        {
            $name = $this->decoyName();
            $this->wire($this->settings(array('login_honeypot_field' => true, 'response_mode' => 'taunt')), self::HOST, array($name => 'bot', 'log' => 'admin'));

            $this->failLogin();

            $this->assertCount(1, $this->served);
            $this->assertStringContainsString('Nice try', $this->served[0]->body(), 'taunt mode swaps to the taunting variant');
        }

        // --- NEVER LOCK A REAL USER (structural): no auth hook is ever registered -----------------

        public function testNoAuthHookRegistered(): void
        {
            $actions = array();
            $filters = array();
            Functions\when('add_action')->alias(static function ($hook, $cb = null, $prio = 10, $args = 1) use (&$actions) {
                $actions[] = $hook;
            });
            Functions\when('add_filter')->alias(static function ($hook, $cb = null, $prio = 10, $args = 1) use (&$filters) {
                $filters[] = $hook;
            });

            WpNativeCapture::register();

            $registered = array_merge($actions, $filters);
            foreach (array('authenticate', 'wp_authenticate', 'wp_signon', 'login_redirect') as $authHook) {
                $this->assertNotContains($authHook, $registered, "the feature must register NO $authHook hook — the auth decision stays out of scope");
            }
            // The only login hooks are the post-auth failure capture and the field render.
            $this->assertContains('wp_login_failed', $actions);
            $this->assertContains('login_form', $actions);
        }

        // --- NEVER LOCK A REAL USER (structural): no persistent lock state is written -------------

        public function testOnlyEphemeralCounterIsWritten(): void
        {
            // Velocity-only serve, honeypot + native capture off, so the ONLY state written is the counter.
            $this->backend->set('ctr:login_lockout:' . self::IP, 4, 60);
            $this->wire($this->settings(array('login_lockout_velocity' => 5)), self::HOST, array('log' => 'admin', 'pwd' => 'wrong'));

            $this->failLogin(); // n=5 -> served

            $this->assertCount(1, $this->served, 'the serve fired on the velocity signal');
            $this->assertSame(
                array('ctr:login_lockout:' . self::IP),
                $this->backend->keys(),
                'the ONLY state written is the ephemeral velocity counter — no lock/pin the auth path could read'
            );
            $this->assertSame(5, $this->backend->get('ctr:login_lockout:' . self::IP), 'the counter is measurement only');
        }

        // --- NO PII: submitted values never reach the served page --------------------------------

        public function testNoSubmittedValueInBody(): void
        {
            $name = $this->decoyName();
            $secret = 'sekret-bot-value-42';
            $this->wire(
                $this->settings(array('login_honeypot_field' => true)),
                self::HOST,
                array($name => $secret, 'log' => 'victim-user', 'pwd' => 'hunter2')
            );

            $this->failLogin('victim-user');

            $this->assertCount(1, $this->served);
            $body = $this->served[0]->body();
            $this->assertStringNotContainsString($secret, $body, 'the decoy value must never be reflected');
            $this->assertStringNotContainsString('victim-user', $body, 'the submitted username must never be reflected');
            $this->assertStringNotContainsString('hunter2', $body, 'the password must never be reflected');
        }

        // --- FINGERPRINT-SAFE: no llar / no 6-digit CRS rule id; minute from the small set --------

        public function testServedBodyIsFingerprintSafe(): void
        {
            $name = $this->decoyName();
            $this->wire($this->settings(array('login_honeypot_field' => true)), self::HOST, array($name => 'bot', 'log' => 'admin'));

            $this->failLogin();

            $body = $this->served[0]->body();
            $this->assertStringNotContainsStringIgnoringCase('llar', $body, 'no login-lockout plugin marker');
            $this->assertSame(0, preg_match('/9\d{5}/', $body), 'no six-digit CRS rule id may appear');
            $this->assertSame(1, preg_match('/in (\d+) minutes/', $body, $m), 'the notice carries a minute count');
            $this->assertContains((int) $m[1], array(5, 7, 9, 11, 13, 15, 17, 19, 23), 'the minute is drawn from the small allowed set');
        }

        // --- SEED STABILITY: same host => same countdown minute on re-scan ------------------------

        public function testSeedIsStablePerHost(): void
        {
            $name = $this->decoyName();

            $this->wire($this->settings(array('login_honeypot_field' => true)), self::HOST, array($name => 'bot', 'log' => 'admin'));
            $this->failLogin();
            $this->clock->advance(120); // a later scan, well after the counter window
            $this->failLogin();

            $this->assertCount(2, $this->served);
            preg_match('/in (\d+) minutes/', $this->served[0]->body(), $a);
            preg_match('/in (\d+) minutes/', $this->served[1]->body(), $b);
            $this->assertSame($a[1], $b[1], 'the minute is deterministic per deploy (host|salt), stable on re-scan');
        }

        // --- DEGRADE-SAFE: an emit fault never escapes / never exits (no 500) ---------------------

        public function testEmitFaultDegradesToNormalWp(): void
        {
            $name = $this->decoyName();
            $this->wire($this->settings(array('login_honeypot_field' => true)), self::HOST, array($name => 'bot', 'log' => 'admin'));
            WpNativeCapture::$responder = static function ($fake) {
                throw new \RuntimeException('emit boom');
            };

            // The fault is swallowed by onLoginFailed's try/catch: no exception, no exit, no 500.
            $this->failLogin();
            $this->assertTrue(true, 'a render/emit fault degrades to normal WordPress instead of faulting the request');
        }

        // --- SETTINGS ROUND-TRIP -----------------------------------------------------------------

        public function testSettingsRoundTripThroughSanitizer(): void
        {
            $out = \Funnypot\WordPress\Admin\SettingsSanitizer::sanitize(array(
                'login_fake_lockout' => '1',
                'login_lockout_velocity' => '9',
            ));
            $this->assertTrue($out['login_fake_lockout']);
            $this->assertSame(9, $out['login_lockout_velocity']);

            $def = \Funnypot\WordPress\Admin\SettingsSanitizer::sanitize(array());
            $this->assertFalse($def['login_fake_lockout'], 'an absent checkbox means off');
            $this->assertSame(15, $def['login_lockout_velocity'], 'the default velocity threshold');

            $clamped = \Funnypot\WordPress\Admin\SettingsSanitizer::sanitize(array('login_lockout_velocity' => '1'));
            $this->assertSame(5, $clamped['login_lockout_velocity'], 'the threshold clamps up to the floor of 5');
        }
    }
}
