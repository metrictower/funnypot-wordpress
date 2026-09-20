<?php

declare(strict_types=1);

namespace {
    // Minimal stub so `$errors instanceof \WP_Error` resolves without a live WordPress.
    if (!class_exists('WP_Error')) {
        class WP_Error
        {
        }
    }
}

namespace Funnypot\WordPress\Tests\Unit {

    use Brain\Monkey\Functions;
    use Funnypot\WordPress\Capture\WpNativeCapture;
    use Funnypot\WordPress\Log\HitLogWriter;
    use Funnypot\WordPress\Settings;
    use Funnypot\WordPress\Tests\Fakes\InMemoryBackend;
    use Funnypot\WordPress\Tests\Fakes\MutableClock;
    use Funnypot\WordPress\Tests\Fakes\SpyHitLogWriter;
    use Funnypot\WordPress\WpStateStore;

    final class WpNativeCaptureTest extends TestCase
    {
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
            $this->wire(true);
        }

        /** Wire the static seams with the in-memory fakes. */
        private function wire($captureOn, $hitlog = null)
        {
            $log = $hitlog !== null ? $hitlog : $this->inner;
            $store = $this->store;
            $server = $this->server;
            $settings = $this->settings($captureOn);

            WpNativeCapture::$settingsProvider = static function () use ($settings) {
                return $settings;
            };
            WpNativeCapture::$serverProvider = static function () use (&$server) {
                return $server;
            };
            WpNativeCapture::$depsProvider = static function () use ($log, $store) {
                return array('hitlog' => $log, 'store' => $store);
            };
        }

        private function settings($captureOn, $enabled = true)
        {
            return Settings::fromArray(
                array('enabled' => $enabled, 'wp_native_capture' => $captureOn),
                static function ($name) {
                    return null;
                }
            );
        }

        private function agg($channel, $ip = '203.0.113.9')
        {
            return $this->backend->get('capture_agg:' . $channel . ':' . $ip);
        }

        // --- credential capture without ever storing the credential ------------------------------

        public function testLoginUnknownUserCapturesWithoutCredentials(): void
        {
            Functions\when('username_exists')->justReturn(false);

            WpNativeCapture::onLoginFailed('sprayed_name');

            $this->assertCount(1, $this->inner->rows);
            $row = $this->inner->rows[0];
            $this->assertSame('login_failed', $row['reason']);
            $this->assertSame('/wp-login.php', $row['path']);
            $this->assertSame('log', $row['action']);
            $this->assertArrayNotHasKey('username', $row);
            $this->assertArrayNotHasKey('password', $row);
            $this->assertNotContains('sprayed_name', $row, 'submitted username must never reach the row');

            $agg = $this->agg('login');
            $this->assertSame(1, $agg['count']);
            $this->assertSame('evil-scanner/1.0', $agg['ua']);
            $this->assertNotContains('sprayed_name', $agg, 'submitted username must never reach the aggregate');
        }

        public function testLoginKnownUserIsAnonymised(): void
        {
            Functions\when('username_exists')->justReturn(true);

            WpNativeCapture::onLoginFailed('realadmin');

            $this->assertCount(1, $this->inner->rows);
            $row = $this->inner->rows[0];
            $this->assertSame('login_fail_known_user', $row['reason']);
            foreach ($row as $value) {
                $this->assertNotSame('realadmin', $value, 'a real username must never be persisted');
            }
            $agg = $this->agg('login');
            $this->assertTrue($agg['real_user_targeted']);
            $this->assertNotContains('realadmin', $agg);
        }

        // --- the MUST-FIX: rollup-gate bounds durable rows under multicall amplification ----------

        public function testMulticallAmplificationIsRollupGated(): void
        {
            // A single unauthenticated system.multicall fires xmlrpc_call once per boxed method.
            for ($i = 0; $i < 50; $i++) {
                WpNativeCapture::onXmlrpcCall('wp.getUsersBlogs');
            }

            $this->assertCount(1, $this->inner->rows, '50 fires in one window must collapse to ONE durable row');
            $this->assertSame('xmlrpc_cred_check', $this->inner->rows[0]['reason']);

            $agg = $this->agg('xmlrpc');
            $this->assertSame(50, $agg['count'], 'the burst is captured as the aggregate velocity');

            // A new window (counter key expires) allows a second durable row.
            $this->clock->advance(WpNativeCapture::WINDOW_SECS + 1);
            WpNativeCapture::onXmlrpcCall('wp.getUsersBlogs');
            $this->assertCount(2, $this->inner->rows, 'a fresh window allows one more rollup row');
        }

        public function testLoginBurstIsRollupGated(): void
        {
            Functions\when('username_exists')->justReturn(false);
            for ($i = 0; $i < 20; $i++) {
                WpNativeCapture::onLoginFailed('name' . $i);
            }
            $this->assertCount(1, $this->inner->rows);
            $this->assertSame(20, $this->agg('login')['count']);
        }

        public function testRestUserQueryBurstIsRollupGated(): void
        {
            Functions\when('is_user_logged_in')->justReturn(false);
            $args = array('number' => 10);
            for ($i = 0; $i < 20; $i++) {
                WpNativeCapture::onRestUserQuery($args);
            }
            $this->assertCount(1, $this->inner->rows);
            $this->assertSame(20, $this->agg('rest')['count']);
        }

        // --- xmlrpc method -> reason mapping (fixed vocabulary; no arg/URL text ever stored) ------

        public function testXmlrpcMethodMapping(): void
        {
            WpNativeCapture::onXmlrpcCall('system.multicall');
            $this->assertSame('xmlrpc_multicall', $this->inner->rows[0]['reason']);

            // Fresh IPs so each first-in-window fire writes its own row.
            $this->server['REMOTE_ADDR'] = '198.51.100.1';
            $this->wire(true);
            WpNativeCapture::onXmlrpcCall('pingback.ping');
            $this->assertSame('xmlrpc_pingback', $this->inner->rows[1]['reason']);

            $this->server['REMOTE_ADDR'] = '198.51.100.2';
            $this->wire(true);
            WpNativeCapture::onXmlrpcCall('demo.sayHello');
            $this->assertSame('xmlrpc_call', $this->inner->rows[2]['reason']);

            foreach ($this->inner->rows as $row) {
                $this->assertSame('/xmlrpc.php', $row['path'], 'path is a fixed route, never attacker text');
            }
        }

        // --- REST filters are pure pass-throughs -------------------------------------------------

        public function testRestAuthErrorsPassthrough(): void
        {
            $err = new \WP_Error();
            $out = WpNativeCapture::onRestAuthErrors($err);

            $this->assertSame($err, $out, 'the filter must return the identical incoming value');
            $this->assertCount(1, $this->inner->rows);
            $this->assertSame('rest_auth_failed', $this->inner->rows[0]['reason']);
        }

        public function testRestAuthErrorsNullRecordsNothing(): void
        {
            $out = WpNativeCapture::onRestAuthErrors(null);
            $this->assertNull($out);
            $this->assertCount(0, $this->inner->rows, 'undetermined auth (null) is not a failure to capture');

            $out2 = WpNativeCapture::onRestAuthErrors(true);
            $this->assertTrue($out2, 'authenticated (true) passes through unchanged');
            $this->assertCount(0, $this->inner->rows);
        }

        public function testRestUserQueryUnauthOnly(): void
        {
            // Authenticated: no capture, args unchanged.
            Functions\when('is_user_logged_in')->justReturn(true);
            $args = array('number' => 5, 'order' => 'asc');
            $out = WpNativeCapture::onRestUserQuery($args);
            $this->assertSame($args, $out);
            $this->assertCount(0, $this->inner->rows, 'a logged-in author query is not enumeration');

            // Unauthenticated: capture, args still unchanged.
            Functions\when('is_user_logged_in')->justReturn(false);
            $out2 = WpNativeCapture::onRestUserQuery($args);
            $this->assertSame($args, $out2);
            $this->assertCount(1, $this->inner->rows);
            $this->assertSame('rest_user_enum', $this->inner->rows[0]['reason']);
        }

        // --- gate off / fault-safe ---------------------------------------------------------------

        public function testGateOffIsInert(): void
        {
            $this->wire(false);
            Functions\when('username_exists')->justReturn(false);
            Functions\when('is_user_logged_in')->justReturn(false);

            WpNativeCapture::onLoginFailed('x');
            WpNativeCapture::onXmlrpcCall('system.multicall');
            $err = new \WP_Error();
            $this->assertSame($err, WpNativeCapture::onRestAuthErrors($err));
            $args = array('a' => 1);
            $this->assertSame($args, WpNativeCapture::onRestUserQuery($args));

            $this->assertCount(0, $this->inner->rows);
        }

        public function testFaultSafe(): void
        {
            $throwing = new class implements HitLogWriter {
                public function record(array $row)
                {
                    throw new \RuntimeException('boom');
                }
            };
            $this->wire(true, $throwing);
            Functions\when('is_user_logged_in')->justReturn(false);
            Functions\when('username_exists')->justReturn(false);

            // Actions must swallow the fault.
            WpNativeCapture::onLoginFailed('x');
            WpNativeCapture::onXmlrpcCall('system.multicall');

            // Filters must still return their original argument on a fault.
            $err = new \WP_Error();
            $this->assertSame($err, WpNativeCapture::onRestAuthErrors($err));
            $args = array('a' => 1);
            $this->assertSame($args, WpNativeCapture::onRestUserQuery($args));
        }

        // --- structural: never enters the reporter path ------------------------------------------

        public function testNeverTouchesReporter(): void
        {
            $ref = new \ReflectionClass(WpNativeCapture::class);
            // Scan CODE tokens only (strip comments/docblocks) so the guarantee is about what the class
            // actually references, not what its documentation names.
            $code = '';
            foreach (token_get_all(file_get_contents($ref->getFileName())) as $token) {
                if (is_array($token)) {
                    if ($token[0] === T_COMMENT || $token[0] === T_DOC_COMMENT) {
                        continue;
                    }
                    $code .= $token[1];
                } else {
                    $code .= $token;
                }
            }
            $this->assertStringNotContainsString('ReporterBridge', $code, 'capture must never reference the reporter');
            $this->assertStringNotContainsString('ReportIntent', $code, 'capture must never build a report intent');
        }

        // --- the deps memoization pattern holds across many fires (nit b) ------------------------

        public function testDepsResolvedOnce(): void
        {
            $builds = 0;
            $log = $this->inner;
            $store = $this->store;
            // Mirror the Plugin::wireProviders memo: the heavy factory runs at most once per request.
            $cached = null;
            WpNativeCapture::$depsProvider = static function () use (&$cached, &$builds, $log, $store) {
                if ($cached === null) {
                    $builds++;
                    $cached = array('hitlog' => $log, 'store' => $store);
                }

                return $cached;
            };

            for ($i = 0; $i < 30; $i++) {
                WpNativeCapture::onXmlrpcCall('wp.getUsersBlogs');
            }

            $this->assertSame(1, $builds, 'the heavy services() factory must not be rebuilt per hook fire');
        }

        // --- hook registration -------------------------------------------------------------------

        public function testHooksRegistered(): void
        {
            $actions = array();
            $filters = array();
            Functions\when('add_action')->alias(static function ($hook, $cb, $prio = 10, $args = 1) use (&$actions) {
                $actions[] = $hook;
            });
            Functions\when('add_filter')->alias(static function ($hook, $cb, $prio = 10, $args = 1) use (&$filters) {
                $filters[] = $hook;
            });

            WpNativeCapture::register();

            $this->assertContains('wp_login_failed', $actions);
            $this->assertContains('xmlrpc_call', $actions);
            // The two REST hooks are added as FILTERS (return-preserving), not actions.
            $this->assertContains('rest_authentication_errors', $filters);
            $this->assertContains('rest_user_query', $filters);
            $this->assertNotContains('rest_authentication_errors', $actions);
        }

        // --- settings toggle: default off + round-trips through the sanitizer ---------------------

        public function testSettingDefaultsOff(): void
        {
            $s = Settings::fromArray(array(), static function ($n) {
                return null;
            });
            $this->assertFalse($s->wpNativeCapture());
        }

        public function testSettingRoundTripsThroughSanitizer(): void
        {
            $out = \Funnypot\WordPress\Admin\SettingsSanitizer::sanitize(array('wp_native_capture' => '1'));
            $this->assertTrue($out['wp_native_capture']);

            $off = \Funnypot\WordPress\Admin\SettingsSanitizer::sanitize(array());
            $this->assertFalse($off['wp_native_capture'], 'an absent checkbox means off');
        }
    }
}
