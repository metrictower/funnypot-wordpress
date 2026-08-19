<?php

declare(strict_types=1);

namespace Honeypot\WP;

use Honeypot\WP\Admin\Notices;
use Honeypot\WP\Admin\SettingsScreen;
use Honeypot\WP\Cli\HoneypotCommand;
use Honeypot\WP\Geo\GeoIpRefresh;
use Honeypot\WP\Log\WpdbHitLogWriter;
use Honeypot\WP\Mirror\BlacklistMirror;
use Honeypot\WP\Report\WpdbReportQueue;
use Honeypot\WP\Report\WpRemotePostTransport;
use Honeypot\WP\Report\WpReporterBridge;
use Honeypot\WP\Reputation\WpCache;

/**
 * The WordPress bootstrap (design §4.1) — the one place the adapter meets WordPress. Wires the
 * Interceptor's injectable seams to real WP primitives, registers the two position hooks, the admin
 * screen, WP-CLI, activation/deactivation, and cron. Everything is guarded so a WP-side fault degrades
 * safely (never a 5xx). This class is NOT unit-tested (it needs a live WordPress) — the logic it drives
 * lives in the unit-tested adapter classes. 7.3-clean.
 */
final class Plugin
{
    const OPTION = 'honeypot_wp_settings';
    const HOOK_REPORT_DRAIN = 'honeypot_wp_report_drain';
    const HOOK_WARMER = 'honeypot_wp_warmer_drain';
    const HOOK_MIRROR_PULL = 'honeypot_wp_mirror_pull';
    const HOOK_GEOIP_REFRESH = 'honeypot_wp_geoip_refresh';

    /** @var string the main plugin file */
    private static $file = '';
    /** @var bool */
    private static $providersReady = false;

    /** Called from the plugin main file at ordinary plugin load. */
    public static function register($file)
    {
        self::$file = (string) $file;
        self::wireProviders();

        // BEFORE position fallback (when the mu-shim is absent) + the FALLBACK 404 position.
        add_action('plugins_loaded', array(Interceptor::class, 'runBefore'), 0);
        add_action('template_redirect', array(Interceptor::class, 'runFallback'), 0);

        add_action('admin_menu', array(SettingsScreen::class, 'register'));
        add_action('admin_init', array(SettingsScreen::class, 'registerSetting'));
        add_action('admin_notices', array(__CLASS__, 'renderNotices'));

        register_activation_hook(self::$file, array(__CLASS__, 'activate'));
        register_deactivation_hook(self::$file, array(__CLASS__, 'deactivate'));

        self::registerCron();

        if (defined('WP_CLI') && WP_CLI) {
            HoneypotCommand::register(array(__CLASS__, 'services'));
        }
    }

    /** Called by the mu-loader shim (MuEntry::boot) to mount the BEFORE position at the earliest hook. */
    public static function registerBefore()
    {
        self::wireProviders();
        add_action('muplugins_loaded', array(Interceptor::class, 'runBefore'), 0);
    }

    /** Wire the Interceptor seams to real WP primitives (idempotent). */
    private static function wireProviders()
    {
        if (self::$providersReady) {
            return;
        }
        self::$providersReady = true;

        Interceptor::$settingsProvider = array(__CLASS__, 'settings');
        Interceptor::$serverProvider = static function () {
            return isset($_SERVER) ? $_SERVER : array();
        };
        Interceptor::$rawBodyProvider = static function () {
            $method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper((string) $_SERVER['REQUEST_METHOD']) : 'GET';
            if (!in_array($method, array('POST', 'PUT', 'PATCH', 'DELETE'), true)) {
                return null;
            }
            $raw = @file_get_contents('php://input', false, null, 0, 65536);
            return ($raw === false || $raw === '') ? null : $raw;
        };
        Interceptor::$is404Provider = static function () {
            return function_exists('is_404') ? (bool) is_404() : false;
        };
        Interceptor::$currentHookProvider = static function () {
            return function_exists('current_action') ? (string) current_action() : '';
        };
        Interceptor::$executorProvider = array(__CLASS__, 'executor');
    }

    /** Build the current Settings from the stored option (env constants win via the default resolver). */
    public static function settings()
    {
        $raw = function_exists('get_option') ? get_option(self::OPTION, array()) : array();

        return Settings::fromArray(is_array($raw) ? $raw : array());
    }

    /** Build the DecisionExecutor with the real emitter, hit-log, and reporter side-channels. */
    public static function executor($s)
    {
        $services = self::services();
        $log = isset($services['hitlog']) ? $services['hitlog'] : null;
        $reporter = isset($services['reporter']) ? $services['reporter'] : null;

        return new DecisionExecutor(null, null, null, $log, $reporter);
    }

    /**
     * The shared services bundle used by the executor + cron + CLI. Rebuilt per call (cheap); each
     * piece is guarded so a missing dependency degrades to null rather than fataling.
     *
     * @return array {settings, store, cache, reporter, mirror, geoip, hitlog}
     */
    public static function services()
    {
        global $wpdb;
        $s = self::settings();
        $clock = new WpClock();
        $store = WpStateStore::forSettings($s, $clock, self::stateDir());
        $cache = new WpCache();
        $sensorId = SensorId::resolve(
            static function () {
                return function_exists('get_option') ? get_option(SensorId::OPTION, '') : '';
            },
            static function ($id) {
                if (function_exists('update_option')) {
                    update_option(SensorId::OPTION, $id, true);
                }
            },
            static function () {
                return function_exists('wp_generate_uuid4') ? wp_generate_uuid4() : SensorId::randomUuidV4();
            }
        );

        $transport = new WpRemotePostTransport(1500);
        $reporter = null;
        $hitlog = null;
        if ($wpdb !== null) {
            $queue = new WpdbReportQueue($wpdb, $sensorId, $s->queueCap());
            $reporter = new WpReporterBridge($s, $queue, $transport, $cache, array($clock, 'now'));
            $hitlog = new WpdbHitLogWriter($wpdb);
        }

        $mirror = new BlacklistMirror($s, $store, $transport, null, static function () use ($clock) {
            return $clock->now();
        });
        $geoip = new GeoIpRefresh($s, $transport, static function ($bytes) {
            return @file_put_contents(self::geoDbPath(), $bytes) !== false;
        }, $store->backend(), self::geoFeedUrl(), static function () use ($clock) {
            return $clock->now();
        });

        return array(
            'settings' => $s,
            'store' => $store,
            'cache' => $cache,
            'reporter' => $reporter,
            'mirror' => $mirror,
            'geoip' => $geoip,
            'hitlog' => $hitlog,
            'sensor_id' => $sensorId,
        );
    }

    // --- admin notices ---------------------------------------------------------------------------

    public static function renderNotices()
    {
        $s = self::settings();
        $beforeConfigured = $s->positionActive('before');
        $store = WpStateStore::forSettings($s, new WpClock(), self::stateDir());
        $hook = $store->backend()->get('mount:before');
        $mount = Interceptor::mountState($hook !== null ? $hook : null, $beforeConfigured);
        $notice = Notices::noticeFor($mount, $beforeConfigured);
        if ($notice !== null && function_exists('esc_html')) {
            echo '<div class="notice notice-warning"><p>' . esc_html($notice) . '</p></div>';
        }
    }

    // --- activation / deactivation ---------------------------------------------------------------

    public static function activate()
    {
        Installer::activate(self::$file);
        self::registerCron();
        if (function_exists('wp_schedule_event')) {
            self::scheduleEvents();
        }
    }

    public static function deactivate()
    {
        Installer::deactivate(self::$file);
        foreach (array(self::HOOK_REPORT_DRAIN, self::HOOK_WARMER, self::HOOK_MIRROR_PULL, self::HOOK_GEOIP_REFRESH) as $hook) {
            $ts = function_exists('wp_next_scheduled') ? wp_next_scheduled($hook) : false;
            if ($ts && function_exists('wp_unschedule_event')) {
                wp_unschedule_event($ts, $hook);
            }
        }
    }

    // --- cron ------------------------------------------------------------------------------------

    private static function registerCron()
    {
        add_action(self::HOOK_REPORT_DRAIN, array(__CLASS__, 'cronReportDrain'));
        add_action(self::HOOK_WARMER, array(__CLASS__, 'cronWarmer'));
        add_action(self::HOOK_MIRROR_PULL, array(__CLASS__, 'cronMirrorPull'));
        add_action(self::HOOK_GEOIP_REFRESH, array(__CLASS__, 'cronGeoipRefresh'));
    }

    private static function scheduleEvents()
    {
        $now = time();
        if (!wp_next_scheduled(self::HOOK_REPORT_DRAIN)) {
            wp_schedule_event($now, 'hourly', self::HOOK_REPORT_DRAIN); // WP-Cron caveat: real cron recommended
        }
        if (!wp_next_scheduled(self::HOOK_MIRROR_PULL)) {
            wp_schedule_event($now, 'hourly', self::HOOK_MIRROR_PULL);
        }
        if (!wp_next_scheduled(self::HOOK_GEOIP_REFRESH)) {
            wp_schedule_event($now, 'daily', self::HOOK_GEOIP_REFRESH);
        }
    }

    public static function cronReportDrain()
    {
        $svc = self::services();
        if (isset($svc['reporter']) && $svc['reporter'] !== null) {
            $svc['reporter']->drain(200);
        }
    }

    public static function cronWarmer()
    {
        // The warmer drains through the reputation adapter's queue; wired inside PolicyFactory per
        // request. A dedicated cron warmer instance shares the same state backend.
    }

    public static function cronMirrorPull()
    {
        $svc = self::services();
        if (isset($svc['mirror']) && $svc['mirror'] !== null) {
            $svc['mirror']->pull();
        }
    }

    public static function cronGeoipRefresh()
    {
        $svc = self::services();
        if (isset($svc['geoip']) && $svc['geoip'] !== null) {
            $svc['geoip']->refresh();
        }
    }

    // --- paths -----------------------------------------------------------------------------------

    private static function stateDir()
    {
        if (function_exists('wp_upload_dir')) {
            $up = wp_upload_dir();
            if (is_array($up) && isset($up['basedir'])) {
                return $up['basedir'] . '/honeypot-wp-state';
            }
        }

        return sys_get_temp_dir() . '/honeypot-wp-state';
    }

    private static function geoDbPath()
    {
        return self::stateDir() . '/dbip-country-lite.mmdb';
    }

    private static function geoFeedUrl()
    {
        // A data-distribution concern; overridable via a constant. Placeholder by default.
        if (defined('HONEYPOT_WP_GEOIP_URL')) {
            return (string) constant('HONEYPOT_WP_GEOIP_URL');
        }

        return 'https://download.db-ip.com/free/dbip-country-lite.mmdb.gz';
    }
}
