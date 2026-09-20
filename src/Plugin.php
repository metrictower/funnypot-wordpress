<?php

declare(strict_types=1);

namespace Funnypot\WordPress;

use Funnypot\WordPress\Admin\IntelDashboard;
use Funnypot\WordPress\Admin\Notices;
use Funnypot\WordPress\Admin\SettingsScreen;
use Funnypot\WordPress\Capture\WpNativeCapture;
use Funnypot\WordPress\Cli\HoneypotCommand;
use Funnypot\WordPress\Geo\GeoIpRefresh;
use Funnypot\WordPress\Log\ScanAbsorbingHitLogWriter;
use Funnypot\WordPress\Log\WpdbHitLogWriter;
use Funnypot\WordPress\Mirror\BlacklistMirror;
use Funnypot\WordPress\Report\WpdbReportQueue;
use Funnypot\WordPress\Report\WpRemotePostTransport;
use Funnypot\WordPress\Report\WpReporterBridge;
use Funnypot\WordPress\Reputation\WpCache;

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

        // WP-native attack capture (FP-0488) — hooks WP's own login/xmlrpc/REST pipelines. Gated inside
        // each callback, so registering unconditionally is safe.
        WpNativeCapture::register();

        add_action('admin_menu', array(SettingsScreen::class, 'register'));
        add_action('admin_menu', array(IntelDashboard::class, 'register'));
        add_action('admin_init', array(SettingsScreen::class, 'registerSetting'));
        add_action('admin_notices', array(__CLASS__, 'renderNotices'));

        // Installed-set oracle (FP-0395): populate the transient out-of-band so the request path only
        // ever reads it. Invalidate whenever the installed set can change.
        add_action('admin_init', array(__CLASS__, 'warmInstalledSet'));
        add_action('activated_plugin', array(__CLASS__, 'refreshInstalledSet'));
        add_action('deactivated_plugin', array(__CLASS__, 'refreshInstalledSet'));
        add_action('switch_theme', array(__CLASS__, 'refreshInstalledSet'));
        add_action('upgrader_process_complete', array(__CLASS__, 'refreshInstalledSet'));

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
        Interceptor::$installedSetProvider = array(__CLASS__, 'installedSetData');
        // Wire the decoy opt-ins from Settings (stealth forces them off inside decoyMap()).
        Interceptor::$decoys = self::settings()->decoyMap();

        // WP-native capture seams (FP-0488). The deps closure memoizes so the heavy services() factory
        // runs at most once per request even under a system.multicall storm.
        WpNativeCapture::$settingsProvider = array(__CLASS__, 'settings');
        $captureDeps = null;
        WpNativeCapture::$depsProvider = static function () use (&$captureDeps) {
            if ($captureDeps === null) {
                $svc = self::services();
                $captureDeps = array(
                    'hitlog' => isset($svc['hitlog']) ? $svc['hitlog'] : null,
                    'store' => isset($svc['store']) ? $svc['store'] : null,
                );
            }

            return $captureDeps;
        };
        WpNativeCapture::$serverProvider = static function () {
            return isset($_SERVER) ? $_SERVER : array();
        };
    }

    /**
     * The installed-set projection for WpSiteProfile — a transient read only (never get_plugins on the
     * request path). Returns null when the absorber is off, which keeps the blanket real-route oracle.
     *
     * @return array|null
     */
    public static function installedSetData()
    {
        $s = self::settings();
        if (!$s->pluginEnumAbsorber()) {
            return null;
        }

        return self::installedSet()->data();
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

        // Wrap the hit log so an enumeration sweep collapses to one rollup row per source per window.
        $store = isset($services['store']) ? $services['store'] : null;
        if ($log !== null && $store !== null && $s->pluginEnumAbsorber()) {
            $log = new ScanAbsorbingHitLogWriter(
                $log,
                $store,
                $s->enumWindowSecs(),
                $s->enumEscalateThreshold(),
                $s->enumAutoBan(),
                $s->enumBanTtlSecs()
            );
        }

        return new DecisionExecutor(null, null, null, $log, $reporter);
    }

    // --- installed-set oracle (FP-0395) ----------------------------------------------------------

    /**
     * The WpInstalledSet wired to WP primitives. The list callables (get_plugins/wp_get_themes, with the
     * wp-admin include) run ONLY inside refresh() from an admin/cron/activation context — never on the
     * request path, where only the transient getters are touched.
     */
    private static function installedSet()
    {
        return new WpInstalledSet(
            static function ($key) {
                return function_exists('get_transient') ? get_transient($key) : false;
            },
            static function ($key, $value, $ttl) {
                if (function_exists('set_transient')) {
                    set_transient($key, $value, $ttl);
                }
            },
            array(__CLASS__, 'listInstalledPluginSlugs'),
            array(__CLASS__, 'listInstalledThemeSlugs')
        );
    }

    /** Repopulate the installed-set transient (invalidation hooks + activation). Guarded — never fatal. */
    public static function refreshInstalledSet()
    {
        try {
            self::installedSet()->refresh();
        } catch (\Throwable $ignored) {
            // an installed-set refresh fault must never affect admin
        }
    }

    /** First-warm on admin_init when the transient is cold, so a fresh site becomes active without a hook. */
    public static function warmInstalledSet()
    {
        try {
            $set = self::installedSet();
            if (!$set->isKnown()) {
                $set->refresh();
            }
        } catch (\Throwable $ignored) {
            // best-effort warm; a cold set stays fail-safe (blanket behavior)
        }
    }

    /** Installed plugin slugs; loads the wp-admin include here (the caller), not on the request path. */
    public static function listInstalledPluginSlugs()
    {
        if (!function_exists('get_plugins') && defined('ABSPATH')) {
            $inc = ABSPATH . 'wp-admin/includes/plugin.php';
            if (is_readable($inc)) {
                require_once $inc;
            }
        }
        if (!function_exists('get_plugins')) {
            return array();
        }
        $slugs = array();
        foreach (get_plugins() as $file => $data) {
            $slug = dirname((string) $file);
            if ($slug === '.' || $slug === '') {
                $slug = basename((string) $file, '.php'); // single-file plugin (e.g. hello.php)
            }
            if ($slug !== '') {
                $slugs[] = $slug;
            }
        }

        return $slugs;
    }

    /** Installed theme slugs — wp_get_themes() is keyed by the stylesheet directory (the slug). */
    public static function listInstalledThemeSlugs()
    {
        if (!function_exists('wp_get_themes')) {
            return array();
        }

        return array_map('strval', array_keys(wp_get_themes()));
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
        self::refreshInstalledSet(); // first-populate so the oracle is warm from activation onward
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
