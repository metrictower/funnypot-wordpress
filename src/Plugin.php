<?php

declare(strict_types=1);

namespace Funnypot\WordPress;

use Funnypot\WordPress\Admin\IntelDashboard;
use Funnypot\WordPress\Admin\Notices;
use Funnypot\WordPress\Admin\SettingsScreen;
use Funnypot\WordPress\Capture\WpNativeCapture;
use Funnypot\WordPress\Cli\HoneypotCommand;
use Funnypot\WordPress\Geo\GeoIpRefresh;
use Funnypot\WordPress\Http\ResponseEmitter;
use Funnypot\WordPress\Log\ScanAbsorbingHitLogWriter;
use Funnypot\WordPress\Log\WpdbHitLogWriter;
use Funnypot\Core\Rules\RulesLocator;
use Funnypot\Core\Rules\RulesUpdater;
use Funnypot\WordPress\Mirror\BlacklistMirror;
use Funnypot\WordPress\Report\WpdbReportQueue;
use Funnypot\WordPress\Rules\RulesAutoUpdate;
use Funnypot\WordPress\Rules\WpRemoteRulesFetcher;
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
    const HOOK_RULES_PULL = 'honeypot_wp_rules_pull';

    /** @var string the main plugin file */
    private static $file = '';
    /** @var bool */
    private static $providersReady = false;
    /** @var \Funnypot\Core\Contracts\Evaluator|null memoized per-request core evaluator (FP-0504) */
    private static $coreEvaluatorMemo = null;

    /** Called from the plugin main file at ordinary plugin load. */
    public static function register($file)
    {
        self::$file = (string) $file;
        self::wireProviders();

        // READ seam for the auto-updated corpus (FP-0502): point rule resolution at the pulled data
        // dir BEFORE the engine is constructed (it is built lazily at hook time, well after this).
        // Without it a cron pull would write a corpus the engine never serves.
        self::maybeUseRulesDataDir();

        // BEFORE position fallback (when the mu-shim is absent) + the FALLBACK 404 position.
        add_action('plugins_loaded', array(Interceptor::class, 'runBefore'), 0);
        add_action('template_redirect', array(Interceptor::class, 'runFallback'), 0);

        // WP-native attack capture (FP-0488) — hooks WP's own login/xmlrpc/REST pipelines. Gated inside
        // each callback, so registering unconditionally is safe.
        WpNativeCapture::register();

        // Login relocation (FP-0490). Single-site only in v1 (multisite left unhandled, not half-broken)
        // and only when a valid slug + toggle are set. captureSlug@9999 runs after Interceptor
        // runBefore@0; serveVacatedDefault@1 forces the BEFORE decoy on the vacated default under
        // honeypot posture. The slug-scoped URL rewriters fast-path out unless a login URL is built.
        $multisite = function_exists('is_multisite') && is_multisite();
        if (!$multisite && self::settings()->loginRelocationActive()) {
            add_action('plugins_loaded', array(LoginRelocator::class, 'captureSlug'), 9999);
            add_action('plugins_loaded', array(LoginRelocator::class, 'serveVacatedDefault'), 1);
            add_action('wp_loaded', array(LoginRelocator::class, 'serveSlug'));
            add_filter('site_url', array(__CLASS__, 'filterSiteUrl'), 10, 4);
            add_filter('network_site_url', array(__CLASS__, 'filterNetworkSiteUrl'), 10, 3);
            add_filter('logout_url', array(__CLASS__, 'filterLogoutUrl'), 10, 2);
        }

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

        // Reconcile the rules-pull schedule when the option changes, so toggling auto-update on/off (or
        // changing the interval) takes effect without a reactivation.
        add_action('add_option_' . self::OPTION, array(__CLASS__, 'reconcileRulesSchedule'));
        add_action('update_option_' . self::OPTION, array(__CLASS__, 'reconcileRulesSchedule'));

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
        // Same READ seam as register() (FP-0502): the mu path builds the engine at muplugins_loaded, so
        // the data dir must be pointed at here too, before that hook fires.
        self::maybeUseRulesDataDir();
        add_action('muplugins_loaded', array(Interceptor::class, 'runBefore'), 0);
    }

    /**
     * Point rule resolution at the auto-updated data dir when the feature is on (FP-0502). Gating on
     * the toggle keeps disabling the feature a clean off-switch back to the bundled corpus; RulesLocator
     * self-heals to the bundled floor anyway when the data dir is missing or empty. Single-site only in
     * v1 — on multisite the data dir is per-blog while the engine data is global, so leave it unhandled
     * (bundled floor), mirroring the login-relocation v1 posture.
     */
    private static function maybeUseRulesDataDir()
    {
        try {
            $multisite = function_exists('is_multisite') && is_multisite();
            if ($multisite) {
                return;
            }
            if (self::settings()->rulesAutoUpdateEnabled()) {
                RulesLocator::useDataDir(self::rulesDir());
            }
        } catch (\Throwable $ignored) {
            // never let a resolution-dir choice fault the boot path (fail-safe to the bundled floor)
        }
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
        // FALLBACK real-route oracle (FP-0504): feed the pure fail-safe-to-genuine helper WP booleans,
        // each function_exists/isset-guarded with doubt => genuine. query_vars is populated by
        // WP::parse_request before template_redirect, so it is readable at our @0 hook.
        Interceptor::$genuineRouteProvider = static function () {
            $is404 = function_exists('is_404') && is_404();
            $frontOrHome = (function_exists('is_front_page') && is_front_page())
                || (function_exists('is_home') && is_home());

            return Interceptor::isGenuineRoute($is404, $frontOrHome, self::requestPathIsRoot(), self::mainQueryEmpty());
        };
        // Memoized raw core evaluator, shared by the ownership pre-check and the engine build so a
        // not-genuine owned path never compiles the rules artifact twice in one request. The built-in
        // ownership check (Interceptor::coreOwnsDecoy) uses this; no separate ownership seam is wired.
        Interceptor::$coreProvider = array(__CLASS__, 'coreEvaluator');
        // Wire the decoy opt-ins from Settings (stealth forces them off inside decoyMap()). On
        // multisite the relocation hooks are not mounted (v1 single-site only), so the relocation-driven
        // wp-login decoy auto-arm must be suppressed too — otherwise the accept-any decoy would shadow
        // a real, un-relocated /wp-login.php and lock the operator out. The explicit decoy_wp_login
        // toggle still applies. is_multisite() is available at this hook.
        $multisite = function_exists('is_multisite') && is_multisite();
        Interceptor::$decoys = self::settings()->decoyMap($multisite ? false : null);

        // Login relocation seams (FP-0490). Each hook is fail-open (try/catch -> real login).
        LoginRelocator::$settingsProvider = array(__CLASS__, 'settings');
        LoginRelocator::$serverProvider = static function () {
            return isset($_SERVER) ? $_SERVER : array();
        };
        LoginRelocator::$isUserLoggedInProvider = static function () {
            return function_exists('is_user_logged_in') ? (bool) is_user_logged_in() : false;
        };
        LoginRelocator::$requireRealLogin = static function () {
            if (defined('ABSPATH')) {
                require ABSPATH . 'wp-login.php';
            }
            exit;
        };
        LoginRelocator::$redirectToAdmin = static function () {
            if (function_exists('wp_safe_redirect') && function_exists('admin_url')) {
                wp_safe_redirect(admin_url());
            }
            exit;
        };

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
        // Login honeypot field (FP-0505). The host is the canonical server-side site host (home_url),
        // request-invariant and un-spoofable, so the GET render name equals the POST submit name; NOT
        // the client Host header. Both seams are function_exists/isset-guarded -> degrade to empty (the
        // render/detect then no-op) if WP is not fully loaded.
        WpNativeCapture::$hostProvider = static function () {
            if (!function_exists('home_url') || !function_exists('wp_parse_url')) {
                return '';
            }

            return (string) (wp_parse_url(home_url(), PHP_URL_HOST) ?: '');
        };
        WpNativeCapture::$postProvider = static function () {
            return isset($_POST) ? $_POST : array();
        };
        // Bot-gated fake lockout (FP-0506). The responder emits the core lockout page at 200 then exits,
        // preempting WordPress's own login re-render on an ALREADY-FAILED request (post-auth; no auth hook,
        // no persistent lock). The site-name provider is the public blog title (escaped by the skin);
        // both degrade to a safe default when WordPress is not fully loaded.
        WpNativeCapture::$responder = static function ($fake) {
            ResponseEmitter::emit($fake, 200);
            exit;
        };
        WpNativeCapture::$siteNameProvider = static function () {
            return function_exists('get_bloginfo') ? (string) get_bloginfo('name') : '';
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

    /**
     * The raw core evaluator (Honeypot), memoized for the request so the FP-0504 ownership pre-check
     * and the engine build share one compile of the rules artifact. A build fault returns null (the
     * interceptor then treats the path as unowned and lets WordPress proceed).
     *
     * @param Settings|null $s
     * @return \Funnypot\Core\Contracts\Evaluator|null
     */
    public static function coreEvaluator($s = null)
    {
        if (self::$coreEvaluatorMemo !== null) {
            return self::$coreEvaluatorMemo;
        }
        try {
            $s = $s instanceof Settings ? $s : self::settings();
            self::$coreEvaluatorMemo = \Funnypot\Core\Honeypot::default(EvaluatorConfig::fromSettings($s));
        } catch (\Throwable $ignored) {
            return null;
        }

        return self::$coreEvaluatorMemo;
    }

    /** Is the current request path the site root "/"? (FP-0504 oracle input; doubt => false). */
    private static function requestPathIsRoot()
    {
        $uri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '';
        $path = (string) parse_url($uri, PHP_URL_PATH);
        if ($path === '') {
            return false;
        }

        return rtrim($path, '/') === '' ; // "/" or "" after trimming trailing slashes
    }

    /**
     * Did WP's main query resolve nothing (empty query_vars)? The discriminator between a true junk
     * fallthrough (/phpmyadmin => empty) and a real custom-var endpoint (SEO sitemaps carry `sitemap`).
     * query_vars is populated by WP::parse_request before template_redirect. Doubt (unset/unreadable)
     * => false, so the not-genuine conjunction fails and the path stays genuine (FP-0504 fail-safe).
     */
    private static function mainQueryEmpty()
    {
        if (!isset($GLOBALS['wp']) || !is_object($GLOBALS['wp'])) {
            return false;
        }
        if (!isset($GLOBALS['wp']->query_vars) || !is_array($GLOBALS['wp']->query_vars)) {
            return false;
        }

        return empty($GLOBALS['wp']->query_vars);
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

        // Corpus auto-update (FP-0502): a thin cron service over core's signed RulesUpdater. The updater
        // is built through a factory so the exec-free WP fetcher + channel are wired here while the
        // service stays free of core construction (and unit-testable with an injected updater).
        $rulesFactory = static function ($dir) use ($s) {
            return new RulesUpdater(
                (string) $dir,
                $s->rulesChannel(),
                null,
                RulesAutoUpdate::REPO_BASE_URL,
                new WpRemoteRulesFetcher()
            );
        };
        $rules = new RulesAutoUpdate($s, self::rulesDir(), $rulesFactory, $store->backend(), static function () use ($clock) {
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
            'rules' => $rules,
        );
    }

    // --- login relocation URL rewriting (FP-0490) ------------------------------------------------

    /**
     * site_url filter: rewrite a built login URL to the slug, scoped to the slug-render context or an
     * authenticated user (slug-leak guard). Fast-paths out unless the URL builds wp-login.php.
     */
    public static function filterSiteUrl($url, $path = '', $scheme = null, $blogId = null)
    {
        return self::rewriteLogin($url, (string) $scheme);
    }

    /** network_site_url filter (3 args). Same slug-scoped rewrite as filterSiteUrl. */
    public static function filterNetworkSiteUrl($url, $path = '', $scheme = null)
    {
        return self::rewriteLogin($url, (string) $scheme);
    }

    /** logout_url filter: authed-only by nature (a logout link is only ever shown to a logged-in user). */
    public static function filterLogoutUrl($url, $redirect = '')
    {
        try {
            if (strpos((string) $url, 'wp-login.php') === false) {
                return $url;
            }

            return LoginRelocator::rewriteLoginUrl(
                $url,
                'logout',
                self::settings()->loginSlug(),
                false,
                self::currentUserLoggedIn()
            );
        } catch (\Throwable $e) {
            return $url; // fail-open: leave the URL as WP built it
        }
    }

    private static function rewriteLogin($url, $scheme)
    {
        try {
            if (strpos((string) $url, 'wp-login.php') === false) {
                return $url; // fast path — the vast majority of site_url() calls
            }

            return LoginRelocator::rewriteLoginUrl(
                $url,
                $scheme,
                self::settings()->loginSlug(),
                LoginRelocator::isRenderingSlug(),
                self::currentUserLoggedIn()
            );
        } catch (\Throwable $e) {
            return $url; // fail-open
        }
    }

    private static function currentUserLoggedIn()
    {
        return function_exists('is_user_logged_in') ? (bool) is_user_logged_in() : false;
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
        foreach (self::cronHooks() as $hook) {
            $ts = function_exists('wp_next_scheduled') ? wp_next_scheduled($hook) : false;
            if ($ts && function_exists('wp_unschedule_event')) {
                wp_unschedule_event($ts, $hook);
            }
        }
    }

    // --- cron ------------------------------------------------------------------------------------

    /** Every cron hook this plugin owns — the set deactivate() clears. */
    public static function cronHooks()
    {
        return array(
            self::HOOK_REPORT_DRAIN,
            self::HOOK_WARMER,
            self::HOOK_MIRROR_PULL,
            self::HOOK_GEOIP_REFRESH,
            self::HOOK_RULES_PULL,
        );
    }

    private static function registerCron()
    {
        add_action(self::HOOK_REPORT_DRAIN, array(__CLASS__, 'cronReportDrain'));
        add_action(self::HOOK_WARMER, array(__CLASS__, 'cronWarmer'));
        add_action(self::HOOK_MIRROR_PULL, array(__CLASS__, 'cronMirrorPull'));
        add_action(self::HOOK_GEOIP_REFRESH, array(__CLASS__, 'cronGeoipRefresh'));
        add_action(self::HOOK_RULES_PULL, array(__CLASS__, 'cronRulesPull'));
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
        // Corpus auto-update (FP-0502): schedule only when the toggle is on, at the configured
        // interval, with a per-host jittered first run so a fleet does not stampede the release host.
        $interval = RulesAutoUpdate::desiredSchedule(self::settings());
        if ($interval !== null && !wp_next_scheduled(self::HOOK_RULES_PULL)) {
            $jitter = (int) abs(crc32((string) gethostname()) % 3600);
            wp_schedule_event($now + $jitter, $interval, self::HOOK_RULES_PULL);
        }
    }

    /**
     * Reschedule/unschedule the rules-pull when the settings option changes: clear the existing event
     * and re-add it only if the toggle is on (picking up an interval change). The other events are
     * re-added idempotently. Integration-level; guarded so an option save never fatals.
     */
    public static function reconcileRulesSchedule()
    {
        $ts = function_exists('wp_next_scheduled') ? wp_next_scheduled(self::HOOK_RULES_PULL) : false;
        if ($ts && function_exists('wp_unschedule_event')) {
            wp_unschedule_event($ts, self::HOOK_RULES_PULL);
        }
        if (function_exists('wp_schedule_event')) {
            self::scheduleEvents();
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

    public static function cronRulesPull()
    {
        $svc = self::services();
        if (isset($svc['rules']) && $svc['rules'] !== null) {
            $svc['rules']->run();
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

    /**
     * Where the auto-updated corpus is written and read from (FP-0502). Defaults to an uploads subdir
     * the plugin already knows how to create; override with the HONEYPOT_WP_RULES_DIR constant to place
     * it OUTSIDE the web root — the least-privilege posture, since the dir holds require'd PHP.
     */
    private static function rulesDir()
    {
        if (defined('HONEYPOT_WP_RULES_DIR')) {
            return (string) constant('HONEYPOT_WP_RULES_DIR');
        }
        if (function_exists('wp_upload_dir')) {
            $up = wp_upload_dir();
            if (is_array($up) && isset($up['basedir'])) {
                return $up['basedir'] . '/honeypot-wp-rules';
            }
        }

        return sys_get_temp_dir() . '/honeypot-wp-rules';
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
