<?php

declare(strict_types=1);

namespace Funnypot\WordPress;

/**
 * The two position hooks (design §3, §4.1) driving one PolicyEngine::evaluate() call each. Both entry
 * points are idempotent (a static $ran guard) and config-gated, and the whole normalize->evaluate->
 * execute body is wrapped in a try/catch that degrades any fault to "WP proceeds" — never a 5xx (a 500
 * is itself a tell, invariant §6.2).
 *
 * All movable pieces are settable static seams so the flow is driven by a fake engine + injected spies
 * in tests. 7.3-clean.
 */
final class Interceptor
{
    /** @var bool */
    private static $ranBefore = false;
    /** @var bool */
    private static $ranFallback = false;

    // --- injectable seams (production defaults are wired by Plugin::register) -------------------
    /** @var callable():Settings */
    public static $settingsProvider;
    /** @var callable():array */
    public static $serverProvider;
    /** @var callable():?string */
    public static $rawBodyProvider;
    /** @var callable():bool */
    public static $is404Provider;
    /** @var callable():string which BEFORE hook fired (current_action) */
    public static $currentHookProvider;
    /** @var callable(Settings,string,array):\Funnypot\Policy\PolicyEngine */
    public static $policyFactory;
    /** @var callable(Settings):DecisionExecutor */
    public static $executorProvider;
    /** @var callable(Settings,\Funnypot\WordPress\WpClock):WpStateStore */
    public static $storeProvider;
    /** @var array{xmlrpc:bool,wp_login:bool} decoy opt-ins for WpSiteProfile */
    public static $decoys = array('xmlrpc' => false, 'wp_login' => false);

    /** BEFORE position: hooked at priority 0 on muplugins_loaded (+ plugins_loaded fallback). */
    public static function runBefore()
    {
        if (self::$ranBefore) {
            return;
        }
        self::$ranBefore = true;
        self::handle('before');
    }

    /** FALLBACK position: hooked at priority 0 on template_redirect; only acts on a genuine is_404(). */
    public static function runFallback()
    {
        if (self::$ranFallback) {
            return;
        }
        self::$ranFallback = true;
        self::handle('fallback');
    }

    /** Reset idempotency guards (tests only). */
    public static function reset()
    {
        self::$ranBefore = false;
        self::$ranFallback = false;
    }

    /**
     * Map the observed BEFORE hook + whether BEFORE is configured to the reported mount state
     * (Wordfence gap a). Pure — extracted for unit test.
     *
     * @param string|null $observedHook 'muplugins_loaded' | 'plugins_loaded' | null
     * @param bool        $beforeConfigured
     * @return string
     */
    public static function mountState($observedHook, $beforeConfigured)
    {
        if ($observedHook === 'muplugins_loaded') {
            return 'mu-plugin';
        }
        if ($observedHook === 'plugins_loaded') {
            return 'plugins_loaded (degraded)';
        }

        return $beforeConfigured ? 'not running' : 'n/a';
    }

    // ---------------------------------------------------------------------------------------------

    private static function handle($position)
    {
        $s = self::settings();
        if ($s === null || !$s->enabled()) {
            return; // master switch off -> WP proceeds
        }

        $clock = new WpClock();
        $store = self::store($s, $clock);

        if ($position === 'before') {
            self::recordMount($store, $clock);
            if (!$s->positionActive('before')) {
                return;
            }
        } else {
            if (!$s->positionActive('fallback')) {
                return;
            }
            if (!self::is404()) {
                return; // the FALLBACK position only ever upgrades a genuine 404 (FP-free by construction)
            }
        }

        try {
            $server = self::server();
            $rawBody = self::rawBody();
            $evidence = RequestFactory::evidence($server, $rawBody, $s);

            $is404 = ($position === 'fallback') ? true : null; // BEFORE: the main query has not run
            $wpProfile = new WpSiteProfile($is404, self::$decoys['xmlrpc'], self::$decoys['wp_login']);
            $profile = $wpProfile->toPolicyProfile($evidence->path());

            $ctx = CoreEvaluator::contextFromEvidence($evidence);
            $engine = self::engine($s, $position, array('ctx' => $ctx, 'store' => $store, 'clock' => $clock));

            $decision = $engine->evaluate($evidence, $profile);

            $executor = self::executor($s);
            $executor->execute($decision, $evidence);
        } catch (\Throwable $e) {
            // Any fault degrades to WP-proceeds (Decision::allow); never a 5xx.
            return;
        }
    }

    private static function recordMount($store, $clock)
    {
        try {
            $hook = self::currentHook();
            if ($hook !== '') {
                // Short-TTL marker of which BEFORE hook actually fired (verified mount, Wordfence gap a).
                $store->backend()->set('mount:before', $hook, 600);
            }
        } catch (\Throwable $ignored) {
            // never let mount bookkeeping affect the request
        }
    }

    // --- seam resolution -------------------------------------------------------------------------

    private static function settings()
    {
        if (is_callable(self::$settingsProvider)) {
            return call_user_func(self::$settingsProvider);
        }

        return null;
    }

    private static function server()
    {
        if (is_callable(self::$serverProvider)) {
            return (array) call_user_func(self::$serverProvider);
        }

        return isset($_SERVER) ? $_SERVER : array();
    }

    private static function rawBody()
    {
        if (is_callable(self::$rawBodyProvider)) {
            return call_user_func(self::$rawBodyProvider);
        }

        return null;
    }

    private static function is404()
    {
        if (is_callable(self::$is404Provider)) {
            return (bool) call_user_func(self::$is404Provider);
        }
        if (function_exists('is_404')) {
            return (bool) is_404();
        }

        return false;
    }

    private static function currentHook()
    {
        if (is_callable(self::$currentHookProvider)) {
            return (string) call_user_func(self::$currentHookProvider);
        }
        if (function_exists('current_action')) {
            return (string) current_action();
        }

        return '';
    }

    private static function store($s, $clock)
    {
        if (is_callable(self::$storeProvider)) {
            return call_user_func(self::$storeProvider, $s, $clock);
        }

        return WpStateStore::forSettings($s, $clock);
    }

    private static function engine($s, $position, array $deps)
    {
        if (is_callable(self::$policyFactory)) {
            return call_user_func(self::$policyFactory, $s, $position, $deps);
        }

        return PolicyFactory::forPosition($s, $position, $deps);
    }

    private static function executor($s)
    {
        if (is_callable(self::$executorProvider)) {
            return call_user_func(self::$executorProvider, $s);
        }

        return new DecisionExecutor();
    }
}
