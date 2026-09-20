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
    /** @var bool separate guard for the forced-before pass (FP-0490); see runBeforeForced() */
    private static $ranForced = false;

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
    /** @var callable():?array installed-set oracle for WpSiteProfile; null => blanket behavior */
    public static $installedSetProvider;
    /**
     * @var callable():bool FALLBACK real-route oracle (FP-0504): does WP consider this request a
     * genuine route? Fail-safe-to-genuine — see isGenuineRoute(). Unset => legacy (!is_404()).
     */
    public static $genuineRouteProvider;
    /**
     * @var callable(\Funnypot\Policy\RequestEvidence,string):bool FALLBACK ownership pre-check
     * (FP-0504): does core positively OWN a decoy for this not-genuine path? Unset => the built-in
     * counterfactual classify via the core evaluator (coreProvider); no seam => false (no serve).
     */
    public static $decoyOwnershipProvider;
    /** @var callable(Settings):?object raw core evaluator (Honeypot) provider; memoized by Plugin. */
    public static $coreProvider;

    /** BEFORE position: hooked at priority 0 on muplugins_loaded (+ plugins_loaded fallback). */
    public static function runBefore()
    {
        if (self::$ranBefore) {
            return;
        }
        self::$ranBefore = true;
        self::handle('before');
    }

    /**
     * FALLBACK position: hooked at priority 0 on template_redirect (before redirect_canonical@10).
     * Acts on a genuine is_404(), and — FP-0504 — on a WP-preempted not-genuine path (soft-404 /
     * canonical-redirect / front-page fallthrough) that core positively owns a decoy for.
     */
    public static function runFallback()
    {
        if (self::$ranFallback) {
            return;
        }
        self::$ranFallback = true;
        self::handle('fallback');
    }

    /**
     * Run the BEFORE pass unconditionally, ignoring positionActive('before') (FP-0490). The login
     * relocator calls this from plugins_loaded@1 when the vacated default /wp-login.php should serve
     * the decoy under a posture (honeypot) that leaves the BEFORE position off. It uses a SEPARATE
     * $ranForced guard because runBefore@0 already set $ranBefore=true before returning early at the
     * inactive-before gate — reusing that guard would silently no-op and the decoy would never fire.
     * When BEFORE is active (WAF/both) runBefore@0 has already served + exited, so this never runs.
     */
    public static function runBeforeForced()
    {
        if (self::$ranForced) {
            return;
        }
        self::$ranForced = true;
        self::handle('before', true);
    }

    /** Reset idempotency guards (tests only). */
    public static function reset()
    {
        self::$ranBefore = false;
        self::$ranFallback = false;
        self::$ranForced = false;
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

    /**
     * The FALLBACK real-route oracle (FP-0504). Pure — extracted for unit test. FAIL-SAFE-TO-GENUINE:
     * a request is NOT genuine only when
     *   (a) WP returned a hard 404, or
     *   (b) WP soft-resolved a non-root request to the front page / blog index with an EMPTY main query
     *       (the canonical-redirect / soft-404 junk fallthrough — the /phpmyadmin case).
     * Everything else is genuine and must never be decoyed. The empty-main-query clause is load-bearing:
     * WP suppresses is_home for feed/robots/favicon/search (they are genuine under rule b already), but
     * NOT for SEO-plugin sitemaps (/sitemap.xml, /sitemap_index.xml), which trip is_home=true while core
     * owns them — they carry a `sitemap` query var, so a non-empty main query keeps them genuine here.
     * Ownership is NOT a safety signal: core owns decoys for legitimate no-object endpoints, so this
     * oracle — not the ownership gate — is what protects a real site's surfaces.
     *
     * @param bool $is404        WP resolved a hard 404
     * @param bool $frontOrHome  is_front_page() or is_home() is true
     * @param bool $requestIsRoot the normalised request path is "/"
     * @param bool $mainQueryEmpty WP's main query resolved nothing (empty query_vars)
     * @return bool genuine (true) => never decoy; not genuine (false) => eligible for the ownership check
     */
    public static function isGenuineRoute($is404, $frontOrHome, $requestIsRoot, $mainQueryEmpty)
    {
        if ((bool) $is404) {
            return false;
        }
        if ((bool) $frontOrHome && !((bool) $requestIsRoot) && (bool) $mainQueryEmpty) {
            return false;
        }

        return true;
    }

    // ---------------------------------------------------------------------------------------------

    private static function handle($position, $force = false)
    {
        $s = self::settings();
        if ($s === null || !$s->enabled()) {
            return; // master switch off -> WP proceeds
        }

        $clock = new WpClock();
        $store = self::store($s, $clock);

        if ($position === 'before') {
            // The forced pass (FP-0490) is a targeted re-entry for the vacated login endpoint, not a
            // real BEFORE mount — skip the mount marker so it never mislabels the diagnostic as degraded.
            if (!$force) {
                self::recordMount($store, $clock);
            }
            if (!$force && !$s->positionActive('before')) {
                return;
            }
        } else {
            if (!$s->positionActive('fallback')) {
                return;
            }
        }

        try {
            $server = self::server();
            $rawBody = self::rawBody();
            $evidence = RequestFactory::evidence($server, $rawBody, $s);

            // BEFORE: the main query has not run (only the reserved set is known). FALLBACK: the request
            // is a counterfactual-404 — either a hard 404 or a WP-preempted soft-404 core owns a decoy
            // for; both must report routeExists=false so the engine earns the deceive.
            $realRoute = null;
            if ($position === 'fallback') {
                if (self::isGenuineRequest()) {
                    return; // genuine WP page/endpoint -> never touch it (fail-safe-to-genuine)
                }
                if (!self::is404()) {
                    // WP preempted the path (canonical redirect / soft-404 / front-page fallthrough).
                    // Inert-by-default: stealth/blocked stay WP-normal (the engine would clamp anyway).
                    if (!$s->responseModeServesDecoys()) {
                        return;
                    }
                    // Ownership can only NARROW an already-not-genuine path (never promote a genuine
                    // one — the oracle above ran first). An unowned soft-404 is left to WordPress.
                    if (!self::coreOwnsDecoy($s, $evidence)) {
                        return;
                    }
                }
                $realRoute = false;
            }

            $installedSet = self::installedSet();
            $wpProfile = new WpSiteProfile($realRoute, self::$decoys['xmlrpc'], self::$decoys['wp_login'], $installedSet);
            $profile = $wpProfile->toPolicyProfile($evidence->path());

            $ctx = CoreEvaluator::contextFromEvidence($evidence);
            $engine = self::engine($s, $position, array('ctx' => $ctx, 'store' => $store, 'clock' => $clock) + self::coreDep($s));

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

    private static function installedSet()
    {
        if (!is_callable(self::$installedSetProvider)) {
            return null;
        }
        try {
            $set = call_user_func(self::$installedSetProvider);
            return is_array($set) ? $set : null;
        } catch (\Throwable $ignored) {
            // A provider fault reverts to the blanket oracle (fail-safe), not a broken interception.
            return null;
        }
    }

    /**
     * FALLBACK real-route oracle result (FP-0504). Fail-safe-to-genuine: a provider fault returns
     * genuine so a real page is never decoyed. With no provider wired, fall back to the legacy rule
     * (only a hard 404 is not genuine) so the fallback behaves exactly as before FP-0504.
     */
    private static function isGenuineRequest()
    {
        if (is_callable(self::$genuineRouteProvider)) {
            try {
                return (bool) call_user_func(self::$genuineRouteProvider);
            } catch (\Throwable $ignored) {
                return true; // doubt => genuine (never decoy a real page)
            }
        }

        return !self::is404();
    }

    /**
     * Does core positively OWN a decoy for this (already not-genuine) path? Only ever narrows — the
     * genuine-route oracle has run first. The built-in check classifies with a counterfactual-404
     * profile (routeExists=false) and treats a non-null core fake handle as ownership; any fault or
     * missing core evaluator degrades to "not owned" (WP proceeds), never a serve.
     */
    private static function coreOwnsDecoy($s, $evidence)
    {
        if (is_callable(self::$decoyOwnershipProvider)) {
            return (bool) call_user_func(self::$decoyOwnershipProvider, $evidence, $evidence->path());
        }

        $core = self::coreEvaluator($s);
        if ($core === null) {
            return false;
        }
        $ctx = CoreEvaluator::contextFromEvidence($evidence);
        $cfProfile = (new WpSiteProfile(false, self::$decoys['xmlrpc'], self::$decoys['wp_login'], self::installedSet()))
            ->toPolicyProfile($evidence->path());
        $verdict = (new CoreEvaluator($core, $ctx))->classify($evidence, $cfProfile);

        return $verdict->engineHandle() !== '';
    }

    /** The raw core evaluator (Honeypot) from the memoized provider; null when unavailable. */
    private static function coreEvaluator($s)
    {
        if (is_callable(self::$coreProvider)) {
            try {
                return call_user_func(self::$coreProvider, $s);
            } catch (\Throwable $ignored) {
                return null;
            }
        }

        return null;
    }

    /** Engine dep: reuse the memoized core so the ownership check and evaluate share one build. */
    private static function coreDep($s)
    {
        $core = self::coreEvaluator($s);

        return $core !== null ? array('evaluator' => $core) : array();
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
