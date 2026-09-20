<?php

declare(strict_types=1);

namespace Funnypot\WordPress;

/**
 * Relocate the real WordPress login to an operator-chosen secret slug and turn the vacated default
 * /wp-login.php (+ the anon /wp-admin bounce that lands there) over to the existing wp-login mock-auth
 * decoy (FP-0490). The technique is re-derived from WPS Hide Login (GPLv2-or-later) in prose — no code,
 * structure, or strings are copied.
 *
 * Three responsibilities, wired from Plugin::register() and each fail-open (try/catch -> WP proceeds to
 * the real login, never a 5xx):
 *   - captureSlug (plugins_loaded@9999): a request on the slug becomes the real login.
 *   - serveSlug   (wp_loaded): run core's genuine wp-login.php for the slug request.
 *   - serveVacatedDefault (plugins_loaded@1): serve the decoy on the non-404 default /wp-login.php.
 *
 * The decoy is served through the ONE existing decision path (Interceptor -> WpSiteProfile -> engine ->
 * DecisionExecutor -> CoreEvaluator) via Interceptor::runBeforeForced() — no parallel renderer, no
 * REQUEST_URI mangling. All movable pieces are settable static seams so the pure logic is unit-testable
 * without WordPress. 7.3-clean.
 */
final class LoginRelocator
{
    /** @var bool true only while the slug page itself is being rendered (scopes URL rewriting). */
    private static $renderingSlug = false;

    // --- injectable seams (production defaults wired by Plugin::wireProviders) --------------------
    /** @var callable():?Settings */
    public static $settingsProvider;
    /** @var callable():array */
    public static $serverProvider;
    /** @var callable():bool */
    public static $isUserLoggedInProvider;
    /** @var callable():void run core's real wp-login.php then exit */
    public static $requireRealLogin;
    /** @var callable():void redirect an already-authed operator to the dashboard then exit */
    public static $redirectToAdmin;

    /** Is the slug page being rendered right now? (the URL-rewrite scope flag) */
    public static function isRenderingSlug()
    {
        return self::$renderingSlug;
    }

    /** Reset transient per-request state (tests only). */
    public static function reset()
    {
        self::$renderingSlug = false;
    }

    // --- the pure routing decision ---------------------------------------------------------------

    /**
     * Classify a request against the relocation config. Pure — no WP calls.
     *
     * @param string $path          the request path (leading slash, no query)
     * @param array  $query         parsed query vars
     * @param bool   $isUserLoggedIn
     * @param bool   $permalinkPretty whether pretty permalinks are in use (informational; both forms
     *                                are handled regardless)
     * @param Settings $s
     * @return string 'real_login' | 'decoy_default' | 'passthrough_default' | 'passthrough'
     */
    public static function route($path, array $query, $isUserLoggedIn, $permalinkPretty, Settings $s)
    {
        if (!$s->loginRelocationActive()) {
            return 'passthrough';
        }

        $slug = $s->loginSlug();
        $norm = strtolower((string) $path);
        if (strlen($norm) > 1) {
            $norm = rtrim($norm, '/');
        }

        // Slug match: pretty form (/slug, /slug/) or plain-permalink form (root + ?slug present).
        $isSlug = ($norm === '/' . $slug);
        if (!$isSlug && ($norm === '' || $norm === '/' || $norm === '/index.php') && array_key_exists($slug, $query)) {
            $isSlug = true;
        }
        if ($isSlug) {
            return 'real_login';
        }

        if ($norm === '/wp-login.php') {
            // Carve-outs -> the real default login, never the decoy: an authed operator must never be
            // mis-served; action=postpass is a legitimate anonymous flow that posts to the default.
            if ($isUserLoggedIn) {
                return 'passthrough_default';
            }
            if (isset($query['action']) && (string) $query['action'] === 'postpass') {
                return 'passthrough_default';
            }

            return 'decoy_default';
        }

        return 'passthrough';
    }

    /**
     * Rewrite a generated login URL to the slug — but ONLY on the slug-render context or for an
     * authenticated user (FP-0490 slug-leak guard). For anonymous, non-slug requests the URL is
     * returned unchanged so it keeps pointing at the default /wp-login.php (the decoy) and the secret
     * slug is never leaked. Pure — table-tested. Scheme, query and trailing-slash form are preserved
     * because only the "wp-login.php" segment is swapped.
     *
     * @param string $url
     * @param string $scheme        the URL scheme context (informational; kept for signature clarity)
     * @param string $slug
     * @param bool   $onSlugContext are we rendering the slug page?
     * @param bool   $isAuthed
     * @return string
     */
    public static function rewriteLoginUrl($url, $scheme, $slug, $onSlugContext, $isAuthed)
    {
        $url = (string) $url;
        $pos = strpos($url, 'wp-login.php');
        if ($slug === '' || $pos === false) {
            return $url;
        }
        if (!$onSlugContext && !$isAuthed) {
            return $url; // slug-leak guard: never hand the slug to an anon, non-slug request
        }

        // Swap only the FIRST occurrence — the path segment. A later "wp-login.php" inside a query
        // value (e.g. a redirect_to) must be left intact.
        return substr($url, 0, $pos) . $slug . substr($url, $pos + strlen('wp-login.php'));
    }

    // --- hook bodies (each fail-open) ------------------------------------------------------------

    /** plugins_loaded@9999: mark a slug request as the login page (runs after Interceptor runBefore@0). */
    public static function captureSlug()
    {
        try {
            $s = self::settings();
            if ($s === null) {
                return;
            }
            $server = self::server();
            if (self::route(self::path($server), self::query($server), self::isUserLoggedIn(), true, $s) !== 'real_login') {
                return;
            }
            self::$renderingSlug = true;
            $GLOBALS['pagenow'] = 'wp-login.php';
            $_SERVER['SCRIPT_NAME'] = '/wp-login.php';
        } catch (\Throwable $e) {
            // fail-open: WP proceeds to the real login
        }
    }

    /** wp_loaded: run the genuine wp-login.php for the slug (logged-in => bounce to the dashboard). */
    public static function serveSlug()
    {
        try {
            if (!self::$renderingSlug) {
                return;
            }
            $s = self::settings();
            if ($s === null || !$s->loginRelocationActive()) {
                return;
            }
            if (self::isUserLoggedIn()) {
                self::redirectToAdmin();
                return;
            }
            self::requireRealLogin();
        } catch (\Throwable $e) {
            // fail-open: WP proceeds to the real login
        }
    }

    /**
     * plugins_loaded@1: serve the decoy on the vacated default /wp-login.php. Under honeypot posture
     * (BEFORE off) the interceptor's own runBefore@0 skipped it, so force the BEFORE pass here — the
     * (auto-armed) wp-login decoy makes /wp-login.php sacrificial and the engine deceives + halts. When
     * BEFORE is active (WAF/both) runBefore@0 already served + exited, so this is never reached.
     */
    public static function serveVacatedDefault()
    {
        try {
            $s = self::settings();
            if ($s === null) {
                return;
            }
            $server = self::server();
            if (self::route(self::path($server), self::query($server), self::isUserLoggedIn(), true, $s) !== 'decoy_default') {
                return;
            }
            if (!$s->positionActive('before')) {
                Interceptor::runBeforeForced();
            }
        } catch (\Throwable $e) {
            // fail-open: WP proceeds (the real login is served on the default)
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

    private static function isUserLoggedIn()
    {
        if (is_callable(self::$isUserLoggedInProvider)) {
            return (bool) call_user_func(self::$isUserLoggedInProvider);
        }

        return function_exists('is_user_logged_in') ? (bool) is_user_logged_in() : false;
    }

    private static function requireRealLogin()
    {
        if (is_callable(self::$requireRealLogin)) {
            call_user_func(self::$requireRealLogin);
            return;
        }
        if (defined('ABSPATH')) {
            require ABSPATH . 'wp-login.php';
        }
        exit;
    }

    private static function redirectToAdmin()
    {
        if (is_callable(self::$redirectToAdmin)) {
            call_user_func(self::$redirectToAdmin);
            return;
        }
        if (function_exists('wp_safe_redirect') && function_exists('admin_url')) {
            wp_safe_redirect(admin_url());
        }
        exit;
    }

    /** The request path (leading slash, query stripped) from a $_SERVER-shaped array. */
    private static function path(array $server)
    {
        $uri = isset($server['REQUEST_URI']) ? (string) $server['REQUEST_URI'] : '/';
        $pos = strpos($uri, '?');
        $p = $pos === false ? $uri : substr($uri, 0, $pos);

        return $p === '' ? '/' : $p;
    }

    /** Parsed query vars from a $_SERVER-shaped array (QUERY_STRING or the REQUEST_URI tail). */
    private static function query(array $server)
    {
        $qs = isset($server['QUERY_STRING']) ? (string) $server['QUERY_STRING'] : '';
        if ($qs === '' && isset($server['REQUEST_URI'])) {
            $uri = (string) $server['REQUEST_URI'];
            $pos = strpos($uri, '?');
            if ($pos !== false) {
                $qs = substr($uri, $pos + 1);
            }
        }
        $out = array();
        if ($qs !== '') {
            parse_str($qs, $out);
        }

        return $out;
    }
}
