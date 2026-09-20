<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Capture;

use Funnypot\WordPress\RequestFactory;
use Funnypot\WordPress\Settings;

/**
 * Captures attacks that WordPress handles itself — credential stuffing (wp_login_failed), XML-RPC
 * abuse (xmlrpc_call), and REST auth-failure / user-enumeration — into the LOCAL hit store, so they
 * reach the operator dashboard even though they never pass through the Interceptor pipeline.
 *
 * Capture-only: the two filter callbacks return their incoming argument UNCHANGED, so login/xmlrpc/REST
 * behaviour is byte-identical whether capture is on or off. Local intel only — this path never builds a
 * ReportIntent and never calls the reporter, so nothing new is sent to mainnet.
 *
 * Never logs a real credential: the password is never in scope (we hook wp_login_failed, not
 * authenticate, and it fires only on failure), and a real-account failure is anonymised via a
 * username_exists() self-guard. No submitted username/password/xmlrpc-arg/pingback-URL is ever
 * persisted — only IP, a fixed opaque reason, and a bounded User-Agent in the aggregate slot.
 *
 * Durable rows are rollup-gated per IP per channel per window (mirrors ScanAbsorbingHitLogWriter): the
 * first fire in the window writes one row, later fires in the window bump the aggregate slot only. So an
 * N-way system.multicall (which fires xmlrpc_call N times) can never exhaust the hit table.
 *
 * All movable pieces are settable static seams so the flow is driven by fakes in tests (mirrors the
 * Interceptor). Degrade-safe: every callback body is wrapped so a fault never breaks WP. 7.3-clean.
 */
final class WpNativeCapture
{
    /** Row-collapse window: at most one durable row per IP per channel per window. */
    const WINDOW_SECS = 60;

    /** Aggregate-slot TTL. Longer than the collapse window so a recently-quiet IP keeps a readable UA
     *  for the dashboard; the row bound comes from the counter window, so this never weakens the gate. */
    const AGG_TTL_SECS = 3600;

    /** Distinct reason labels kept per aggregate slot (bounded memory). */
    const SAMPLE_CAP = 8;

    // --- injectable seams (production defaults are wired by Plugin::wireProviders) ------------------
    /** @var callable():?Settings */
    public static $settingsProvider;
    /** @var callable():array {hitlog, store} — resolved once per request (memoized by the provider) */
    public static $depsProvider;
    /** @var callable():array */
    public static $serverProvider;

    /** Register the four WP-native hooks. Gating happens inside each callback at fire time. */
    public static function register()
    {
        if (function_exists('add_action')) {
            add_action('wp_login_failed', array(__CLASS__, 'onLoginFailed'), 10, 1);
            add_action('xmlrpc_call', array(__CLASS__, 'onXmlrpcCall'), 10, 1);
        }
        if (function_exists('add_filter')) {
            // Pass-through filters: they return their incoming argument unchanged and only side-effect
            // the capture. A wrong return here would break the REST API.
            add_filter('rest_authentication_errors', array(__CLASS__, 'onRestAuthErrors'), 99, 1);
            add_filter('rest_user_query', array(__CLASS__, 'onRestUserQuery'), 10, 2);
        }
    }

    // --- channel callbacks -----------------------------------------------------------------------

    /** wp_login_failed (action). The username is used only for the known-account boolean, then discarded. */
    public static function onLoginFailed($username)
    {
        try {
            $s = self::settings();
            if ($s === null || !$s->enabled() || !$s->wpNativeCapture()) {
                return;
            }
            $known = function_exists('username_exists') && username_exists((string) $username);
            if ($known) {
                // A real local account was targeted (or an operator typo): anonymise — store no username.
                self::capture($s, 'login', 'login_fail_known_user', '/wp-login.php', true);
            } else {
                self::capture($s, 'login', 'login_failed', '/wp-login.php');
            }
        } catch (\Throwable $ignored) {
            // a capture fault must never break WP login
        }
    }

    /** xmlrpc_call (action). Reads only the method name (a fixed vocabulary); args are never touched. */
    public static function onXmlrpcCall($name)
    {
        try {
            $s = self::settings();
            if ($s === null || !$s->enabled() || !$s->wpNativeCapture()) {
                return;
            }
            self::capture($s, 'xmlrpc', self::xmlrpcReason((string) $name), '/xmlrpc.php');
        } catch (\Throwable $ignored) {
            // a capture fault must never break XML-RPC
        }
    }

    /** rest_authentication_errors (filter). Returns the incoming value UNCHANGED in every branch. */
    public static function onRestAuthErrors($errors)
    {
        try {
            $s = self::settings();
            if ($s !== null && $s->enabled() && $s->wpNativeCapture() && $errors instanceof \WP_Error) {
                self::capture($s, 'rest', 'rest_auth_failed', '/wp-json');
            }
        } catch (\Throwable $ignored) {
            // never assert/deny auth on a capture fault
        }

        return $errors;
    }

    /**
     * rest_user_query (filter). Fires for legitimate authenticated collection queries too (block-editor
     * author selector, admin users screen), so capture is gated to unauthenticated requests. Returns the
     * incoming prepared args UNCHANGED in every branch.
     */
    public static function onRestUserQuery($preparedArgs, $request = null)
    {
        try {
            $s = self::settings();
            if ($s !== null && $s->enabled() && $s->wpNativeCapture()
                && !(function_exists('is_user_logged_in') && is_user_logged_in())) {
                self::capture($s, 'rest', 'rest_user_enum', '/wp-json/wp/v2/users');
            }
        } catch (\Throwable $ignored) {
            // capture is a side-effect only; the query args are never altered
        }

        return $preparedArgs;
    }

    // --- capture core (rollup-gated) -------------------------------------------------------------

    /**
     * Record one WP-native attempt: bump the per-IP-per-channel counter, always update the aggregate
     * slot, and write a durable rollup row ONLY on the first fire in the window. No submitted
     * username/password/arg/URL ever reaches the row or the slot.
     */
    private static function capture(Settings $s, $channel, $reason, $path, $realUserTargeted = false)
    {
        $server = self::server();
        $ip = RequestFactory::clientIp($server, $s);
        if ($ip === '') {
            return;
        }

        $deps = self::deps();
        $hitlog = isset($deps['hitlog']) ? $deps['hitlog'] : null;
        $store = isset($deps['store']) ? $deps['store'] : null;
        if ($hitlog === null || $store === null) {
            return; // no persistence available (e.g. $wpdb === null) -> degrade to no-op
        }

        $ua = isset($server['HTTP_USER_AGENT']) ? substr((string) $server['HTTP_USER_AGENT'], 0, 255) : '';
        $method = isset($server['REQUEST_METHOD']) ? (string) $server['REQUEST_METHOD'] : '';

        $n = $store->incr('capture:' . $channel . ':' . $ip, self::WINDOW_SECS);
        self::bumpAggregate($store, $channel, $ip, $ua, $reason, $realUserTargeted, $n);

        if ($n === 1) {
            // One durable row per IP per channel per window; later fires in the window are the aggregate
            // count (velocity) only, so a system.multicall burst cannot exhaust the hit table.
            $hitlog->record(array(
                'ts' => time(),
                'ip' => $ip,
                'method' => $method,
                'path' => $path,
                'action' => 'log',
                'reason' => $reason,
                'status' => 0,
            ));
        }
    }

    /** Per-IP-per-channel aggregate slot (local intel only — never relayed to mainnet). */
    private static function bumpAggregate($store, $channel, $ip, $ua, $reason, $realUserTargeted, $n)
    {
        $key = 'capture_agg:' . $channel . ':' . $ip;
        $agg = $store->backend()->get($key);
        if (!is_array($agg)) {
            $agg = array(
                'count' => 0,
                'first_ts' => time(),
                'ua' => '',
                'reasons_sample' => array(),
                'real_user_targeted' => false,
            );
        }
        if (!isset($agg['reasons_sample']) || !is_array($agg['reasons_sample'])) {
            $agg['reasons_sample'] = array();
        }

        $agg['count'] = (int) $n;
        if ($ua !== '') {
            $agg['ua'] = substr($ua, 0, 255);
        }
        if (count($agg['reasons_sample']) < self::SAMPLE_CAP && !in_array($reason, $agg['reasons_sample'], true)) {
            $agg['reasons_sample'][] = $reason;
        }
        if ($realUserTargeted) {
            $agg['real_user_targeted'] = true;
        }

        $store->backend()->set($key, $agg, self::AGG_TTL_SECS);
    }

    /** Map the (fixed-vocabulary) XML-RPC method name to an opaque reason label. Never attacker free-text. */
    private static function xmlrpcReason($name)
    {
        switch ($name) {
            case 'wp.getUsersBlogs':
            case 'wp.getUsers':
            case 'blogger.getUsersBlogs':
                return 'xmlrpc_cred_check';
            case 'system.multicall':
                return 'xmlrpc_multicall';
            case 'pingback.ping':
                return 'xmlrpc_pingback';
            default:
                return 'xmlrpc_call';
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

    private static function deps()
    {
        if (is_callable(self::$depsProvider)) {
            $d = call_user_func(self::$depsProvider);

            return is_array($d) ? $d : array();
        }

        return array();
    }

    private static function server()
    {
        if (is_callable(self::$serverProvider)) {
            return (array) call_user_func(self::$serverProvider);
        }

        return isset($_SERVER) ? $_SERVER : array();
    }
}
