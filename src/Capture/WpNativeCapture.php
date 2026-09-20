<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Capture;

use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\Chrome\PageSlots;
use Funnypot\Core\Support\Chrome\WordpressSkin;
use Funnypot\Core\Support\LoginDecoyField;
use Funnypot\Core\Support\VisualPersona;
use Funnypot\Policy\FakeResponse;
use Funnypot\WordPress\EvaluatorConfig;
use Funnypot\WordPress\Http\ResponseEmitter;
use Funnypot\WordPress\RequestFactory;
use Funnypot\WordPress\Settings;

/**
 * Captures attacks that WordPress handles itself — credential stuffing (wp_login_failed), XML-RPC
 * abuse (xmlrpc_call), REST auth-failure / user-enumeration, and XML-RPC pingback SSRF targets
 * (pingback_ping_source_uri) — into the LOCAL hit store, so they reach the operator dashboard even
 * though they never pass through the Interceptor pipeline.
 *
 * Two toggles, two behaviours. wp_native_capture drives the login/xmlrpc/REST callbacks, which are
 * capture-only: they return their incoming argument UNCHANGED, so behaviour is byte-identical whether
 * capture is on or off. wp_pingback_shield drives onPingbackSourceUri, which DOES change the served
 * response: it returns '' so WordPress faults with its canonical error before its own fetch, closing
 * the SSRF/DDoS-relay vector. Either way this path never builds a ReportIntent and never calls the
 * reporter, so nothing new is sent to mainnet.
 *
 * Never logs a real credential: the password is never in scope (we hook wp_login_failed, not
 * authenticate, and it fires only on failure), and a real-account failure is anonymised via a
 * username_exists() self-guard. No submitted username/password/xmlrpc-arg is ever persisted — only IP,
 * a fixed opaque reason, and a bounded User-Agent in the aggregate slot. The one deliberate exception is
 * the pingback source URI: it is attacker-chosen infrastructure (the SSRF/DDoS victim), not a
 * credential, so a bounded, sanitized, length-capped copy is kept in the local `pingback` aggregate slot
 * only — never a durable-row column, never relayed. Any renderer MUST HTML-escape it.
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

    /** Distinct pingback source URIs kept per aggregate slot (bounded memory), same bound as SAMPLE_CAP. */
    const PINGBACK_TARGET_CAP = 8;

    // --- injectable seams (production defaults are wired by Plugin::wireProviders) ------------------
    /** @var callable():?Settings */
    public static $settingsProvider;
    /** @var callable():array {hitlog, store} — resolved once per request (memoized by the provider) */
    public static $depsProvider;
    /** @var callable():array */
    public static $serverProvider;
    /** @var callable():string canonical server-side site host (NOT the client Host header) */
    public static $hostProvider;
    /** @var callable():array the submitted form ($_POST) */
    public static $postProvider;
    /** @var callable(FakeResponse):void emits the fake lockout response; production default exits after emit */
    public static $responder;
    /** @var callable():string the public site title for the fake lockout page (get_bloginfo('name')) */
    public static $siteNameProvider;

    /** Register the WP-native hooks. Gating happens inside each callback at fire time. */
    public static function register()
    {
        if (function_exists('add_action')) {
            add_action('wp_login_failed', array(__CLASS__, 'onLoginFailed'), 10, 1);
            add_action('xmlrpc_call', array(__CLASS__, 'onXmlrpcCall'), 10, 1);
            // Login honeypot field (FP-0505): inject the hidden decoy input into WP's own login form.
            add_action('login_form', array(__CLASS__, 'renderLoginField'));
        }
        if (function_exists('add_filter')) {
            // Pass-through filters: they return their incoming argument unchanged and only side-effect
            // the capture. A wrong return here would break the REST API.
            add_filter('rest_authentication_errors', array(__CLASS__, 'onRestAuthErrors'), 99, 1);
            add_filter('rest_user_query', array(__CLASS__, 'onRestUserQuery'), 10, 2);
            // Pingback shield (behaviour-changing, opt-in via wp_pingback_shield): priority 1 so we see
            // the raw source URI before WP's own wp_http_validate_url (prio 10) would null a private/
            // metadata target. Arity 2 to receive both source and target.
            add_filter('pingback_ping_source_uri', array(__CLASS__, 'onPingbackSourceUri'), 1, 2);
        }
    }

    // --- channel callbacks -----------------------------------------------------------------------

    /**
     * wp_login_failed (action). Drives two INDEPENDENT captures, each behind its own toggle:
     * the login honeypot field (FP-0505) and the native login-failure capture (FP-0488). Only the
     * shared enabled() check is common, so arming one without the other works. The username is used
     * only for the known-account boolean, then discarded; the password never enters scope.
     */
    public static function onLoginFailed($username)
    {
        try {
            $s = self::settings();
            if ($s === null || !$s->enabled()) {
                return;
            }
            // Honeypot detection runs FIRST so that when both toggles are on and the field is tripped,
            // the high-confidence 'login_honeypot_field' reason owns the durable rollup row (the gate
            // writes the row on the first fire per IP/channel/window); the native reason then lands in
            // the aggregate sample only. It also surfaces the trip boolean for the fake-lockout gate.
            $honeypotTripped = false;
            if ($s->loginHoneypotField()) {
                $honeypotTripped = self::detectLoginHoneypot($s);
            }
            if ($s->wpNativeCapture()) {
                $known = function_exists('username_exists') && username_exists((string) $username);
                if ($known) {
                    // A real local account was targeted (or an operator typo): anonymise — store no username.
                    self::capture($s, 'login', 'login_fail_known_user', '/wp-login.php', true);
                } else {
                    self::capture($s, 'login', 'login_failed', '/wp-login.php');
                }
            }

            // Bot-gated fake lockout (FP-0506). Evaluated LAST, after the capture writes, so the intel
            // row is persisted before any exit. It is served ONLY to a suspected bot — the honeypot field
            // was tripped, or a conservative per-IP failed-login velocity was reached — NEVER on a plain
            // failed-login count, so a real user never sees it. The velocity counter is measurement only:
            // it lives on its own key, is read solely by this cosmetic gate, and no auth path consults it.
            // No persistent lock is written and no authenticate/wp_signon hook exists, so the credential
            // decision is untouched and the next correct password always authenticates (even for an IP that
            // tripped velocity behind a shared NAT). Any render/emit fault is swallowed below -> normal WP.
            if ($s->loginFakeLockout()) {
                $velocityHit = self::lockoutVelocityHit($s);
                if ($s->responseModeServesDecoys() && ($honeypotTripped || $velocityHit)) {
                    self::serveFakeLockout($s); // renders + emits + exits; returns only if it declined/faulted
                }
            }
        } catch (\Throwable $ignored) {
            // a capture fault must never break WP login
        }
    }

    /**
     * Passive detection for the login honeypot field: read the ONE decoy key from the submitted form
     * and, if a scripted bot filled it, record a high-confidence signal. The value is inspected for
     * emptiness only — never persisted or reflected — and the password is never touched (only the known
     * decoy key is read). Called from within onLoginFailed's try/catch. Returns whether the field was
     * tripped so the fake-lockout gate can reuse the boolean without re-reading the form.
     */
    private static function detectLoginHoneypot(Settings $s): bool
    {
        $name = self::decoyFieldName($s);
        if ($name === '') {
            return false;
        }
        $post = self::post();
        $v = isset($post[$name]) ? $post[$name] : '';
        if (is_string($v) && trim($v) !== '') {
            self::capture($s, 'login', 'login_honeypot_field', '/wp-login.php');

            return true;
        }

        return false;
    }

    /**
     * Signal 2 for the fake-lockout gate: a conservative per-IP failed-login velocity. Bumps a DEDICATED
     * counter (its own key, decoupled from the wp_native_capture counter so it works with that toggle off)
     * over a 60s rolling window and reports whether the count reached the configured threshold. This is
     * measurement only — the counter is read by nothing on the auth path and enforces nothing. No IP or
     * store => no signal (fall through to normal WP).
     */
    private static function lockoutVelocityHit(Settings $s): bool
    {
        $ip = RequestFactory::clientIp(self::server(), $s);
        if ($ip === '') {
            return false;
        }
        $deps = self::deps();
        $store = isset($deps['store']) ? $deps['store'] : null;
        if ($store === null) {
            return false;
        }

        $n = $store->incr('login_lockout:' . $ip, self::WINDOW_SECS);

        return $n >= $s->loginLockoutVelocity();
    }

    /**
     * Render the vendored core fake-lockout page and emit it at 200 text/html in place of WordPress's own
     * login re-render, then exit. Reuses WordpressSkin::renderLockout unchanged (no core edit). The seed
     * is crc32(seedFor) = host|salt — the SAME per-deploy seed the FP-0505 decoy field name uses — so the
     * "N minutes" and the visual persona are deterministic per deploy and stable on re-scan, with no clock
     * or state read. Every early-out (headers already sent, no host) falls through to normal WordPress; the
     * caller's try/catch swallows any render/emit fault, so this only ever UPGRADES an already-failed
     * request and never faults it (never a 500, which would itself be a tell).
     */
    private static function serveFakeLockout(Settings $s): void
    {
        list($r, $c) = self::loginRequestAndConfig($s);
        if ($r === null) {
            return; // no host -> no-op (fall through to normal WP)
        }
        $seed = crc32($c->seedFor($r));
        $persona = VisualPersona::fromSeed($seed);
        $slots = PageSlots::fromArray(array('app_name' => self::siteName()));
        $escapedPath = self::escAttr('/wp-login.php'); // trusted literal, pre-escaped for the skin
        $taunt = ($s->coreResponseStyle() === 'taunt');
        $html = (new WordpressSkin())->renderLockout($slots, $persona, $escapedPath, $seed, $taunt, '/wp-login.php');

        self::respond(new FakeResponse(200, array(), $html, 'text/html; charset=UTF-8'));
    }

    /**
     * Emit the fake lockout response. The production path (seam unset) writes it via ResponseEmitter and
     * exits, preempting WordPress's login re-render; tests override the seam to capture the response
     * WITHOUT exiting, so the serve is unit-testable. The seam default cannot be a static-property
     * initializer (PHP forbids a closure there), so it is resolved here (mirrors settings()/post()).
     *
     * The headers-already-sent guard lives on the production emit path only: if output has begun we must
     * not emit a broken page, so we return without exit and WordPress renders normally (degrade-safe). A
     * capturing test responder bypasses emit entirely, so the guard never blocks unit testing.
     */
    private static function respond(FakeResponse $fake): void
    {
        if (is_callable(self::$responder)) {
            call_user_func(self::$responder, $fake);

            return;
        }
        if (function_exists('headers_sent') && headers_sent()) {
            return; // output already started -> never emit a broken page; fall through to WP
        }
        ResponseEmitter::emit($fake, 200);
        exit;
    }

    /** The public site title for the fake lockout page (persona fills in when empty); never PII. */
    private static function siteName(): string
    {
        if (is_callable(self::$siteNameProvider)) {
            return (string) call_user_func(self::$siteNameProvider);
        }
        if (function_exists('get_bloginfo')) {
            return (string) get_bloginfo('name');
        }

        return '';
    }

    /**
     * Render the invisible honeypot field into WordPress's own login form (login_form action). A real
     * user never fills it (display:none wrapper + tabindex=-1 + aria-hidden + autocomplete=off); a dumb
     * form-filling bot does. Additive echo only — never alters or blocks a real login. The name is a
     * derived closed-list token (never attacker input) but is escaped for hygiene. Any fault is
     * swallowed so a render error can never break the login page.
     */
    public static function renderLoginField()
    {
        try {
            $s = self::settings();
            if ($s === null || !$s->enabled() || !$s->loginHoneypotField()) {
                return;
            }
            $name = self::decoyFieldName($s);
            if ($name === '') {
                return;
            }
            // The label is a fixed, neutral optional-contact wording; the field NAME is a value picked
            // from the core closed list, so name and label need not match — harmless under display:none,
            // and deliberately not a "leave blank"/trap instruction (that would be a self-unmask tell).
            echo '<p style="display:none" aria-hidden="true"><label>Alternate contact'
                . '<input type="text" name="' . self::escAttr($name) . '" value="" tabindex="-1" autocomplete="off">'
                . '</label></p>';
        } catch (\Throwable $ignored) {
            // a render fault must never break the login page
        }
    }

    /**
     * The decoy field name for this site, derived ONCE for both the render and the detect halves so
     * they agree by construction. Keyed on crc32(seedFor) where seedFor = host|salt (personaSeed is
     * null in EvaluatorConfig): the host comes from the server-side hostProvider (home_url), not the
     * client Host header, so it is request-invariant and un-spoofable — the GET render name equals the
     * POST submit name. Returns '' (callers no-op) when the host is unavailable.
     */
    private static function decoyFieldName(Settings $s)
    {
        list($r, $c) = self::loginRequestAndConfig($s);
        if ($r === null) {
            return '';
        }

        return LoginDecoyField::expectedName($r, $c);
    }

    /**
     * The login-page RequestContext + core Config, built ONCE from the canonical server-side host
     * (home_url via hostProvider — request-invariant and un-spoofable, NOT the client Host header), so the
     * decoy field name (FP-0505) and the fake-lockout seed (FP-0506) both derive from a single source of
     * truth and agree by construction. Returns [null, null] when the host is unavailable (callers no-op).
     *
     * @return array{0:?RequestContext,1:?\Funnypot\Core\Config}
     */
    private static function loginRequestAndConfig(Settings $s): array
    {
        $host = '';
        if (is_callable(self::$hostProvider)) {
            $host = (string) call_user_func(self::$hostProvider);
        }
        if ($host === '') {
            return array(null, null);
        }
        $r = new RequestContext('GET', '/wp-login.php', '', array(), null, $host);
        $c = EvaluatorConfig::fromSettings($s);

        return array($r, $c);
    }

    /** Escape a value for an HTML attribute (WP esc_attr, with the ENT_QUOTES fallback when WP is absent). */
    private static function escAttr($v)
    {
        if (function_exists('esc_attr')) {
            return esc_attr((string) $v);
        }

        return htmlspecialchars((string) $v, ENT_QUOTES);
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

    /**
     * pingback_ping_source_uri (filter). The source URI ($args[0]) is the attacker-chosen URL WordPress
     * would fetch to verify the pingback — i.e. the SSRF / DDoS-reflection target. We capture a bounded,
     * sanitized copy as LOCAL intel and return '' so pingback_ping() faults with its canonical
     * "A valid URL was not provided." error BEFORE its wp_safe_remote_get, meaning WordPress never
     * fetches the URL and this site can never be coerced into an open pingback relay.
     *
     * We NEVER fetch the URL ourselves: no HTTP/socket primitive exists anywhere on this path. Two
     * independent no-fetch guarantees hold — our path has no fetch code, and returning '' makes WordPress
     * short-circuit before its own fetch.
     *
     * Inert unless the shield is enabled: feature off or unconfirmed returns the source UNCHANGED so
     * WordPress behaves exactly as it would without the plugin. Once the feature is confirmed on we always
     * return '' (short-circuit) — even if capture throws — because not-fetching is the safety property.
     */
    public static function onPingbackSourceUri($source, $target = '')
    {
        try {
            $s = self::settings();
        } catch (\Throwable $ignored) {
            return $source; // cannot confirm the feature is on -> stay inert (native WP behaviour)
        }
        if ($s === null || !$s->enabled() || !$s->pingbackShield()) {
            return $source; // feature off -> inert
        }
        // Feature ON: we WILL short-circuit so WordPress never fetches. Capture is best-effort.
        try {
            self::capturePingback($s, (string) $source);
        } catch (\Throwable $ignored) {
            // capture failed; still short-circuit below so no outbound fetch can happen
        }

        return ''; // empty source => canonical pingback_error(0, ...) BEFORE wp_safe_remote_get
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

    /**
     * Record one pingback source URI (the SSRF target) into the local `pingback` channel: bump the
     * per-IP counter, add the sanitized URI to the bounded distinct `targets` sample, and write a durable
     * rollup row ONLY on the first fire in the window. The URL is never a durable-row column (no schema
     * change) and never leaves the local store. Self-contained (independent of wp_native_capture).
     */
    private static function capturePingback(Settings $s, string $source)
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
            return; // no persistence available -> degrade to no-op (still short-circuits in the caller)
        }

        $ua = isset($server['HTTP_USER_AGENT']) ? substr((string) $server['HTTP_USER_AGENT'], 0, 255) : '';
        $method = isset($server['REQUEST_METHOD']) ? (string) $server['REQUEST_METHOD'] : '';
        $sample = self::sanitizeUrlSample($source);

        $n = $store->incr('capture:pingback:' . $ip, self::WINDOW_SECS);
        self::bumpPingbackAggregate($store, $ip, $ua, $sample, $n);

        if ($n === 1) {
            // One durable row per IP per window; later fires bump the aggregate (velocity + more targets)
            // only, so a pingback flood cannot exhaust the hit table.
            $hitlog->record(array(
                'ts' => time(),
                'ip' => $ip,
                'method' => $method,
                'path' => '/xmlrpc.php',
                'action' => 'log',
                'reason' => 'xmlrpc_pingback_target',
                'status' => 0,
            ));
        }
    }

    /**
     * Per-IP pingback aggregate slot (local intel only — never relayed to mainnet). Holds the bounded
     * distinct `targets` sample of captured source URIs, kept confined to this channel so the
     * login/xmlrpc/rest slots never carry a URL.
     */
    private static function bumpPingbackAggregate($store, $ip, $ua, $sample, $n)
    {
        $key = 'capture_agg:pingback:' . $ip;
        $agg = $store->backend()->get($key);
        if (!is_array($agg)) {
            $agg = array(
                'count' => 0,
                'first_ts' => time(),
                'ua' => '',
                'targets' => array(),
            );
        }
        if (!isset($agg['targets']) || !is_array($agg['targets'])) {
            $agg['targets'] = array();
        }

        $agg['count'] = (int) $n;
        if ($ua !== '') {
            $agg['ua'] = substr($ua, 0, 255);
        }
        if ($sample !== ''
            && count($agg['targets']) < self::PINGBACK_TARGET_CAP
            && !in_array($sample, $agg['targets'], true)) {
            $agg['targets'][] = $sample;
        }

        $store->backend()->set($key, $agg, self::AGG_TTL_SECS);
    }

    /**
     * Bound + de-fang a captured source URI: strip control characters/newlines and cap at 255 chars.
     * Stored verbatim otherwise (not urldecoded/normalised — the raw attacker string is the intel). It is
     * local-only and MUST be HTML-escaped by any renderer; this method emits it nowhere.
     */
    private static function sanitizeUrlSample(string $raw): string
    {
        $clean = preg_replace('/[\x00-\x1f\x7f]/', '', $raw);
        if (!is_string($clean)) {
            return ''; // fail-safe: never let raw bytes through on a preg fault
        }
        $clean = trim($clean);
        if (strlen($clean) > 255) {
            $clean = substr($clean, 0, 255);
        }

        return $clean;
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

    private static function post()
    {
        if (is_callable(self::$postProvider)) {
            return (array) call_user_func(self::$postProvider);
        }

        return isset($_POST) ? $_POST : array();
    }
}
