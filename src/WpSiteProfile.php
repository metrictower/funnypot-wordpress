<?php

declare(strict_types=1);

namespace Funnypot\WordPress;

use Funnypot\Policy\SiteProfile;

/**
 * The declared stack + real-route oracle (design §4.2) — the single most important FP-safety input.
 * Only WordPress knows its own routes, so this is the one job the host must do. D authors NO
 * decision logic here; the oracle is DATA the position-blind engine consumes.
 *
 * `funnypot-policy`'s SiteProfile is a final value object keyed on exact path sets, so this builder
 * computes routeExists/isSacrificialPath with WP-aware prefix + is_404 logic and projects the answer
 * for the request's own path into a concrete SiteProfile via toPolicyProfile(). 7.3-clean.
 */
final class WpSiteProfile
{
    const STACK = 'wordpress';

    /** Genuine-WP reserved exact paths (always real routes). */
    private static $reservedExact = array(
        '/',
        '/wp-cron.php',
        '/wp-comments-post.php',
        '/wp-signup.php',
        '/wp-activate.php',
        '/wp-trackback.php',
    );

    /** Genuine-WP reserved prefixes (any path beneath is a real route). */
    private static $reservedPrefixes = array(
        '/wp-admin/',
        '/wp-json/',
        '/wp-includes/',
        '/wp-content/uploads/',
        '/wp-content/plugins/',
        '/wp-content/themes/',
    );

    /** Provably-nonexistent-on-a-stock-WP paths — the day-1 auto-enforce carve-out set. */
    private static $sacrificial = array(
        '/.env',
        '/.env.bak',
        '/.env.local',
        '/.git/config',
        '/.git/head',
        '/wp-config.php.bak',
        '/wp-config.php~',
        '/wp-config.php.save',
        '/wp-config.php.orig',
        '/wp-content/debug.log',
        '/.aws/credentials',
        '/.ssh/id_rsa',
        '/.svn/entries',
        '/config.php.bak',
        '/backup.sql',
        '/database.sql',
    );

    /** @var bool|callable|null is_404 seam; null at BEFORE (main query not run yet) */
    private $is404;
    /** @var bool xmlrpc decoy opted in AND real feature disabled */
    private $xmlrpcDecoy;
    /** @var bool wp-login decoy opted in AND real feature disabled */
    private $wpLoginDecoy;

    /**
     * @param bool|callable|null $is404        FALLBACK: the resolved is_404() (bool or fn():bool);
     *                                         BEFORE: null (only the static reserved set is known)
     * @param bool               $xmlrpcDecoy  xmlrpc.php becomes sacrificial only when true
     * @param bool               $wpLoginDecoy wp-login.php becomes sacrificial only when true
     */
    public function __construct($is404 = null, $xmlrpcDecoy = false, $wpLoginDecoy = false)
    {
        $this->is404 = $is404;
        $this->xmlrpcDecoy = (bool) $xmlrpcDecoy;
        $this->wpLoginDecoy = (bool) $wpLoginDecoy;
    }

    public function stack()
    {
        return self::STACK;
    }

    /** Does this path resolve to a route that actually EXISTS on this site? (the FP-safety oracle) */
    public function routeExists(string $path)
    {
        $p = self::normalize($path);

        if ($p === '/xmlrpc.php') {
            return !$this->xmlrpcDecoy;
        }
        if ($p === '/wp-login.php') {
            return !$this->wpLoginDecoy;
        }
        if (in_array($p, self::$reservedExact, true)) {
            return true;
        }
        foreach (self::$reservedPrefixes as $prefix) {
            // Match a path beneath the prefix, or the bare directory itself (trailing slash stripped).
            if (strpos($p, $prefix) === 0 || $p === rtrim($prefix, '/')) {
                return true;
            }
        }

        // Non-reserved: only the FALLBACK position knows whether WP resolved a real post.
        if ($this->is404 !== null) {
            return $this->resolveIs404() === false;
        }

        return false;
    }

    /** Is this path in the sacrificial set (provably doesn't exist on a stock WP install)? */
    public function isSacrificialPath(string $path)
    {
        $p = self::normalize($path);

        if ($p === '/xmlrpc.php') {
            return $this->xmlrpcDecoy;
        }
        if ($p === '/wp-login.php') {
            return $this->wpLoginDecoy;
        }

        return in_array($p, self::$sacrificial, true);
    }

    /**
     * Project this oracle's answer for the request's own path into a concrete policy SiteProfile.
     * The engine only ever queries the profile for the current request path, so a per-request
     * projection is exact. The EXACT request path is used as the set key (not the normalized form)
     * so the engine's routeExists($e->path())/isSacrificialPath($e->path()) lookups hit.
     *
     * @param string $path the exact request path from the evidence
     * @return SiteProfile
     */
    public function toPolicyProfile(string $path)
    {
        $real = $this->routeExists($path) ? array($path) : array();
        $sac = $this->isSacrificialPath($path) ? array($path) : array();

        return new SiteProfile(self::STACK, $real, $sac);
    }

    private function resolveIs404()
    {
        if (is_callable($this->is404)) {
            return (bool) call_user_func($this->is404);
        }

        return (bool) $this->is404;
    }

    /** Lower-case + strip a trailing slash (except root) so surface checks are variant-tolerant. */
    private static function normalize(string $path)
    {
        $p = strtolower(trim($path));
        if ($p === '') {
            return '/';
        }
        if (strlen($p) > 1 && substr($p, -1) === '/') {
            $p = rtrim($p, '/');
            if ($p === '') {
                $p = '/';
            }
        }

        return $p;
    }
}
