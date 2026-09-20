<?php

declare(strict_types=1);

namespace Funnypot\WordPress;

/**
 * The installed plugin/theme slug oracle (FP-0395). Only WordPress knows which extensions are really
 * installed, so a probe for an uninstalled slug is an unambiguous enumeration attempt — but `get_plugins()`
 * / `wp_get_themes()` are wp-admin includes unavailable at `muplugins_loaded` and too expensive to run per
 * request. So the installed set is READ from a transient on the request path and POPULATED out-of-band
 * (activation / admin / cache-invalidation hooks) via injected list callables.
 *
 * Fail-safe: a cold or unreadable transient yields `known === false`, which WpSiteProfile treats as "we
 * don't know our own routes" and reverts to blanket real-route behavior — a genuine installed asset is
 * never converted into a reported probe. All WordPress calls are injected callables so it unit-tests with
 * no WordPress. 7.3-clean.
 */
final class WpInstalledSet
{
    const TRANSIENT = 'funnypot_wp_installed_set';
    /** Cache lifetime; correctness comes from the invalidation hooks, this only bounds staleness. */
    const TTL = 43200;

    /** @var callable(string):mixed transient read */
    private $getTransient;
    /** @var callable(string,mixed,int):void transient write */
    private $setTransient;
    /** @var callable():array installed plugin slugs; invoked ONLY by refresh(), never on the read path */
    private $listPlugins;
    /** @var callable():array installed theme slugs; invoked ONLY by refresh() */
    private $listThemes;

    /**
     * @param callable      $getTransient fn(string $key): mixed
     * @param callable      $setTransient fn(string $key, mixed $value, int $ttl): void
     * @param callable|null $listPlugins  fn(): string[] — out-of-band only
     * @param callable|null $listThemes   fn(): string[] — out-of-band only
     */
    public function __construct($getTransient, $setTransient, $listPlugins = null, $listThemes = null)
    {
        $this->getTransient = $getTransient;
        $this->setTransient = $setTransient;
        $this->listPlugins = $listPlugins;
        $this->listThemes = $listThemes;
    }

    /**
     * The projection WpSiteProfile consumes. Read path: transient only, NEVER the list callables.
     *
     * @return array{plugins:array,themes:array,known:bool}
     */
    public function data()
    {
        $row = call_user_func($this->getTransient, self::TRANSIENT);
        if (!is_array($row) || empty($row['known'])) {
            return array('plugins' => array(), 'themes' => array(), 'known' => false);
        }

        return array(
            'plugins' => isset($row['plugins']) && is_array($row['plugins']) ? $row['plugins'] : array(),
            'themes' => isset($row['themes']) && is_array($row['themes']) ? $row['themes'] : array(),
            'known' => true,
        );
    }

    /** @return bool has the set been populated at least once (warm cache)? */
    public function isKnown()
    {
        $d = $this->data();

        return $d['known'] === true;
    }

    /** @return array plugin slugs (empty when cold — fail-safe) */
    public function plugins()
    {
        return $this->data()['plugins'];
    }

    /** @return array theme slugs (empty when cold — fail-safe) */
    public function themes()
    {
        return $this->data()['themes'];
    }

    /**
     * Populate the transient from the live installed set. Call ONLY from an admin / cron / activation
     * context where the wp-admin includes are safe — never on the request path.
     */
    public function refresh()
    {
        $plugins = $this->listPlugins !== null ? self::slugList(call_user_func($this->listPlugins)) : array();
        $themes = $this->listThemes !== null ? self::slugList(call_user_func($this->listThemes)) : array();

        call_user_func($this->setTransient, self::TRANSIENT, array(
            'plugins' => $plugins,
            'themes' => $themes,
            'known' => true,
        ), self::TTL);
    }

    /** Lower-case, string-coerce, de-dup so slug comparison against a normalized path is exact. */
    private static function slugList($values)
    {
        if (!is_array($values)) {
            return array();
        }
        $out = array();
        foreach ($values as $v) {
            $v = strtolower(trim((string) $v));
            if ($v !== '' && !in_array($v, $out, true)) {
                $out[] = $v;
            }
        }

        return $out;
    }
}
