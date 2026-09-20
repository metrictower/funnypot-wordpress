<?php

declare(strict_types=1);

namespace Funnypot\WordPress;

/**
 * Recognizes the plugin/theme metadata-probe URL shapes a mass enumerator sweeps
 * (`/wp-content/plugins/<slug>/readme.txt`, `/wp-content/themes/<slug>/style.css`). Path-shape only —
 * it does NOT consult the installed set (that is WpSiteProfile's job). The scan absorber uses it to
 * collapse a burst of these into one rollup. Pure, no WordPress dependency. 7.3-clean.
 */
final class PluginEnumProbe
{
    /**
     * Is this a plugin/theme metadata-probe path? Returns the kind + slug, or null.
     *
     * @param string $path a request path (no query string)
     * @return array{kind:string,slug:string}|null
     */
    public static function matchesMetadataPath(string $path)
    {
        $p = strtolower(trim($path));

        if (preg_match('#^/wp-content/plugins/([a-z0-9][a-z0-9._-]*)/readme\.txt$#', $p, $m)) {
            return self::probe('plugin', $m[1]);
        }
        if (preg_match('#^/wp-content/themes/([a-z0-9][a-z0-9._-]*)/style\.css$#', $p, $m)) {
            return self::probe('theme', $m[1]);
        }

        return null;
    }

    /** Reject a traversal segment before treating it as a slug (belt-and-braces over the char class). */
    private static function probe(string $kind, string $slug)
    {
        if (strpos($slug, '..') !== false) {
            return null;
        }

        return array('kind' => $kind, 'slug' => $slug);
    }
}
