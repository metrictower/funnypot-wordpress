<?php

declare(strict_types=1);

namespace Honeypot\WP;

/**
 * Installs the degrade-safe mu-plugin loader shim so the BEFORE position runs at muplugins_loaded —
 * the earliest hook with the plugin API + $_SERVER available (design §4.1). SF-4: the shim is fail-safe
 * on the load path, the ONE path that runs unconditionally on every request before the interceptor's
 * try/catch even exists. It must NEVER fatal — a mu-plugin cannot be deactivated from wp-admin, so a
 * shim that require'd a now-missing bootstrap would take down the site it protects.
 *
 * The pure decisions (plan / shimBody / isStale) are unit-tested; the filesystem write is
 * integration-tested. 7.3-clean.
 */
final class MuLoaderInstaller
{
    /** Bump when the shim body changes so self-heal rewrites a skewed copy. */
    const SHIM_VERSION = 1;
    const SHIM_FILENAME = 'honeypot-wp-loader.php';

    /**
     * Where the BEFORE position mounts: 'mu' when the mu-plugins dir is writable, else 'fallback'
     * (plugins_loaded — still before template_redirect / theme output).
     *
     * @param bool $muDirWritable
     * @return string 'mu' | 'fallback'
     */
    public static function plan($muDirWritable)
    {
        return $muDirWritable ? 'mu' : 'fallback';
    }

    /**
     * The degrade-safe shim body (SF-4). It:
     *  - NEVER fatals on a missing bootstrap (is_file guard -> silent return);
     *  - require's ONE stable versioned entry file (mu-entry.php), never inlined plugin logic;
     *  - calls a single guarded static (class_exists/method_exists + try/catch) so shim/plugin version
     *    skew degrades to inert, not fatal.
     *
     * @param string $bootstrapPath absolute path to the plugin's mu-entry.php
     * @return string
     */
    public static function shimBody($bootstrapPath)
    {
        $path = var_export((string) $bootstrapPath, true);

        return "<?php\n"
            . "// honeypot-wp mu-loader shim v" . self::SHIM_VERSION . " (SF-4 degrade-safe). Auto-generated; do not edit.\n"
            . "\$honeypot_wp_bootstrap = " . $path . ";\n"
            . "if (!is_file(\$honeypot_wp_bootstrap)) { return; } // plugin removed/renamed -> inert, never fatal\n"
            . "require_once \$honeypot_wp_bootstrap;\n"
            . "if (class_exists('Honeypot\\\\WP\\\\MuEntry') && method_exists('Honeypot\\\\WP\\\\MuEntry', 'boot')) {\n"
            . "    try { \\Honeypot\\WP\\MuEntry::boot(); } catch (\\Throwable \$e) { /* a fault must never take the site down */ }\n"
            . "}\n";
    }

    /** True when the on-disk shim differs from what we would write now (drives self-heal). */
    public static function isStale($currentContent, $expectedContent)
    {
        return (string) $currentContent !== (string) $expectedContent;
    }

    // --- real filesystem side effects (integration-tested) --------------------------------------

    /**
     * Install / self-heal the shim. Best-effort: an unwritable dir returns false (the caller then uses
     * the plugins_loaded fallback + an admin notice) and NEVER throws.
     *
     * @param string $muPluginsDir  wp-content/mu-plugins
     * @param string $bootstrapPath the plugin's mu-entry.php
     * @return bool true when the shim is present + current
     */
    public static function install($muPluginsDir, $bootstrapPath)
    {
        try {
            if (!is_dir($muPluginsDir)) {
                if (!@mkdir($muPluginsDir, 0755, true) && !is_dir($muPluginsDir)) {
                    return false;
                }
            }
            if (!is_writable($muPluginsDir)) {
                return false;
            }
            $target = rtrim($muPluginsDir, '/') . '/' . self::SHIM_FILENAME;
            $expected = self::shimBody($bootstrapPath);
            if (is_file($target)) {
                $current = @file_get_contents($target);
                if ($current !== false && !self::isStale($current, $expected)) {
                    return true; // already current
                }
            }

            return @file_put_contents($target, $expected) !== false;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** Remove the shim on deactivation. Best-effort, never throws. */
    public static function uninstall($muPluginsDir)
    {
        try {
            $target = rtrim($muPluginsDir, '/') . '/' . self::SHIM_FILENAME;
            if (is_file($target)) {
                return @unlink($target);
            }

            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }
}
