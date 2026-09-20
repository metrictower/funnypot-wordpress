<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Log;

use Funnypot\WordPress\PluginEnumProbe;
use Funnypot\WordPress\WpStateStore;

/**
 * A HitLogWriter decorator that absorbs plugin/theme enumeration sweeps (FP-0395). A full
 * nuclei-wordfence run is 80k+ requests; writing one hit row each would exhaust the log store. So a
 * per-source 60s window collapses the burst: the first metadata-probe row in the window writes ONE
 * `mass_plugin_scan` rollup row, later probes in the window write no row and only bump a state-slot
 * aggregate (count + slug sample + user agent). All non-enum traffic passes straight through unchanged.
 *
 * The attacker still receives every response — DecisionExecutor emits independently of the hit log — so
 * absorption only bounds local telemetry, never what is served. Fault-safe: any error degrades to a
 * best-effort pass-through so a logging fault never affects the response. 7.3-clean.
 */
final class ScanAbsorbingHitLogWriter implements HitLogWriter
{
    /** Aggregate slug-sample cap (spec) — enough to characterize a sweep, bounded memory. */
    const SAMPLE_CAP = 20;

    /** @var HitLogWriter */
    private $inner;
    /** @var WpStateStore */
    private $store;
    /** @var int */
    private $windowSecs;
    /** @var int */
    private $escalateThreshold;
    /** @var bool */
    private $autoBan;
    /** @var int */
    private $banTtlSecs;

    public function __construct(HitLogWriter $inner, WpStateStore $store, $windowSecs = 60, $escalateThreshold = 5, $autoBan = false, $banTtlSecs = 3600)
    {
        $this->inner = $inner;
        $this->store = $store;
        $this->windowSecs = (int) $windowSecs;
        $this->escalateThreshold = (int) $escalateThreshold;
        $this->autoBan = (bool) $autoBan;
        $this->banTtlSecs = (int) $banTtlSecs;
    }

    public function record(array $row)
    {
        try {
            $path = isset($row['path']) ? (string) $row['path'] : '';
            $action = isset($row['action']) ? (string) $row['action'] : '';
            $ip = isset($row['ip']) ? (string) $row['ip'] : '';
            $probe = PluginEnumProbe::matchesMetadataPath($path);

            // Only deceive/log enum-probe rows with a source key are absorbed; everything else is a
            // normal row. An installed-slug asset is a real route (ALLOW) and never reaches the log.
            if ($probe === null || $ip === '' || !in_array($action, array('deceive', 'log'), true)) {
                $this->inner->record($row);
                return;
            }

            $n = $this->store->incr('enumscan:' . $ip, $this->windowSecs);
            $this->bumpAggregate($ip, $probe, $row, $n);

            if ($n === 1) {
                // One rollup row per source per window; the wildcard path marks the collapsed sweep.
                $this->inner->record(array(
                    'ts' => isset($row['ts']) ? $row['ts'] : time(),
                    'ip' => $ip,
                    'method' => isset($row['method']) ? $row['method'] : 'GET',
                    'path' => '/wp-content/' . $probe['kind'] . 's/*',
                    'action' => 'deceive',
                    'reason' => 'mass_plugin_scan',
                    'status' => isset($row['status']) ? $row['status'] : 0,
                ));
            }

            if ($this->autoBan && $this->escalateThreshold > 0 && $n > $this->escalateThreshold) {
                $this->store->block($ip, $this->banTtlSecs);
            }
        } catch (\Throwable $ignored) {
            try {
                $this->inner->record($row);
            } catch (\Throwable $ignored2) {
                // a hit-log fault must never affect the response
            }
        }
    }

    /** Update the per-source aggregate state slot (local intel only — never relayed to mainnet). */
    private function bumpAggregate(string $ip, array $probe, array $row, $n)
    {
        $key = 'enumscan_agg:' . $ip;
        $agg = $this->store->backend()->get($key);
        if (!is_array($agg)) {
            $agg = array(
                'count' => 0,
                'first_ts' => isset($row['ts']) ? (int) $row['ts'] : 0,
                'ua' => '',
                'slugs_sample' => array(),
            );
        }

        $agg['count'] = (int) $n;
        if (count($agg['slugs_sample']) < self::SAMPLE_CAP && !in_array($probe['slug'], $agg['slugs_sample'], true)) {
            $agg['slugs_sample'][] = $probe['slug'];
        }
        $ua = isset($row['ua']) ? (string) $row['ua'] : '';
        if ($ua !== '') {
            $agg['ua'] = substr($ua, 0, 255);
        }

        $this->store->backend()->set($key, $agg, $this->windowSecs);
    }
}
