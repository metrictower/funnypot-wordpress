<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Log;

/**
 * The real hit-log writer over $wpdb (design §4.5). Thin: one prepared INSERT into
 * {$prefix}honeypot_wp_hits, bounded by the cron sweep. Integration-tested (needs a live $wpdb), not
 * unit-tested. 7.3-clean.
 */
final class WpdbHitLogWriter implements HitLogWriter
{
    /** @var object $wpdb */
    private $wpdb;
    /** @var string */
    private $table;

    /** @param object $wpdb the WordPress $wpdb handle */
    public function __construct($wpdb)
    {
        $this->wpdb = $wpdb;
        $this->table = $wpdb->prefix . 'honeypot_wp_hits';
    }

    public function record(array $row)
    {
        // $wpdb->insert prepares every value; nothing here is a raw payload (reason is an opaque label).
        $this->wpdb->insert($this->table, array(
            'ts' => isset($row['ts']) ? (int) $row['ts'] : time(),
            'ip' => isset($row['ip']) ? substr((string) $row['ip'], 0, 45) : '',
            'method' => isset($row['method']) ? substr((string) $row['method'], 0, 10) : '',
            'path' => isset($row['path']) ? substr((string) $row['path'], 0, 255) : '',
            'action' => isset($row['action']) ? substr((string) $row['action'], 0, 16) : '',
            'reason' => isset($row['reason']) ? substr((string) $row['reason'], 0, 32) : '',
            'status' => isset($row['status']) ? (int) $row['status'] : 0,
        ));
    }
}
