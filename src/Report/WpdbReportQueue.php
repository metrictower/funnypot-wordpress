<?php

declare(strict_types=1);

namespace Honeypot\WP\Report;

use Funnypot\Mainnet\Report\ReportQueue;

/**
 * The $wpdb-backed report queue (design §4.9). Storage-agnostic ReportQueue implementation over
 * {$prefix}honeypot_wp_report_queue + a dedup/daily sidecar, mirroring the app's abuse_queue shape.
 * Every write is $wpdb->prepare'd. Integration-tested (needs a live $wpdb), not unit-tested; the unit
 * suite drives an in-memory queue fake. 7.3-clean.
 */
final class WpdbReportQueue implements ReportQueue
{
    /** @var object $wpdb */
    private $wpdb;
    /** @var string */
    private $queueTable;
    /** @var string */
    private $sidecarTable;
    /** @var string */
    private $sensorId;
    /** @var int */
    private $queueCap;

    /**
     * @param object $wpdb
     * @param string $sensorId the per-install UUID (D3)
     * @param int    $queueCap hard queue size cap (oldest dropped first)
     */
    public function __construct($wpdb, string $sensorId, int $queueCap = 10000)
    {
        $this->wpdb = $wpdb;
        $this->queueTable = $wpdb->prefix . 'honeypot_wp_report_queue';
        $this->sidecarTable = $wpdb->prefix . 'honeypot_wp_report_sidecar';
        $this->sensorId = $sensorId;
        $this->queueCap = $queueCap;
    }

    public function push(array $row)
    {
        $this->wpdb->insert($this->queueTable, array(
            'ip' => isset($row['ip']) ? (string) $row['ip'] : '',
            'categories' => isset($row['categories']) ? (string) $row['categories'] : '',
            'comment' => isset($row['comment']) ? (string) $row['comment'] : '',
            'created_at' => isset($row['created_at']) ? (string) $row['created_at'] : gmdate('c'),
            'attempts' => isset($row['attempts']) ? (int) $row['attempts'] : 0,
            'signals' => isset($row['signals']) ? (string) $row['signals'] : null,
        ));
        $this->enforceCap();

        return true;
    }

    public function take(int $limit)
    {
        $sql = $this->wpdb->prepare(
            "SELECT * FROM {$this->queueTable} ORDER BY id ASC LIMIT %d",
            $limit
        );
        $rows = $this->wpdb->get_results($sql, ARRAY_A);

        return is_array($rows) ? $rows : array();
    }

    public function delete($id)
    {
        $this->wpdb->delete($this->queueTable, array('id' => (int) $id));
    }

    public function bumpAttempts($id)
    {
        $this->wpdb->query($this->wpdb->prepare(
            "UPDATE {$this->queueTable} SET attempts = attempts + 1 WHERE id = %d",
            $id
        ));
    }

    public function count()
    {
        return (int) $this->wpdb->get_var("SELECT COUNT(*) FROM {$this->queueTable}");
    }

    public function recentlyReported(string $key, int $withinHours)
    {
        $cutoff = gmdate('c', time() - ($withinHours * 3600));
        $found = $this->wpdb->get_var($this->wpdb->prepare(
            "SELECT dedup_key FROM {$this->sidecarTable} WHERE dedup_key = %s AND reported_at >= %s LIMIT 1",
            $key,
            $cutoff
        ));

        return $found !== null;
    }

    public function markReported(string $key)
    {
        $this->wpdb->query($this->wpdb->prepare(
            "INSERT INTO {$this->sidecarTable} (dedup_key, reported_at) VALUES (%s, %s)
             ON DUPLICATE KEY UPDATE reported_at = VALUES(reported_at)",
            $key,
            gmdate('c')
        ));
    }

    public function dailyCount()
    {
        $today = gmdate('Y-m-d');
        return (int) $this->wpdb->get_var($this->wpdb->prepare(
            "SELECT sent FROM {$this->sidecarTable} WHERE dedup_key = %s LIMIT 1",
            'daily:' . $today
        ));
    }

    public function bumpDaily()
    {
        $today = gmdate('Y-m-d');
        $this->wpdb->query($this->wpdb->prepare(
            "INSERT INTO {$this->sidecarTable} (dedup_key, sent, reported_at) VALUES (%s, 1, %s)
             ON DUPLICATE KEY UPDATE sent = sent + 1",
            'daily:' . $today,
            gmdate('c')
        ));
    }

    public function sensorId()
    {
        return $this->sensorId;
    }

    /** Hard queue cap: drop the oldest rows when the queue exceeds the cap (SF-6). */
    private function enforceCap()
    {
        $count = $this->count();
        if ($count <= $this->queueCap) {
            return;
        }
        $excess = $count - $this->queueCap;
        $this->wpdb->query($this->wpdb->prepare(
            "DELETE FROM {$this->queueTable} ORDER BY id ASC LIMIT %d",
            $excess
        ));
    }
}
