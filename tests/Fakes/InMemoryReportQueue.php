<?php

declare(strict_types=1);

namespace Honeypot\WP\Tests\Fakes;

use Funnypot\Mainnet\Report\ReportQueue;

/** In-memory ReportQueue for tests — mirrors the contract without $wpdb. */
final class InMemoryReportQueue implements ReportQueue
{
    /** @var array<int,array> */
    public $rows = array();
    /** @var array<string,bool> */
    public $reported = array();
    /** @var int */
    public $daily = 0;
    /** @var int */
    private $seq = 0;
    /** @var string */
    private $sensorId;
    /** @var int */
    private $cap;

    public function __construct(string $sensorId = 'sensor-uuid', int $cap = 10000)
    {
        $this->sensorId = $sensorId;
        $this->cap = $cap;
    }

    public function push(array $row)
    {
        $row['id'] = ++$this->seq;
        $this->rows[] = $row;
        while (count($this->rows) > $this->cap) {
            array_shift($this->rows); // oldest dropped first
        }

        return true;
    }

    public function take(int $limit)
    {
        return array_slice($this->rows, 0, $limit);
    }

    public function delete($id)
    {
        foreach ($this->rows as $i => $row) {
            if (isset($row['id']) && $row['id'] === $id) {
                unset($this->rows[$i]);
                $this->rows = array_values($this->rows);
                return;
            }
        }
    }

    public function bumpAttempts($id)
    {
        foreach ($this->rows as $i => $row) {
            if (isset($row['id']) && $row['id'] === $id) {
                $this->rows[$i]['attempts'] = (isset($row['attempts']) ? (int) $row['attempts'] : 0) + 1;
                return;
            }
        }
    }

    public function count()
    {
        return count($this->rows);
    }

    public function recentlyReported(string $key, int $withinHours)
    {
        return isset($this->reported[$key]);
    }

    public function markReported(string $key)
    {
        $this->reported[$key] = true;
    }

    public function dailyCount()
    {
        return $this->daily;
    }

    public function bumpDaily()
    {
        $this->daily++;
    }

    public function sensorId()
    {
        return $this->sensorId;
    }
}
