<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\WordPress\Db\WpdbSilencer;
use Funnypot\WordPress\Log\WpdbHitLogWriter;
use Funnypot\WordPress\Report\WpdbReportQueue;

// ARRAY_A is a core WordPress constant (present in prod); define it for the DB-less unit process.
if (!defined('ARRAY_A')) {
    define('ARRAY_A', 'ARRAY_A');
}

/**
 * A missing/broken plugin table must degrade to a silent no-op on any request/cron-facing $wpdb
 * write: no echoed DB error (a fingerprint tell), no throw, and the caller's suppression state left
 * exactly as it was. The double below MUST actually echo on the UNSUPPRESSED path (test
 * testFakeEchoesWhenUnsuppressed proves it), otherwise the silent-degrade assertions are vacuous.
 */
final class WpdbSilentDegradeTest extends TestCase
{
    /** Anti-vacuous guard: the fake really does emit the DB-error tell when errors are not suppressed. */
    public function testFakeEchoesWhenUnsuppressed(): void
    {
        $wpdb = new SilenceFakeWpdb();
        $wpdb->missing = true; // table absent -> wpdb would print_error()

        ob_start();
        $result = $wpdb->insert('wp_honeypot_wp_hits', array('ip' => '1.2.3.4'));
        $out = (string) ob_get_clean();

        $this->assertFalse($result);
        $this->assertNotSame('', $out, 'the fake must echo on the unsuppressed path or the degrade tests are vacuous');
    }

    /**
     * The crux: capture over a missing hits table emits ZERO output and does not throw. Proving zero
     * output also proves no header side-effect — the headers-already-sent condition is downstream of
     * the premature echo, so no echo means nothing can have started output early.
     */
    public function testHitLogRecordDegradesSilentlyWhenTableMissing(): void
    {
        $wpdb = new SilenceFakeWpdb();
        $wpdb->missing = true;
        $writer = new WpdbHitLogWriter($wpdb);

        ob_start();
        $writer->record(array('ip' => '1.2.3.4', 'method' => 'POST', 'path' => '/wp-login.php', 'reason' => 'login_failed'));
        $out = (string) ob_get_clean();

        $this->assertSame('', $out, 'a missing hits table must not print a DB error');
        $this->assertFalse($wpdb->suppress_errors, 'suppression restored to prior after the write');
    }

    /** Happy path unchanged: with the table present the row is written and nothing is echoed. */
    public function testHitLogRecordWritesNormallyWhenTablePresent(): void
    {
        $wpdb = new SilenceFakeWpdb(); // missing = false
        $writer = new WpdbHitLogWriter($wpdb);

        ob_start();
        $writer->record(array('ip' => '1.2.3.4', 'method' => 'GET', 'path' => '/', 'reason' => 'login_failed'));
        $out = (string) ob_get_clean();

        $this->assertSame('', $out);
        $this->assertCount(1, $wpdb->inserted);
        $this->assertSame('wp_honeypot_wp_hits', $wpdb->inserted[0][0]);
    }

    /** Suppression is restored to the CAPTURED prior on normal return — both a false and a true prior. */
    public function testRestoresCapturedPriorOnNormalReturn(): void
    {
        $wpdb = new SilenceFakeWpdb();

        $wpdb->suppress_errors = false;
        WpdbSilencer::silently($wpdb, function () {});
        $this->assertFalse($wpdb->suppress_errors, 'a verbose site stays verbose outside the write');

        $wpdb->suppress_errors = true;
        WpdbSilencer::silently($wpdb, function () {});
        $this->assertTrue($wpdb->suppress_errors, 'an already-suppressed site stays suppressed');
    }

    /** finally restores the prior even when the closure throws, and the throw propagates unchanged. */
    public function testRestoresPriorOnThrowAndRethrows(): void
    {
        $wpdb = new SilenceFakeWpdb();
        $wpdb->suppress_errors = false;

        $caught = false;
        try {
            WpdbSilencer::silently($wpdb, function () {
                throw new \RuntimeException('boom');
            });
        } catch (\RuntimeException $e) {
            $caught = true;
            $this->assertSame('boom', $e->getMessage());
        }

        $this->assertTrue($caught, 'the helper does not swallow — the caller owns the catch');
        $this->assertFalse($wpdb->suppress_errors, 'prior restored on the throw path (proves the finally)');
    }

    /** Nested silently() (the push -> enforceCap -> count shape) restores correctly at each level. */
    public function testNestedSuppressionRestoresAtEachLevel(): void
    {
        $wpdb = new SilenceFakeWpdb();
        $wpdb->suppress_errors = false; // the real prior

        WpdbSilencer::silently($wpdb, function () use ($wpdb) {
            $this->assertTrue($wpdb->suppress_errors, 'outer sets suppression on');
            WpdbSilencer::silently($wpdb, function () use ($wpdb) {
                $this->assertTrue($wpdb->suppress_errors, 'inner captures true, sets true');
            });
            $this->assertTrue($wpdb->suppress_errors, 'inner restored its captured prior (true), not a hardcoded false');
        });

        $this->assertFalse($wpdb->suppress_errors, 'outer restored the real prior (false)');
    }

    /** ReportQueue parity: push (insert + nested enforceCap/count) degrades silently on a missing table. */
    public function testReportQueuePushDegradesSilentlyWhenTableMissing(): void
    {
        $wpdb = new SilenceFakeWpdb();
        $wpdb->missing = true;
        $queue = new WpdbReportQueue($wpdb, 'sensor-uuid');

        ob_start();
        $ok = $queue->push(array('ip' => '1.2.3.4', 'categories' => '21', 'comment' => 'x'));
        $out = (string) ob_get_clean();

        $this->assertSame('', $out, 'push must not print a DB error on a missing queue table');
        $this->assertTrue($ok, 'push returns true regardless (fire-and-forget)');
        $this->assertFalse($wpdb->suppress_errors, 'suppression restored after the nested push');
    }

    /** ReportQueue reads on a missing table coerce to array()/0 with zero output. */
    public function testReportQueueReadsDegradeToEmptyWhenTableMissing(): void
    {
        $wpdb = new SilenceFakeWpdb();
        $wpdb->missing = true;
        $queue = new WpdbReportQueue($wpdb, 'sensor-uuid');

        ob_start();
        $rows = $queue->take(50);
        $count = $queue->count();
        $out = (string) ob_get_clean();

        $this->assertSame('', $out);
        $this->assertSame(array(), $rows);
        $this->assertSame(0, $count);
    }
}

/**
 * A $wpdb double whose write/read methods ECHO a DB-error string on the UNSUPPRESSED path (mirroring
 * wpdb::print_error()) and stay silent when suppress_errors is on. suppress_errors($b) sets the flag
 * and returns the PRIOR value, matching wpdb. Named distinctly from IntelDashboardTest's FakeWpdb so
 * both unit files can load in one suite run without a redeclaration collision.
 */
final class SilenceFakeWpdb
{
    /** @var string */
    public $prefix = 'wp_';
    /** @var bool */
    public $suppress_errors = false;
    /** @var bool when true, every op faults like a missing/broken table */
    public $missing = false;
    /** @var array<int,array> recorded inserts on the happy path */
    public $inserted = array();

    /** Mirrors wpdb::suppress_errors — sets the flag, returns the previous value. */
    public function suppress_errors($suppress = true)
    {
        $prior = $this->suppress_errors;
        $this->suppress_errors = (bool) $suppress;

        return $prior;
    }

    /** Echo the raw DB error only when not suppressed — this is the tell the helper must kill. */
    private function fault()
    {
        if (!$this->suppress_errors) {
            echo "WordPress database error: [Table 'wp.wp_honeypot_wp_hits' doesn't exist]";
        }
    }

    public function insert($table, $data)
    {
        if ($this->missing) {
            $this->fault();

            return false;
        }
        $this->inserted[] = array($table, $data);

        return 1;
    }

    public function prepare($sql, ...$args)
    {
        $out = str_replace('%s', "'%s'", $sql);

        return vsprintf($out, $args);
    }

    public function get_results($sql, $type = null)
    {
        if ($this->missing) {
            $this->fault();

            return false;
        }

        return array();
    }

    public function get_var($sql)
    {
        if ($this->missing) {
            $this->fault();

            return null;
        }

        return 0;
    }

    public function query($sql)
    {
        if ($this->missing) {
            $this->fault();

            return false;
        }

        return 1;
    }

    public function delete($table, $where)
    {
        if ($this->missing) {
            $this->fault();

            return false;
        }

        return 1;
    }
}
