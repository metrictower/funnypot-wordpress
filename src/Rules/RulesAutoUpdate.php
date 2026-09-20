<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Rules;

use Funnypot\Core\Rules\RulesStatus;
use Funnypot\WordPress\Settings;
use Funnypot\WordPress\State\StateBackend;

/**
 * The WRITE seam for the deception-corpus auto-update (FP-0502): a thin cron service that runs
 * funnypot-core's signed RulesUpdater on a schedule. It adds NO cryptography — every trust check
 * (ed25519 signature + per-file sha256 + array-literal validator, all before any require) lives in
 * core's RulesUpdater and is unchanged. This class only decides whether to run, catches the one throw
 * that escapes update(), translates the result to the {updated, reason} shape the other WP crons use,
 * and records a small status snapshot for the admin screen.
 *
 * Fail-safe: inert when the toggle is off, and any fault degrades to "keep the current/bundled corpus"
 * — a cron tick never fatals. The updater is built through an injected factory so tests can drive the
 * whole flow with a test-keyed verifier + a network-free fetcher. 7.3-clean.
 */
final class RulesAutoUpdate
{
    /** The fixed distribution repo. The fetcher's allow-list already pins its GitHub release hosts. */
    const REPO_BASE_URL = 'https://github.com/metrictower/funnypot-rules';

    /** State-backend key holding the last cron result (for the admin display). */
    const STATE_KEY = 'rules:autoupdate';

    /** @var Settings */
    private $settings;

    /** @var string the data dir RulesUpdater writes to and RulesLocator reads from */
    private $dataDir;

    /** @var callable(string):object fn(string $dataDir): RulesUpdater (or a test double) */
    private $updaterFactory;

    /** @var StateBackend|null */
    private $backend;

    /** @var callable():int */
    private $clock;

    /**
     * @param Settings          $s
     * @param string            $dataDir
     * @param callable          $updaterFactory fn(string $dataDir): object exposing update()/status()
     * @param StateBackend|null $backend        stores the last-result snapshot for the admin screen
     * @param callable|null     $clock
     */
    public function __construct(Settings $s, string $dataDir, callable $updaterFactory, $backend = null, $clock = null)
    {
        $this->settings = $s;
        $this->dataDir = $dataDir;
        $this->updaterFactory = $updaterFactory;
        $this->backend = $backend instanceof StateBackend ? $backend : null;
        $this->clock = $clock !== null ? $clock : 'time';
    }

    /**
     * Run one update tick.
     *
     * @return array {updated:bool, reason:string, status?:array}
     */
    public function run()
    {
        if (!$this->settings->rulesAutoUpdateEnabled()) {
            return array('updated' => false, 'reason' => 'inactive'); // inert off-switch
        }

        try {
            $updater = call_user_func($this->updaterFactory, $this->dataDir);
            // acquireLock()->ensureDir() runs BEFORE update()'s own try/catch, so a read-only or
            // uncreatable data dir throws OUT of update(). Catch it here or a cron tick turns fatal.
            $result = $updater->update();
        } catch (\Throwable $e) {
            $reason = 'error:' . $e->getMessage();
            $this->record($reason, null);

            return array('updated' => false, 'reason' => $reason);
        }

        // success covers 'updated', 'already-current' and 'busy'; a failure keeps the current corpus.
        $reason = (string) $result->status;
        $this->record($reason, $result->toVersion);

        return array('updated' => (bool) $result->success, 'reason' => $reason, 'status' => $result->toArray());
    }

    /**
     * A disk-only read of the installed corpus status (no network), safe for the admin screen.
     *
     * @return RulesStatus|null
     */
    public function status()
    {
        try {
            $updater = call_user_func($this->updaterFactory, $this->dataDir);
            $st = $updater->status();

            return $st instanceof RulesStatus ? $st : null;
        } catch (\Throwable $e) {
            return null;
        }
    }

    /** The last recorded cron result snapshot (reason + version + timestamp), or null. */
    public function lastResult()
    {
        if ($this->backend === null) {
            return null;
        }
        $v = $this->backend->get(self::STATE_KEY);

        return is_array($v) ? $v : null;
    }

    /**
     * The WP-cron recurrence the toggle+interval imply, or null when auto-update is off (unschedule).
     * Pure — extracted so the schedule decision is unit-testable without a live WordPress.
     *
     * @return string|null 'hourly' | 'twicedaily' | 'daily' | null
     */
    public static function desiredSchedule(Settings $s)
    {
        return $s->rulesAutoUpdateEnabled() ? $s->rulesUpdateInterval() : null;
    }

    private function record($reason, $version)
    {
        if ($this->backend === null) {
            return;
        }
        try {
            $this->backend->set(self::STATE_KEY, array(
                'reason' => (string) $reason,
                'version' => $version !== null ? (string) $version : null,
                'checked_at' => (int) call_user_func($this->clock),
            ), 0);
        } catch (\Throwable $ignored) {
            // recording is best-effort; it must never affect the cron outcome
        }
    }
}
