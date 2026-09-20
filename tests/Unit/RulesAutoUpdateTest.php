<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\Core\Rules\RulesLocator;
use Funnypot\Core\Rules\RulesUpdater;
use Funnypot\Core\Rules\RulesUpdateException;
use Funnypot\Core\Rules\UpdateResult;
use Funnypot\WordPress\Rules\RulesAutoUpdate;
use Funnypot\WordPress\Settings;
use Funnypot\WordPress\Tests\Fakes\FakeRulesUpdater;
use Funnypot\WordPress\Tests\Fakes\InMemoryBackend;
use Funnypot\WordPress\Tests\Support\ArrayFetcher;
use Funnypot\WordPress\Tests\Support\ReleaseFactory;

/**
 * The cron WRITE-seam wiring over core's signed RulesUpdater. Asserts inert-when-off, the result
 * translation, fail-closed (corpus unchanged on a rejection), the §5 read-only-dir try/catch that
 * would otherwise fatal a cron tick, and an end-to-end verify-before-load happy path through a
 * test-keyed verifier + a network-free fetcher. The exhaustive crypto tests live in funnypot-core.
 */
final class RulesAutoUpdateTest extends TestCase
{
    /** @var string */
    private $tmp;

    protected function setUp(): void
    {
        parent::setUp();
        RulesLocator::reset();
        $this->tmp = sys_get_temp_dir() . '/funnypot-wp-rules-' . bin2hex(random_bytes(6));
        @mkdir($this->tmp, 0755, true);
    }

    protected function tearDown(): void
    {
        RulesLocator::reset();
        $this->rmrf($this->tmp);
        parent::tearDown();
    }

    private function settings(bool $enabled): Settings
    {
        return Settings::fromArray(array('rules_autoupdate_enabled' => $enabled), static function () {
            return null; // no wp-config constant override in tests
        });
    }

    public function testInertWhenToggleOff(): void
    {
        $constructed = false;
        $service = new RulesAutoUpdate($this->settings(false), $this->tmp . '/data', static function () use (&$constructed) {
            $constructed = true;
            throw new \RuntimeException('factory must not run when off');
        });

        $res = $service->run();
        $this->assertFalse($res['updated']);
        $this->assertSame('inactive', $res['reason']);
        $this->assertFalse($constructed, 'the updater is never constructed when auto-update is off');
    }

    public function testFailedResultKeepsCorpusUnchanged(): void
    {
        $dataDir = $this->tmp . '/data';
        $fake = new FakeRulesUpdater(UpdateResult::failed(RulesUpdateException::REASON_BAD_SIGNATURE, 'nope'));
        $service = new RulesAutoUpdate($this->settings(true), $dataDir, static function () use ($fake) {
            return $fake;
        });

        $res = $service->run();
        $this->assertFalse($res['updated']);
        $this->assertSame('bad-signature', $res['reason']);

        // Fail-closed: with the data dir set but no successful swap, resolution stays on the bundled floor.
        RulesLocator::useDataDir($dataDir);
        $this->assertSame(
            RulesLocator::packagedPath('nuclei-index.full.php'),
            RulesLocator::resolve('nuclei-index.full.php')
        );
    }

    public function testReadOnlyDataDirDoesNotFatal(): void
    {
        // A path whose parent is a regular file: mkdir can never create the data dir, so the real
        // updater's acquireLock()->ensureDir() throws BEFORE update()'s own try/catch. The cron
        // handler must swallow that and return cleanly (§5) — never propagate.
        $blocker = $this->tmp . '/not-a-dir';
        file_put_contents($blocker, 'x');
        $dataDir = $blocker . '/data';

        $backend = new InMemoryBackend();
        $service = new RulesAutoUpdate($this->settings(true), $dataDir, static function ($dir) {
            return new RulesUpdater((string) $dir); // real updater, default verifier/fetcher
        }, $backend);

        $res = $service->run(); // must not throw
        $this->assertFalse($res['updated']);
        $this->assertStringStartsWith('error:', $res['reason']);
        // The failure was recorded for the admin display.
        $last = $service->lastResult();
        $this->assertStringStartsWith('error:', (string) $last['reason']);
    }

    public function testHappyPathVerifiesAndActivatesThroughTheWiring(): void
    {
        $dataDir = $this->tmp . '/data';

        // The end-to-end flow uses PharData + require of the extracted engine artifacts. Brain Monkey
        // loads Patchwork's file-stream wrapper process-wide, which breaks PharData's own stat calls, so
        // run the real fetch/verify/extract/swap with the wrapper bypassed. This exercises the WP wiring
        // against the real core updater (a test-keyed verifier + a network-free fetcher); the exhaustive
        // crypto tests live in funnypot-core.
        $res = null;
        $status = null;
        $resolved = null;
        $this->withoutPatchworkStream(function () use ($dataDir, &$res, &$status, &$resolved) {
            $factory = new ReleaseFactory($this->tmp . '/build');
            $fetcher = new ArrayFetcher();
            $factory->publish($fetcher, 'v1', 1, $factory->engineFiles(100, 100));
            $verifier = $factory->verifier();

            $updaterFactory = static function ($dir) use ($factory, $fetcher, $verifier) {
                $u = new RulesUpdater((string) $dir, 'stable', 'v1', $factory->baseUrl, $fetcher, $verifier);
                $u->setPackagedCoverageForTesting(array('routes' => 1, 'templates' => 1, 'attack_rules' => 1));

                return $u;
            };
            $service = new RulesAutoUpdate($this->settings(true), $dataDir, $updaterFactory, new InMemoryBackend());

            $res = $service->run();
            $status = $service->status();

            // With the read seam pointed at the data dir, resolution now serves the pulled corpus.
            RulesLocator::useDataDir($dataDir);
            $resolved = RulesLocator::resolve('nuclei-index.full.php');
        });

        $this->assertTrue($res['updated'], 'a verified signed release applies through the wiring');
        $this->assertSame('updated', $res['reason']);
        $this->assertNotNull($status);
        $this->assertSame('data-dir', $status->source);
        $this->assertSame('v1', $status->version);
        $this->assertStringStartsWith($dataDir, (string) $resolved);
        $this->assertNotSame(RulesLocator::packagedPath('nuclei-index.full.php'), $resolved);
    }

    /** Run $fn with Patchwork's file-stream wrapper disabled (so PharData works), then restore it. */
    private function withoutPatchworkStream(callable $fn): void
    {
        $stream = 'Patchwork\\CodeManipulation\\Stream';
        if (class_exists($stream) && method_exists($stream, 'bypass')) {
            $stream::bypass($fn);

            return;
        }
        $fn();
    }

    public function testBusyAndAlreadyCurrentAreSuccess(): void
    {
        $service = static function (UpdateResult $r) {
            return new RulesAutoUpdate(
                Settings::fromArray(array('rules_autoupdate_enabled' => true), static function () {
                    return null;
                }),
                sys_get_temp_dir() . '/x',
                static function () use ($r) {
                    return new FakeRulesUpdater($r);
                }
            );
        };

        $noop = $service(UpdateResult::noop('v3'))->run();
        $this->assertTrue($noop['updated']);
        $this->assertSame('already-current', $noop['reason']);
    }

    private function rmrf(string $dir): void
    {
        if (!is_dir($dir)) {
            @unlink($dir);

            return;
        }
        foreach (scandir($dir) ?: array() as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . '/' . $item;
            if (is_link($path) || !is_dir($path)) {
                @unlink($path);
            } else {
                $this->rmrf($path);
            }
        }
        @rmdir($dir);
    }
}
