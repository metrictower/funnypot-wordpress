<?php

declare(strict_types=1);

namespace Funnypot\WordPress;

use Funnypot\Core\Honeypot;
use Funnypot\Mainnet\CircuitBreaker;
use Funnypot\Mainnet\Client as MainnetClient;
use Funnypot\Mainnet\Config as MainnetConfig;
use Funnypot\Policy\Geo\NullGeoIp;
use Funnypot\Policy\Log\NullLogger;
use Funnypot\Policy\PolicyConfig;
use Funnypot\Policy\PolicyEngine;
use Funnypot\WordPress\Geo\WpGeoIp;
use Funnypot\WordPress\Reputation\MainnetReputation;
use Funnypot\WordPress\Reputation\NullReputation;
use Funnypot\WordPress\Reputation\Warmer;
use Funnypot\WordPress\Reputation\WpCache;
use Funnypot\WordPress\Report\WpRemotePostTransport;

/**
 * The plugin's one wiring point (design §4.3): reads the settings, builds the §8 PolicyConfig, and
 * constructs the shared PolicyEngine with the injected ports. D authors NO decision logic here — only
 * assembly. The optional sixth GeoIp port is wired only when country policy is enabled (decision R);
 * the reputation port is a NullReputation unless checking is active (F/M), and reputation is read
 * cache-first through F's cachedVerdict (never a request-path socket, M5).
 *
 * Every movable dependency is injectable via $deps so the wiring is unit-testable with fakes; the
 * production defaults construct the real WP-backed adapters. 7.3-clean.
 */
final class PolicyFactory
{
    /**
     * @param Settings $s
     * @param string   $position 'before' | 'fallback'
     * @param array    $deps     optional overrides: evaluator (core Evaluator), ctx (RequestContext),
     *                           store (WpStateStore), clock (Clock), logger (Logger), cache
     *                           (Mainnet Cache), transport (Mainnet Transport), geo_reader (callable),
     *                           warmer (Warmer)
     * @return PolicyEngine
     */
    public static function forPosition(Settings $s, string $position, array $deps = array())
    {
        $clock = isset($deps['clock']) ? $deps['clock'] : new WpClock();
        $store = isset($deps['store']) ? $deps['store'] : WpStateStore::forSettings($s, $clock);
        $logger = isset($deps['logger']) ? $deps['logger'] : new NullLogger();

        $config = PolicyConfig::fromArray($s->toPolicyConfig($position));

        $coreEval = isset($deps['evaluator'])
            ? $deps['evaluator']
            : Honeypot::default(EvaluatorConfig::fromSettings($s));
        $ctx = isset($deps['ctx']) ? $deps['ctx'] : null;
        $evaluator = new CoreEvaluator($coreEval, $ctx);

        $geo = ($s->countryPosture() !== Settings::COUNTRY_OFF)
            ? new WpGeoIp(isset($deps['geo_reader']) ? $deps['geo_reader'] : null)
            : new NullGeoIp();

        $reputation = self::buildReputation($s, $deps, $store, $clock);

        return new PolicyEngine(
            $evaluator,
            $reputation,
            $store,
            $geo,
            $clock,
            $logger,
            $config,
            $s->seedSalt(),
            'honeypot'
        );
    }

    private static function buildReputation(Settings $s, array $deps, $store, $clock)
    {
        if (isset($deps['reputation'])) {
            return $deps['reputation'];
        }
        if (!$s->checkActive()) {
            return new NullReputation();
        }

        $cache = isset($deps['cache']) ? $deps['cache'] : new WpCache();
        $transport = isset($deps['transport']) ? $deps['transport'] : new WpRemotePostTransport(1500);
        $clockFn = static function () use ($clock) {
            return $clock->now();
        };

        $client = new MainnetClient(MainnetConfig::fromArray($s->toMainnetConfig()), $transport, $cache, null, null, $clockFn);

        $warmer = isset($deps['warmer'])
            ? $deps['warmer']
            : new Warmer(
                static function ($ip) use ($client) {
                    $client->check($ip); // out-of-band only; the cron drains this, never the request path
                },
                $store->backend(),
                new CircuitBreaker($cache, 5, 60, 21600, $clockFn),
                $s->queueCap()
            );

        $cachedVerdictFn = static function ($ip) use ($client) {
            return $client->cachedVerdict($ip); // request-path: no socket, no breaker (M5)
        };

        return new MainnetReputation($cachedVerdictFn, $warmer);
    }
}
