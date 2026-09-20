<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Support;

use Funnypot\Core\Rules\KeyRing;
use Funnypot\Core\Rules\SignatureVerifier;
use Funnypot\Core\SchemaVersion;
use Phar;
use PharData;

/**
 * Builds signed funnypot-rules release fixtures for the WP auto-update wiring tests: a gzipped tarball
 * of engine artifacts, a schema-2 manifest pinning their sha256s + a freshness window, and a detached
 * ed25519 signature over the CONTEXT-PREFIXED manifest bytes — served through an ArrayFetcher at the
 * exact URLs RulesUpdater requests. Owns throwaway `release` + `channels` ed25519 keypairs so a
 * test-keyed SignatureVerifier can drive the whole verify/swap flow with no network and no real keys.
 *
 * Re-derives the core suite's ReleaseFactory pattern (funnypot-core tests/Support/ReleaseFactory.php);
 * the WP tests assert the CONSUMER WIRING, not the crypto (core owns those tests).
 */
final class ReleaseFactory
{
    /** @var string */
    public $baseUrl = 'https://github.com/metrictower/funnypot-rules';

    /** @var string */
    private $releaseSecret;
    /** @var string */
    private $releasePublic;
    /** @var string */
    private $channelsSecret;
    /** @var string */
    private $channelsPublic;
    /** @var string */
    private $workDir;
    /** @var int */
    private $tarSeq = 0;

    public function __construct(string $workDir)
    {
        $release = sodium_crypto_sign_keypair();
        $this->releaseSecret = sodium_crypto_sign_secretkey($release);
        $this->releasePublic = sodium_crypto_sign_publickey($release);
        $channels = sodium_crypto_sign_keypair();
        $this->channelsSecret = sodium_crypto_sign_secretkey($channels);
        $this->channelsPublic = sodium_crypto_sign_publickey($channels);
        $this->workDir = rtrim($workDir, '/');
        @mkdir($this->workDir, 0755, true);
    }

    /** A verifier that trusts exactly this factory's two role-scoped keys. */
    public function verifier(): SignatureVerifier
    {
        return new SignatureVerifier(new KeyRing(array(
            array('key_id' => 'test-release', 'public_key' => base64_encode($this->releasePublic), 'valid_from' => '2000-01-01', 'valid_until' => null, 'roles' => array('release')),
            array('key_id' => 'test-channels', 'public_key' => base64_encode($this->channelsPublic), 'valid_from' => '2000-01-01', 'valid_until' => null, 'roles' => array('channels')),
        )));
    }

    /**
     * Register a full release (manifest + sig + tarball) with $fetcher under $version.
     *
     * @param array<string,string> $engineFiles artifactName => PHP file contents
     */
    public function publish(ArrayFetcher $fetcher, string $version, int $seq, array $engineFiles): void
    {
        $tarballName = 'funnypot-rules-' . $version . '.tar.gz';
        $tarballBytes = $this->buildTarball($engineFiles);

        $files = array();
        foreach ($engineFiles as $name => $contents) {
            $files['engine/' . $name] = hash('sha256', $contents);
        }

        $now = time();
        $manifest = array(
            'schema' => SchemaVersion::RELEASE_CURRENT,
            'version' => $version,
            'version_seq' => $seq,
            'generated_at' => gmdate('c', $now),
            'expires' => gmdate('c', $now + 90 * 86400),
            'built_at' => gmdate('c', $now),
            'key_id' => 'test-release',
            'tarball' => $tarballName,
            'tarball_sha256' => hash('sha256', $tarballBytes),
            'files' => $files,
        );

        $manifestBytes = json_encode($manifest, JSON_UNESCAPED_SLASHES);
        $sig = sodium_crypto_sign_detached(SignatureVerifier::CONTEXT_MANIFEST . $manifestBytes, $this->releaseSecret);

        $base = $this->baseUrl . '/releases/download/' . rawurlencode($version) . '/';
        $fetcher->put($base . $version . '.manifest.json', $manifestBytes);
        $fetcher->put($base . $version . '.manifest.json.sig', $sig);
        $fetcher->put($base . $tarballName, $tarballBytes);
    }

    /**
     * A minimal, valid engine artifact set. $routes/$templates shape coverage counts.
     *
     * @return array<string,string>
     */
    public function engineFiles(int $routes = 100, int $templates = 100): array
    {
        $routeMap = array();
        for ($i = 0; $i < $routes; $i++) {
            $routeMap['GET /r' . $i] = array('b' => array(array('pid' => 'p' . $i, 't' => array('t' . $i))));
        }
        $templateMap = array();
        for ($i = 0; $i < $templates; $i++) {
            $templateMap['t' . $i] = array('sev' => 'medium', 'tags' => array('x'), 'name' => 'T' . $i);
        }
        $index = array('schema' => 1, 'manifest' => array('schema' => 1), 'routes' => $routeMap, 'templates' => $templateMap);

        $attackRules = array(array(
            'id' => 'attack-demo',
            'severity' => 'high',
            'tags' => array('attack'),
            'status' => 200,
            'match' => array(array('in' => 'query', 'regex' => 'q=([a-z0-9]+)')),
            'response' => array('body' => 'ok'),
        ));

        return array(
            'nuclei-index.full.php' => $this->literal($index),
            'funnypot-attack.php' => $this->literal($attackRules),
            'funnypot-routes.php' => $this->literal(array()),
            'funnypot-routes-index.php' => $this->literal(array('routes' => array(), 'templates' => array())),
            'funnypot-param.php' => $this->literal(array('schema' => 1, 'buckets' => array())),
        );
    }

    /** @param mixed $value */
    public function literal($value): string
    {
        return "<?php\n\ndeclare(strict_types=1);\n\nreturn " . var_export($value, true) . ";\n";
    }

    /** @param array<string,string> $engineFiles */
    private function buildTarball(array $engineFiles): string
    {
        $stage = $this->workDir . '/stage-' . (++$this->tarSeq);
        @mkdir($stage . '/engine', 0755, true);
        foreach ($engineFiles as $name => $contents) {
            file_put_contents($stage . '/engine/' . $name, $contents);
        }

        $tarPath = $this->workDir . '/rel-' . $this->tarSeq . '.tar';
        @unlink($tarPath);
        @unlink($tarPath . '.gz');
        $phar = new PharData($tarPath);
        $phar->buildFromDirectory($stage);
        $phar->compress(Phar::GZ);
        unset($phar);

        $bytes = (string) file_get_contents($tarPath . '.gz');
        @unlink($tarPath);
        @unlink($tarPath . '.gz');

        return $bytes;
    }
}
