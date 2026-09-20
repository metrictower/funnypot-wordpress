<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\WordPress\Http\ResponseEmitter;

/**
 * FP-0494 — the `blocked` mode 403 page must be believable but NOT a fingerprint on either axis:
 *   (A) no canonical WAF/scanner signature (checked against core's own vendored denylist), and
 *   (B) no funnypot self-signature and no real WAF-product branding (a curated absence list, because
 *       the vendored denylist does NOT carry funnypot/honeypot/nuclei/wafw00f tokens — the plugin owns
 *       this net; the core CI gate never scans plugin source).
 * The body is a static method so it is scannable without emitting output.
 */
final class BlockPageContentTest extends TestCase
{
    private function denylist()
    {
        return require __DIR__ . '/../../vendor/metrictower/funnypot-core/resources/fingerprint-denylist.php';
    }

    public function testBodyHasZeroVendoredDenylistHits(): void
    {
        $body = ResponseEmitter::blockPageBody('3f9c-a1b2-7d4e');
        $dl = $this->denylist();

        foreach ($dl['literals'] as $literal) {
            $this->assertFalse(stripos($body, $literal) !== false, 'denylist literal leaked: ' . $literal);
        }
        foreach ($dl['patterns'] as $pattern) {
            $this->assertSame(0, preg_match('/' . $pattern . '/i', $body), 'denylist pattern matched: ' . $pattern);
        }
    }

    public function testBodyHasNoCuratedSelfOrVendorSignature(): void
    {
        // Curated absence, NOT sourced from the vendored denylist. The denylist has no funnypot/honeypot/
        // nuclei/wafw00f tokens, so a self-signature would slip past a denylist-only iteration; assert
        // it explicitly here. WAF-product brands are asserted too (branding is a fingerprint tell).
        $body = ResponseEmitter::blockPageBody('3f9c-a1b2-7d4e');
        $forbidden = array(
            // no funnypot self-signature
            'funnypot', 'honeypot',
            // no scanner/tool names
            'nuclei', 'wafw00f', 'identywaf',
            // no CRS/ModSecurity markers (belt-and-braces over the denylist)
            'mod_security', 'mod-security', 'modsecurity', 'owasp_crs', 'owasp crs', 'secrule',
            // no real WAF-product branding
            'cloudflare', 'wordfence', 'sucuri', 'imperva', 'incapsula',
        );
        foreach ($forbidden as $needle) {
            $this->assertFalse(stripos($body, $needle) !== false, 'forbidden token leaked: ' . $needle);
        }

        // No bare six-digit CRS-style rule id anywhere in the body.
        $this->assertSame(0, preg_match('/\b9\d{5}\b/', $body), 'a bare CRS-style rule id leaked');
    }

    public function testBodyIsBelievableAndInert(): void
    {
        $body = ResponseEmitter::blockPageBody('3f9c-a1b2-7d4e');
        $this->assertStringContainsString('403', $body);
        $this->assertStringContainsString('Access Denied', $body);
        $this->assertStringContainsString('3f9c-a1b2-7d4e', $body); // the reference token is rendered
        $this->assertStringNotContainsStringIgnoringCase('<script', $body); // inert: no JS
    }

    public function testRefIsSanitizedToHexGroupsOnly(): void
    {
        // A ref carrying an injection attempt is stripped to [0-9a-f-]; the markup can never break out.
        $body = ResponseEmitter::blockPageBody('<b>9<script>12345');
        $this->assertStringNotContainsString('<b>', $body);
        $this->assertStringNotContainsString('<script>', $body);
        $this->assertSame(0, preg_match('/\b9\d{5}\b/', $body));
    }

    public function testGeneratedRefShapeGuard(): void
    {
        // A null ref generates a fresh token; it must be three hex groups and never a bare 6-digit id.
        // (blockPageBody with null delegates to the private blockRef(); assert via the rendered token.)
        for ($i = 0; $i < 20; $i++) {
            $body = ResponseEmitter::blockPageBody();
            $this->assertSame(1, preg_match('/Reference: ([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})</', $body), 'ref shape');
            $this->assertSame(0, preg_match('/\b9\d{5}\b/', $body), 'ref must never be a bare CRS-style id');
        }
    }
}
