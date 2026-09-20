<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Http;

use Funnypot\Policy\FakeResponse;

/**
 * Writes a policy FakeResponse to PHP output (http_response_code / header / echo). The Decision's
 * app-chosen status overrides the fake's own when supplied (invariant: status is app-chosen, never
 * model-chosen). Carries the same header-splitting defence as core's emitter. 7.3-clean.
 */
final class ResponseEmitter
{
    /**
     * @param FakeResponse $fake
     * @param int|null     $status app-chosen status (Decision::status()); null => the fake's own
     * @return void
     */
    public static function emit(FakeResponse $fake, $status = null)
    {
        $code = ($status !== null) ? (int) $status : $fake->status();
        http_response_code($code);

        $headers = $fake->headers();
        $sawContentType = false;
        foreach ($headers as $name => $value) {
            if (self::splits((string) $name) || self::splits((string) $value)) {
                continue; // defence-in-depth: never emit a header that could split the response
            }
            if (strcasecmp((string) $name, 'Content-Type') === 0) {
                $sawContentType = true;
            }
            // Set-Cookie must append; every other header replaces.
            header($name . ': ' . $value, strcasecmp((string) $name, 'Set-Cookie') !== 0);
        }

        // Ensure the Content-Type matches the request even when the fake did not list it as a header.
        $ct = $fake->contentType();
        if (!$sawContentType && $ct !== '' && !self::splits($ct)) {
            header('Content-Type: ' . $ct);
        }

        echo $fake->body();
    }

    /**
     * Emit an honest block (no honeypot body) at the app-chosen status. Serves the generic block page
     * as HTML — a block posture returns an appliance-style denial regardless of the requested type, so
     * this deliberately does not match the request Content-Type (unlike emit(), which does). Status is
     * app-chosen (Decision::status(), defaulted to 403 upstream), never model-chosen.
     */
    public static function emitBlock($status = 403)
    {
        http_response_code((int) $status);
        header('Content-Type: text/html; charset=UTF-8');
        echo self::blockPageBody();
    }

    /**
     * The generic, vendor-neutral HTML 403 block page. Deliberately minimal so it blends with the stock
     * 403 pages on the web (no product/WAF branding, no funnypot self-constant, no external asset) — an
     * ornate unique page would itself become a fingerprint. The only per-request variation is an inert
     * reference token, which lives in the body (never a header, so the header-split defence is intact).
     *
     * @param string|null $ref html-safe reference token ([0-9a-f-]); null => a fresh random one
     * @return string
     */
    public static function blockPageBody($ref = null)
    {
        if ($ref !== null) {
            $ref = preg_replace('/[^0-9a-f-]/', '', (string) $ref);
        } else {
            $ref = self::blockRef();
        }

        return '<!DOCTYPE html>' . "\n"
            . '<html lang="en"><head><meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width, initial-scale=1">'
            . '<title>403 Forbidden</title>'
            . '<style>'
            . 'body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;'
            . 'background:#f4f4f5;color:#3f3f46;margin:0;padding:0}'
            . '.box{max-width:32rem;margin:12vh auto 0;padding:2rem;text-align:center}'
            . 'h1{font-size:1.5rem;font-weight:600;margin:0 0 .75rem;color:#27272a}'
            . 'p{font-size:.95rem;line-height:1.5;margin:0 0 1rem}'
            . '.ref{font-size:.8rem;color:#a1a1aa}'
            . '</style></head><body><div class="box">'
            . '<h1>Access Denied</h1>'
            . '<p>Your request could not be processed and has been blocked. '
            . 'If you believe this is an error, please contact the site administrator.</p>'
            . '<p class="ref">Reference: ' . $ref . '</p>'
            . '</div></body></html>';
    }

    /**
     * An inert, display-only reference token: three 4-char hex groups joined by hyphens (e.g.
     * 3f9c-a1b2-7d4e). It is [0-9a-f-] only, so it can never form a scanner-name word boundary nor a
     * bare six-digit CRS rule id (a hyphen breaks any run of digits, and a group caps at four).
     *
     * @return string
     */
    private static function blockRef()
    {
        $h = bin2hex(random_bytes(6)); // 12 hex chars
        return substr($h, 0, 4) . '-' . substr($h, 4, 4) . '-' . substr($h, 8, 4);
    }

    private static function splits($s)
    {
        return preg_match('/[\r\n\x00]/', (string) $s) === 1;
    }
}
