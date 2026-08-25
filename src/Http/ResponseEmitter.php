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

    /** Emit an honest block (no honeypot body) at the app-chosen status. */
    public static function emitBlock($status = 403)
    {
        http_response_code((int) $status);
        header('Content-Type: text/plain; charset=UTF-8');
        echo "Forbidden\n";
    }

    private static function splits($s)
    {
        return preg_match('/[\r\n\x00]/', (string) $s) === 1;
    }
}
