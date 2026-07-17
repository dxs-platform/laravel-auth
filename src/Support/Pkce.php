<?php

declare(strict_types=1);

namespace Dxs\Auth\Support;

/**
 * RFC 7636 PKCE (S256) — the platform IdP only advertises `S256`.
 */
final class Pkce
{
    /** @return array{verifier: string, challenge: string} */
    public static function generate(): array
    {
        $verifier = self::base64Url(random_bytes(48)); // 64 chars, within 43-128
        $challenge = self::base64Url(hash('sha256', $verifier, true));

        return ['verifier' => $verifier, 'challenge' => $challenge];
    }

    public static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
