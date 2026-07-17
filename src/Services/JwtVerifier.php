<?php

declare(strict_types=1);

namespace Dxs\Auth\Services;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Dxs\Auth\Exceptions\SsoException;
use Throwable;

/**
 * Verifies a platform-issued access token (RFC 9068 `at+jwt`, RS256):
 * signature against the JWKS, plus `iss` / `aud` / `exp`. Returns the claims.
 */
final class JwtVerifier
{
    public function __construct(private readonly OidcDiscovery $discovery) {}

    /** @return array<string, mixed> validated claims */
    public function verify(string $jwt): array
    {
        JWT::$leeway = (int) config('sso.leeway');

        try {
            $keys = JWK::parseKeySet($this->discovery->jwks());
            $claims = (array) JWT::decode($jwt, $keys); // validates signature + exp/nbf/iat
        } catch (Throwable $e) {
            throw new SsoException('SSO token signature/expiry validation failed: '.$e->getMessage(), previous: $e);
        }

        $expectedIss = rtrim((string) config('sso.issuer'), '/');
        if (rtrim((string) ($claims['iss'] ?? ''), '/') !== $expectedIss) {
            throw new SsoException('SSO token issuer mismatch.');
        }

        $aud = $claims['aud'] ?? null;
        $audiences = is_array($aud) ? $aud : [$aud];
        if (! in_array((string) config('sso.service_slug'), array_map('strval', $audiences), true)) {
            throw new SsoException('SSO token audience is not this service.');
        }

        if (! isset($claims['sub']) || $claims['sub'] === '') {
            throw new SsoException('SSO token has no subject.');
        }

        return $claims;
    }
}
