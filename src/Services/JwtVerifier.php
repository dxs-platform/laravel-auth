<?php

declare(strict_types=1);

namespace Dxs\Auth\Services;

use Dxs\Auth\Exceptions\SsoException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
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
        return $this->verifyForAudience($jwt, (string) config('sso.service_slug'));
    }

    /** @return array<string, mixed> validated ID-token claims */
    public function verifyIdToken(string $jwt, string $expectedNonce): array
    {
        $expectedAudience = (string) config('sso.service_slug');
        $claims = $this->verifyForAudience($jwt, $expectedAudience);

        $nonce = $claims['nonce'] ?? null;
        if ($expectedNonce === '' || ! is_string($nonce) || ! hash_equals($expectedNonce, $nonce)) {
            throw new SsoException('SSO ID token nonce mismatch.');
        }

        $audiences = is_array($claims['aud']) ? $claims['aud'] : [$claims['aud']];
        $authorizedParty = $claims['azp'] ?? null;
        if ((count($audiences) > 1 || $authorizedParty !== null)
            && (! is_string($authorizedParty) || ! hash_equals($expectedAudience, $authorizedParty))
        ) {
            throw new SsoException('SSO ID token authorized party mismatch.');
        }

        return $claims;
    }

    /** @return array<string, mixed> */
    private function verifyForAudience(string $jwt, string $expectedAudience): array
    {
        JWT::$leeway = (int) config('sso.leeway');

        try {
            $jwks = $this->discovery->jwks();
            $keyId = $this->keyId($jwt);

            if ($keyId !== null && ! $this->containsKeyId($jwks, $keyId)) {
                $jwks = $this->discovery->jwks(fresh: true);
            }

            $keys = JWK::parseKeySet($jwks);
            $claims = (array) JWT::decode($jwt, $keys); // validates signature + exp/nbf/iat
        } catch (Throwable $e) {
            throw new SsoException('SSO token signature/expiry validation failed: '.$e->getMessage(), previous: $e);
        }

        $expectedIssuer = rtrim((string) config('sso.issuer'), '/');
        $issuer = $claims['iss'] ?? null;
        if (! is_string($issuer) || rtrim($issuer, '/') !== $expectedIssuer) {
            throw new SsoException('SSO token issuer mismatch.');
        }

        $audience = $claims['aud'] ?? null;
        $audiences = is_array($audience) ? array_values($audience) : [$audience];
        if ($audiences === []
            || array_filter($audiences, fn (mixed $value): bool => ! is_string($value)) !== []
            || ! in_array($expectedAudience, $audiences, true)
        ) {
            throw new SsoException('SSO token audience is not this service.');
        }

        if (! isset($claims['sub']) || ! is_string($claims['sub']) || $claims['sub'] === '') {
            throw new SsoException('SSO token has no subject.');
        }

        return $claims;
    }

    private function keyId(string $jwt): ?string
    {
        $segments = explode('.', $jwt);
        if (count($segments) !== 3) {
            return null;
        }

        $header = json_decode(JWT::urlsafeB64Decode($segments[0]), true);
        $keyId = is_array($header) ? ($header['kid'] ?? null) : null;

        return is_string($keyId) && $keyId !== '' ? $keyId : null;
    }

    /** @param array<string, mixed> $jwks */
    private function containsKeyId(array $jwks, string $keyId): bool
    {
        foreach ($jwks['keys'] ?? [] as $key) {
            if (is_array($key) && ($key['kid'] ?? null) === $keyId) {
                return true;
            }
        }

        return false;
    }
}
