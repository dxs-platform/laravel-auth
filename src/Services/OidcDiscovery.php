<?php

declare(strict_types=1);

namespace Dxs\Auth\Services;

use Dxs\Auth\Exceptions\SsoException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

/**
 * OIDC discovery + JWKS, resolved from the issuer's `.well-known` and cached.
 * Nothing but the issuer is hardcoded — endpoints follow discovery, so a
 * gateway-anchored issuer is honoured transparently.
 */
final class OidcDiscovery
{
    /** @return array<string, mixed> */
    public function document(): array
    {
        return Cache::remember('sso:discovery', (int) config('sso.discovery_ttl'), function (): array {
            $url = rtrim((string) config('sso.issuer'), '/').'/.well-known/openid-configuration';
            $response = Http::timeout((int) config('sso.http_timeout'))->acceptJson()->get($url);

            if ($response->failed()) {
                throw new SsoException("SSO discovery failed ({$response->status()}) from {$url}");
            }

            $document = $response->json();
            if (! is_array($document)) {
                throw new SsoException("SSO discovery returned an invalid document from {$url}");
            }

            $expectedIssuer = rtrim((string) config('sso.issuer'), '/');
            $documentIssuer = $document['issuer'] ?? null;
            if (! is_string($documentIssuer) || rtrim($documentIssuer, '/') !== $expectedIssuer) {
                throw new SsoException('SSO discovery issuer does not match the configured issuer.');
            }

            return $document;
        });
    }

    public function authorizationEndpoint(): string
    {
        return $this->endpoint('authorization_endpoint');
    }

    public function tokenEndpoint(): string
    {
        return $this->endpoint('token_endpoint');
    }

    public function jwksUri(): string
    {
        return $this->endpoint('jwks_uri');
    }

    public function endSessionEndpoint(): ?string
    {
        return $this->document()['end_session_endpoint'] ?? null;
    }

    /** @return array<string, mixed> raw JWKS (`{ keys: [...] }`) */
    public function jwks(): array
    {
        return Cache::remember('sso:jwks', (int) config('sso.discovery_ttl'), function (): array {
            $response = Http::timeout((int) config('sso.http_timeout'))->acceptJson()->get($this->jwksUri());

            if ($response->failed()) {
                throw new SsoException("SSO JWKS fetch failed ({$response->status()}).");
            }

            $jwks = $response->json();
            if (! is_array($jwks) || ! isset($jwks['keys']) || ! is_array($jwks['keys']) || $jwks['keys'] === []) {
                throw new SsoException('SSO JWKS response does not contain any signing keys.');
            }

            return $jwks;
        });
    }

    private function endpoint(string $key): string
    {
        $value = $this->document()[$key] ?? null;

        if (! is_string($value) || $value === '') {
            throw new SsoException("SSO discovery is missing `{$key}`.");
        }

        return $value;
    }
}
