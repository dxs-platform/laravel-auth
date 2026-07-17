<?php

declare(strict_types=1);

namespace Dxs\Auth\Services;

use Dxs\Auth\Exceptions\SsoException;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;

/**
 * Reads the current user's tenant directory from the platform IdP.
 *
 * The access token stays server-side. Every request is evaluated upstream so
 * a downstream cannot use stale local membership to cross tenant boundaries.
 */
final class PlatformContextClient
{
    /** @return list<array<string, mixed>> */
    public function organizations(string $accessToken): array
    {
        $data = $this->get($accessToken, 'organizations');

        return array_values(array_filter($data, 'is_array'));
    }

    /** @return array<string, mixed> */
    public function access(string $accessToken, string $organizationSlug): array
    {
        return $this->get($accessToken, 'access', ['organization_slug' => $organizationSlug]);
    }

    /** @return array<string, mixed> */
    public function branches(string $accessToken, string $organizationSlug): array
    {
        return $this->get($accessToken, 'branches', ['organization_slug' => $organizationSlug]);
    }

    /** @return array<string, mixed> */
    public function brands(string $accessToken, string $organizationSlug): array
    {
        return $this->get($accessToken, 'brands', ['organization_slug' => $organizationSlug]);
    }

    /**
     * @param  array<string, scalar|null>  $query
     * @return array<string, mixed>
     */
    private function get(string $accessToken, string $endpoint, array $query = []): array
    {
        $path = config("sso.context_paths.{$endpoint}");
        if (! is_string($path) || $path === '') {
            throw new SsoException("SSO context endpoint [{$endpoint}] is not configured.");
        }

        $url = rtrim((string) config('sso.issuer'), '/').'/'.ltrim($path, '/');
        try {
            $response = Http::withToken($accessToken)
                ->acceptJson()
                ->connectTimeout(min(3, (int) config('sso.http_timeout', 5)))
                ->timeout((int) config('sso.http_timeout', 5))
                ->get($url, array_filter($query, static fn (mixed $value): bool => $value !== null));
        } catch (ConnectionException $exception) {
            throw new SsoException("SSO context fetch [{$endpoint}] is temporarily unreachable.", previous: $exception);
        }

        return $this->decode($response, $endpoint);
    }

    /** @return array<string, mixed> */
    private function decode(Response $response, string $endpoint): array
    {
        if ($response->failed()) {
            throw new SsoException("SSO context fetch [{$endpoint}] failed ({$response->status()}).");
        }

        $data = $response->json();
        if (! is_array($data)) {
            throw new SsoException("SSO context fetch [{$endpoint}] returned malformed JSON.");
        }

        return $data;
    }
}
