<?php

declare(strict_types=1);

namespace Dxs\Auth\Services;

use Dxs\Auth\Exceptions\SsoException;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

/**
 * Consumes the platform's authoritative permission read model. Authorization
 * DECISIONS stay on the platform (EffectiveAccessResolver); the downstream only
 * fetches the resolved permission list for the signed-in user + organization
 * and checks membership locally.
 *
 * NOTE (platform requirement): the endpoint must accept the downstream's OAuth
 * bearer. `/api/sso/me/permissions` is currently `core.auth` (Sanctum session)
 * only — the platform must also allow `idp.verify` (bearer) for downstreams,
 * or expose `/api/sso/service/me/permissions`. Configure via `sso.permissions_path`.
 */
final class PermissionClient
{
    public function __construct(private readonly OidcDiscovery $discovery) {}

    /**
     * @return array{permissions: list<string>, roles: list<array<string,mixed>>}
     */
    public function fetch(string $accessToken, string $organizationId, ?string $branchId = null): array
    {
        $key = 'sso:perms:'.sha1($accessToken.'|'.$organizationId.'|'.((string) $branchId));

        return Cache::remember($key, (int) config('sso.permissions_ttl', 300), function () use ($accessToken, $organizationId, $branchId): array {
            $url = rtrim((string) config('sso.issuer'), '/').'/'.ltrim((string) config('sso.permissions_path', 'api/sso/me/permissions'), '/');

            $response = Http::withToken($accessToken)
                ->timeout((int) config('sso.http_timeout'))
                ->acceptJson()
                ->get($url, array_filter([
                    'organization_id' => $organizationId,
                    'branch_id' => $branchId,
                ]));

            if ($response->failed()) {
                throw new SsoException("Permission fetch failed ({$response->status()}) from {$url}: ".$response->body());
            }

            $data = $response->json();

            return [
                'permissions' => array_values(array_map('strval', $data['permissions'] ?? [])),
                'roles' => array_values($data['roles'] ?? []),
            ];
        });
    }

    /** @return Collection<int, string> */
    public function permissionsFor(string $accessToken, string $organizationId, ?string $branchId = null): Collection
    {
        return collect($this->fetch($accessToken, $organizationId, $branchId)['permissions']);
    }
}
