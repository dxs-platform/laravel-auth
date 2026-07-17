<?php

declare(strict_types=1);

namespace Dxs\Auth\Services;

use Dxs\Auth\Exceptions\SsoException;
use Illuminate\Support\Collection;
use Dxs\Auth\Support\SsoCache;
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
        $tokenHash = hash('sha256', $accessToken);
        $key = SsoCache::key('perms:'.$tokenHash.':'.sha1($organizationId.'|'.((string) $branchId)));
        $this->indexKey($tokenHash, $key);

        return SsoCache::store()->remember($key, (int) config('sso.permissions_ttl', 300), function () use ($accessToken, $organizationId, $branchId): array {
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

    /**
     * Drop every cached permission list for a bearer (all org/branch
     * contexts). Called on local logout and back-channel logout so a revoked
     * token cannot keep answering Gate checks from cache.
     */
    public static function forgetForTokenHash(string $tokenHash): void
    {
        $store = SsoCache::store();
        $indexKey = SsoCache::key('perms-index:'.$tokenHash);

        foreach ((array) $store->pull($indexKey, []) as $key) {
            if (is_string($key)) {
                $store->forget($key);
            }
        }
    }

    /** Track which permission keys exist for a token, for later invalidation. */
    private function indexKey(string $tokenHash, string $key): void
    {
        $store = SsoCache::store();
        $indexKey = SsoCache::key('perms-index:'.$tokenHash);
        $index = (array) $store->get($indexKey, []);

        if (! in_array($key, $index, true)) {
            $index[] = $key;
            $store->put($indexKey, $index, (int) config('sso.permissions_ttl', 300));
        }
    }

    /** @return Collection<int, string> */
    public function permissionsFor(string $accessToken, string $organizationId, ?string $branchId = null): Collection
    {
        return collect($this->fetch($accessToken, $organizationId, $branchId)['permissions']);
    }
}
