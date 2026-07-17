<?php

declare(strict_types=1);

namespace Dxs\Auth\Services;

use Dxs\Auth\Support\SsoCache;
use Illuminate\Contracts\Cache\Repository;

final class LogoutSessionRegistry
{
    private readonly Repository $cache;

    public function __construct(?Repository $cache = null)
    {
        $this->cache = $cache ?? SsoCache::store();
    }

    /** @param array<string, mixed> $claims */
    public function register(array $claims, string $token, string $sessionId): void
    {
        $sessionLineage = $claims['sid'] ?? null;
        if (! is_string($sessionLineage) || $sessionLineage === '') {
            return;
        }

        $ttl = max(1, ((int) ($claims['exp'] ?? time() + 900)) - time());
        $this->cache->put($this->sessionKey($sessionLineage), [
            'session_id' => $sessionId,
            'token_hash' => hash('sha256', $token),
            'expires_at' => time() + $ttl,
        ], $ttl);
    }

    /** @return array{session_id: string, token_hash: string, expires_at: int}|null */
    public function revoke(string $sessionLineage): ?array
    {
        $registration = $this->cache->pull($this->sessionKey($sessionLineage));
        if (! is_array($registration)
            || ! is_string($registration['session_id'] ?? null)
            || ! is_string($registration['token_hash'] ?? null)
        ) {
            return null;
        }

        $ttl = max(1, ((int) ($registration['expires_at'] ?? time() + 900)) - time());
        $this->cache->put($this->revokedTokenKey($registration['token_hash']), true, $ttl);

        // The bearer is dead — its cached permission lists must die with it.
        PermissionClient::forgetForTokenHash($registration['token_hash']);

        return $registration;
    }

    public function tokenIsRevoked(string $token): bool
    {
        return $this->cache->has($this->revokedTokenKey(hash('sha256', $token)));
    }

    private function sessionKey(string $sessionLineage): string
    {
        return SsoCache::key('logout-session:'.hash('sha256', (string) config('sso.issuer').'|'.(string) config('sso.service_slug').'|'.$sessionLineage));
    }

    private function revokedTokenKey(string $tokenHash): string
    {
        return SsoCache::key('revoked-token:'.$tokenHash);
    }
}
