<?php

declare(strict_types=1);

namespace Dxs\Auth\Services;

use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\Support\SsoCache;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Keeps a session's stored platform access token fresh. Access tokens are
 * short-lived (RFC 9068, ~15 min) but the Laravel session outlives them, so
 * without refresh an authenticated user's `console_access_token` goes stale
 * and every permission read 401s — the user silently loses all access while
 * still "logged in". This refreshes the token from the stored refresh token
 * before it expires, in place on the user record.
 *
 * Registered as a singleton so `refreshedThisRequest` memoises per request:
 * the Gate runs before() on every ability check, but the refresh happens at
 * most once per user per request.
 */
final class TokenRefresher
{
    /** @var array<string, true> user identifiers already handled this request */
    private array $refreshedThisRequest = [];

    public function __construct(private readonly TokenExchanger $exchanger) {}

    /**
     * Refresh the user's access token in place when it is near or past expiry.
     * No-op when disabled, already handled this request, or the user lacks a
     * refresh token. A failed refresh is logged and swallowed — the downstream
     * permission read fails closed, and forcing a logout from inside an
     * authorization check would be too aggressive.
     */
    public function ensureFresh(Authenticatable $user): void
    {
        if (! (bool) config('sso.refresh.enabled', true)) {
            return;
        }

        $id = (string) $user->getAuthIdentifier();
        if ($id === '' || isset($this->refreshedThisRequest[$id])) {
            return;
        }
        $this->refreshedThisRequest[$id] = true;

        $refreshToken = data_get($user, 'console_refresh_token');
        if (! is_string($refreshToken) || $refreshToken === '') {
            return;
        }

        if (! $this->isNearExpiry(data_get($user, 'console_token_expires_at'))) {
            return;
        }

        // Serialise refresh across concurrent requests (multi-tab, prefetch):
        // refreshing the same refresh token twice can trip the platform's
        // rotation reuse-detection and revoke the whole family. A request that
        // cannot take the lock skips — the token is only NEAR expiry, so its
        // own reads still succeed while the lock holder refreshes.
        $lock = SsoCache::store()->lock('sso:refresh-lock:'.hash('sha256', $refreshToken), 10);
        if (! $lock->get()) {
            return;
        }

        // Hold the lock until the new tokens are persisted, so a concurrent
        // request cannot re-refresh the still-stored old refresh token.
        try {
            $tokens = $this->exchanger->refresh($refreshToken);

            if ($user instanceof Model) {
                $user->forceFill(array_filter([
                    'console_access_token' => $tokens['access_token'],
                    'console_refresh_token' => $tokens['refresh_token'] ?? $refreshToken,
                    'console_token_expires_at' => isset($tokens['expires_in'])
                        ? Carbon::now()->addSeconds((int) $tokens['expires_in'])
                        : null,
                ], static fn ($value): bool => $value !== null))->save();
            }
        } catch (SsoException $exception) {
            Log::warning('SSO token refresh failed — session will fail closed until re-login: '.$exception->getMessage());
        } finally {
            $lock->release();
        }
    }

    /**
     * True when the token expires within the leeway window (or is already
     * expired, or its expiry is unknown — refresh defensively).
     */
    private function isNearExpiry(mixed $expiresAt): bool
    {
        if ($expiresAt === null) {
            return true;
        }

        try {
            $expiry = $expiresAt instanceof Carbon ? $expiresAt : Carbon::parse((string) $expiresAt);
        } catch (Throwable) {
            return true;
        }

        $leeway = (int) config('sso.refresh.leeway', 60);

        return $expiry->getTimestamp() - $leeway <= Carbon::now()->getTimestamp();
    }
}
