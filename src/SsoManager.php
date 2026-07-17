<?php

declare(strict_types=1);

namespace Dxs\Auth;

use Dxs\Auth\Services\PermissionClient;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;

/**
 * The ergonomic read surface for the current user's platform authorization —
 * what the {@see \Dxs\Auth\Facades\Sso} facade proxies. Gate answers yes/no
 * per ability; this exposes the whole platform-resolved picture (permission
 * slugs AND roles) so downstream controllers, views and Inertia share can
 * render "what can this user do" without touching the HTTP client.
 *
 * Every read reuses {@see PermissionClient}, so it hits the same cache the
 * Gate uses — no extra platform round-trips within the permission TTL.
 */
final class SsoManager
{
    public function __construct(private readonly PermissionClient $permissions) {}

    /** The currently authenticated user, if any. */
    public function user(): ?Authenticatable
    {
        return Auth::user();
    }

    /** True when the user is authenticated AND carries platform context. */
    public function check(): bool
    {
        return $this->context() !== null;
    }

    /**
     * The current user's platform permission slugs (empty when unauthenticated
     * or lacking platform context).
     *
     * @return Collection<int, string>
     */
    public function permissions(): Collection
    {
        $context = $this->context();
        if ($context === null) {
            return collect();
        }

        return $this->permissions->resolveFor($context['token'], $context['organization'], $context['branch'])['permissions'];
    }

    /**
     * The current user's platform roles (each a {slug/display_name/level/…}
     * shape as the platform declared it).
     *
     * @return list<array<string, mixed>>
     */
    public function roles(): array
    {
        $context = $this->context();
        if ($context === null) {
            return [];
        }

        return $this->permissions->resolveFor($context['token'], $context['organization'], $context['branch'])['roles'];
    }

    /** True when the current user holds the given platform permission. */
    public function can(string $ability): bool
    {
        return $this->permissions()->contains($ability);
    }

    /** True when the current user holds every listed permission. */
    public function canAll(string ...$abilities): bool
    {
        $held = $this->permissions();

        foreach ($abilities as $ability) {
            if (! $held->contains($ability)) {
                return false;
            }
        }

        return true;
    }

    /** True when the current user holds at least one listed permission. */
    public function canAny(string ...$abilities): bool
    {
        $held = $this->permissions();

        foreach ($abilities as $ability) {
            if ($held->contains($ability)) {
                return true;
            }
        }

        return false;
    }

    /** True when the current user holds a platform role by name. */
    public function hasRole(string $role): bool
    {
        foreach ($this->roles() as $declared) {
            if (($declared['role'] ?? $declared['slug'] ?? null) === $role) {
                return true;
            }
        }

        return false;
    }

    /**
     * The authenticated user's platform context, or null when unavailable.
     *
     * @return array{token: string, organization: string, branch: ?string}|null
     */
    private function context(): ?array
    {
        $user = Auth::user();
        if ($user === null) {
            return null;
        }

        $token = data_get($user, 'console_access_token');
        $organization = data_get($user, 'console_organization_id');
        if (! is_string($token) || $token === '' || ! is_string($organization) || $organization === '') {
            return null;
        }

        $branch = data_get($user, 'console_branch_id');

        return [
            'token' => $token,
            'organization' => $organization,
            'branch' => is_string($branch) && $branch !== '' ? $branch : null,
        ];
    }
}
