<?php

declare(strict_types=1);

namespace Dxs\Auth;

use Dxs\Auth\Facades\Sso;
use Dxs\Auth\Services\PermissionClient;
use Dxs\Auth\Services\PlatformContextClient;
use Dxs\Auth\Services\TokenRefresher;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;

/**
 * The ergonomic read surface for the current user's platform authorization —
 * what the {@see Sso} facade proxies. Gate answers yes/no
 * per ability; this exposes the whole platform-resolved picture (permission
 * slugs AND roles) so downstream controllers, views and Inertia share can
 * render "what can this user do" without touching the HTTP client.
 *
 * Every read reuses {@see PermissionClient}, so it hits the same cache the
 * Gate uses — no extra platform round-trips within the permission TTL.
 */
final class SsoManager
{
    public function __construct(
        private readonly PermissionClient $permissions,
        private readonly TokenRefresher $refresher,
        private readonly PlatformContextClient $platformContext,
    ) {}

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
     * @return list<string|array<string, mixed>>
     */
    public function roles(): array
    {
        $context = $this->context();
        if ($context === null) {
            return [];
        }

        return $this->permissions->resolveFor($context['token'], $context['organization'], $context['branch'])['roles'];
    }

    /** @return array<string, mixed> */
    public function serviceAccess(): array
    {
        $context = $this->context();

        return $context === null
            ? []
            : $this->permissions->resolveFor($context['token'], $context['organization'], $context['branch'])['service_access'];
    }

    /** @return list<array<string, mixed>> */
    public function organizations(): array
    {
        $context = $this->context();

        return $context === null ? [] : $this->platformContext->organizations($context['token']);
    }

    /** @return array<string, mixed> */
    public function organizationAccess(string $organizationSlug): array
    {
        $context = $this->context();

        return $context === null ? [] : $this->platformContext->access($context['token'], $organizationSlug);
    }

    /** @return array<string, mixed> */
    public function branches(string $organizationSlug): array
    {
        $context = $this->context();

        return $context === null ? [] : $this->platformContext->branches($context['token'], $organizationSlug);
    }

    /** @return array<string, mixed> */
    public function brands(string $organizationSlug): array
    {
        $context = $this->context();

        return $context === null ? [] : $this->platformContext->brands($context['token'], $organizationSlug);
    }

    /** True when the current user holds the given platform permission. */
    public function can(string $ability): bool
    {
        $context = $this->context();
        if ($context === null) {
            return false;
        }

        $decision = $this->permissions->resolveFor($context['token'], $context['organization'], $context['branch']);

        return $decision['authoritative'] && $decision['permissions']->contains($ability);
    }

    /** True when the current user holds every listed permission. */
    public function canAll(string ...$abilities): bool
    {
        $held = collect($abilities)->filter(fn (string $ability): bool => $this->can($ability));

        return $held->count() === count($abilities);
    }

    /** True when the current user holds at least one listed permission. */
    public function canAny(string ...$abilities): bool
    {
        foreach ($abilities as $ability) {
            if ($this->can($ability)) {
                return true;
            }
        }

        return false;
    }

    /** True when the current user holds a platform role by name. */
    public function hasRole(string $role): bool
    {
        $context = $this->context();
        if ($context === null) {
            return false;
        }

        $decision = $this->permissions->resolveFor($context['token'], $context['organization'], $context['branch']);
        if (! $decision['authoritative']) {
            return false;
        }

        foreach ($decision['roles'] as $declared) {
            if (is_string($declared) && hash_equals($declared, $role)) {
                return true;
            }

            if (! is_array($declared)) {
                continue;
            }

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

        $this->refresher->ensureFresh($user);

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
