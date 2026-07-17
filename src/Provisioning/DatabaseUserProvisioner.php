<?php

declare(strict_types=1);

namespace Dxs\Auth\Provisioning;

use Dxs\Auth\Contracts\ProvisionsUsers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * The zero-config JIT provisioner: upserts the app's own user model (from
 * `auth.providers.users.model`, overridable via `sso.provisioner.model`)
 * keyed on the platform subject (`sub` → `console_user_id`), writing the
 * identity columns shipped by the package migration via forceFill — they
 * belong OUT of $fillable so mass assignment can never touch them.
 *
 * Bound as the default {@see ProvisionsUsers}; bind your own implementation
 * (or publish the stub with `sso:install --provisioner`) when the mapping
 * needs app-specific behaviour.
 */
final class DatabaseUserProvisioner implements ProvisionsUsers
{
    public function provision(array $claims, array $tokens): Authenticatable
    {
        $subject = (string) $claims['sub'];
        $model = $this->newModel();

        /** @var Model&Authenticatable $user */
        $user = $model->newQuery()->where('console_user_id', $subject)->first() ?? $model;

        $user->forceFill(array_filter([
            'console_user_id' => $subject,
            'name' => $claims['name'] ?? $user->getAttribute('name') ?? '',
            'email' => $claims['email'] ?? $user->getAttribute('email') ?? '',
            'console_organization_id' => $claims['organization_id'] ?? $user->getAttribute('console_organization_id'),
            'console_access_token' => $tokens['access_token'] ?? null,
            'console_refresh_token' => $tokens['refresh_token'] ?? $user->getAttribute('console_refresh_token'),
            'console_token_expires_at' => isset($tokens['expires_in'])
                ? Carbon::now()->addSeconds((int) $tokens['expires_in'])
                : $user->getAttribute('console_token_expires_at'),
        ], static fn ($value): bool => $value !== null));

        $user->save();

        return $user;
    }

    public function resolveBySubject(string $subject): ?Authenticatable
    {
        /** @var (Model&Authenticatable)|null */
        return $this->newModel()->newQuery()->where('console_user_id', $subject)->first();
    }

    private function newModel(): Model
    {
        /** @var class-string<Model> $class */
        $class = (string) (config('sso.provisioner.model') ?: config('auth.providers.users.model'));

        return new $class;
    }
}
