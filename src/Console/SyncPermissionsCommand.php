<?php

declare(strict_types=1);

namespace Dxs\Auth\Console;

use Dxs\Auth\Exceptions\SsoException;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;

/**
 * Pushes this service's permission catalog UP to the GoDX ID platform, so the
 * platform can build roles from the codes and resolve them for users at login.
 *
 *   php artisan dxs:sync-permissions [--dry-run]
 *
 * The catalog is owned by the service in `config/permissions.php`
 * (`permissions`, `roles`, `default_role`). Registration is admin-gated on the
 * platform, so it runs with an admin bearer (SSO_ADMIN_TOKEN) — typically from
 * CI or an operator, not the app runtime. Target:
 * `PUT {issuer}/{authz_path}` with `{service}` = config('sso.service_id').
 */
final class SyncPermissionsCommand extends Command
{
    protected $signature = 'dxs:sync-permissions {--dry-run : Print the payload without sending}';

    protected $description = 'Sync this service\'s permission catalog to the GoDX ID platform';

    public function handle(): int
    {
        /** @var array<string, mixed> $catalog */
        $catalog = [
            'permissions' => config('permissions.permissions', []),
            'roles' => config('permissions.roles', []),
            'default_role' => config('permissions.default_role'),
        ];

        $count = is_countable($catalog['permissions']) ? count($catalog['permissions']) : 0;

        if ($count === 0) {
            $this->warn('No permissions declared in config/permissions.php — nothing to sync.');

            return self::SUCCESS;
        }

        $validationError = $this->validationError($catalog);
        if ($validationError !== null) {
            $this->error($validationError);

            return self::FAILURE;
        }

        $service = (string) config('sso.service_id');
        if ($service === '') {
            $this->error('SSO_SERVICE_ID is not set — it identifies this service on the platform.');

            return self::FAILURE;
        }

        $this->line("Syncing {$count} permission code(s) for service [{$service}]");

        if ($this->option('dry-run')) {
            $this->line(json_encode($catalog, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));

            return self::SUCCESS;
        }

        $token = (string) config('sso.admin_token');
        if ($token === '') {
            $this->error('SSO_ADMIN_TOKEN is not set — an admin bearer with `catalog.authz.manage` is required.');

            return self::FAILURE;
        }

        $path = str_replace('{service}', rawurlencode($service), (string) config('sso.authz_path'));
        $url = rtrim((string) config('sso.issuer'), '/').'/'.ltrim($path, '/');

        $response = Http::withToken($token)
            ->timeout((int) config('sso.http_timeout', 5))
            ->acceptJson()
            ->put($url, $catalog);

        if ($response->failed()) {
            $this->error("Sync failed ({$response->status()}).");

            throw new SsoException('Permission catalog sync failed.');
        }

        $this->info("Permission catalog synced ({$count} codes).");

        return self::SUCCESS;
    }

    /** @param array<string, mixed> $catalog */
    private function validationError(array $catalog): ?string
    {
        $permissions = $catalog['permissions'] ?? null;
        if (! is_array($permissions)) {
            return 'Permission catalog must contain a permissions array.';
        }

        $slugs = [];
        foreach ($permissions as $index => $permission) {
            $slug = is_array($permission) ? ($permission['slug'] ?? null) : null;
            if (! is_string($slug) || trim($slug) === '') {
                return "Permission at index {$index} must have a non-empty string slug.";
            }

            if (isset($slugs[$slug])) {
                return "Permission slug [{$slug}] is duplicated.";
            }

            $slugs[$slug] = true;
        }

        $roles = $catalog['roles'] ?? [];
        if (! is_array($roles)) {
            return 'Permission catalog roles must be an array.';
        }

        $roleNames = [];
        foreach ($roles as $index => $role) {
            $roleName = is_array($role) ? ($role['role'] ?? null) : null;
            $rolePermissions = is_array($role) ? ($role['permissions'] ?? null) : null;
            if (! is_string($roleName) || trim($roleName) === '' || ! is_array($rolePermissions)) {
                return "Role at index {$index} must contain a role name and permissions array.";
            }

            if (isset($roleNames[$roleName])) {
                return "Role [{$roleName}] is duplicated.";
            }
            $roleNames[$roleName] = true;

            foreach ($rolePermissions as $permissionSlug) {
                if (! is_string($permissionSlug) || ! isset($slugs[$permissionSlug])) {
                    return "Role at index {$index} references an unknown permission.";
                }
            }
        }

        $defaultRole = $catalog['default_role'] ?? null;
        if ($defaultRole !== null && (! is_string($defaultRole) || ! isset($roleNames[$defaultRole]))) {
            return 'Default role must reference a declared role.';
        }

        return null;
    }
}
