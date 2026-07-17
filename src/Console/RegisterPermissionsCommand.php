<?php

declare(strict_types=1);

namespace Dxs\Auth\Console;

use Dxs\Auth\Exceptions\SsoException;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;

/**
 * Pushes this downstream service's permission catalog (codes it declares) UP to
 * the platform, so the platform can build roles from them and resolve them for
 * users. The catalog is a static manifest owned by the service.
 *
 *   php artisan dxs-auth:register-permissions
 *
 * Registration is admin-gated on the platform (`admin.can:catalog.authz.manage`),
 * so this runs with an admin token (SSO_ADMIN_TOKEN), typically from CI / an
 * operator — not the app runtime. Target: `PUT {issuer}/api/admin/services/{service}/authz`.
 */
final class RegisterPermissionsCommand extends Command
{
    protected $signature = 'dxs-auth:register-permissions {--dry-run : Print the manifest payload without sending}';

    protected $description = 'Register this service\'s permission catalog with the GoDX platform';

    public function handle(): int
    {
        /** @var array<string, mixed> $manifest */
        $manifest = config('sso.permissions_manifest', []);

        if (empty($manifest['permissions'] ?? [])) {
            $this->warn('No permissions declared in config(sso.permissions_manifest). Nothing to register.');

            return self::SUCCESS;
        }

        $validationError = $this->validationError($manifest);
        if ($validationError !== null) {
            $this->error($validationError);

            return self::FAILURE;
        }

        $this->line('Registering '.count($manifest['permissions']).' permission code(s) for service ['.(string) config('sso.service_slug').']');

        if ($this->option('dry-run')) {
            $this->line(json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

            return self::SUCCESS;
        }

        $token = (string) config('sso.admin_token');
        if ($token === '') {
            $this->error('SSO_ADMIN_TOKEN is not set — an admin token with `catalog.authz.manage` is required to register.');

            return self::FAILURE;
        }

        $service = (string) config('sso.service_id');
        if ($service === '') {
            $service = (string) config('sso.service_slug');
        }

        $url = rtrim((string) config('sso.issuer'), '/').'/api/admin/services/'.rawurlencode($service).'/authz';

        $response = Http::withToken($token)
            ->timeout((int) config('sso.http_timeout'))
            ->acceptJson()
            ->put($url, $manifest);

        if ($response->failed()) {
            $this->error("Registration failed ({$response->status()}).");

            throw new SsoException('Permission registration failed.');
        }

        $this->info('Permission catalog registered.');

        return self::SUCCESS;
    }

    /** @param array<string, mixed> $manifest */
    private function validationError(array $manifest): ?string
    {
        $permissions = $manifest['permissions'] ?? null;
        if (! is_array($permissions)) {
            return 'Permission manifest must contain a permissions array.';
        }

        $codes = [];
        foreach ($permissions as $index => $permission) {
            $code = is_array($permission) ? ($permission['code'] ?? null) : null;
            if (! is_string($code) || trim($code) === '') {
                return "Permission at index {$index} must have a non-empty string code.";
            }

            if (isset($codes[$code])) {
                return "Permission code [{$code}] is duplicated.";
            }

            $codes[$code] = true;
        }

        $roles = $manifest['roles'] ?? [];
        if (! is_array($roles)) {
            return 'Permission manifest roles must be an array.';
        }

        foreach ($roles as $index => $role) {
            $rolePermissions = is_array($role) ? ($role['permissions'] ?? null) : null;
            if (! is_array($rolePermissions)) {
                return "Role at index {$index} must contain a permissions array.";
            }

            foreach ($rolePermissions as $permissionCode) {
                if (! is_string($permissionCode) || ! isset($codes[$permissionCode])) {
                    return "Role at index {$index} references an unknown permission.";
                }
            }
        }

        return null;
    }
}
