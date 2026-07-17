<?php

declare(strict_types=1);

namespace Dxs\Auth;

use Dxs\Auth\Console\SyncAuthzCommand;
use Dxs\Auth\Http\Middleware\AuthenticateSso;
use Dxs\Auth\Http\Middleware\AuthorizeSsoPermission;
use Dxs\Auth\Services\JwtVerifier;
use Dxs\Auth\Services\LogoutSessionRegistry;
use Dxs\Auth\Services\OidcDiscovery;
use Dxs\Auth\Services\PermissionClient;
use Dxs\Auth\Services\TokenExchanger;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;

final class SsoClientServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/sso.php', 'sso');
        $this->mergeConfigFrom(__DIR__.'/../config/authz.php', 'authz');

        $this->app->singleton(OidcDiscovery::class);
        $this->app->singleton(JwtVerifier::class);
        $this->app->singleton(LogoutSessionRegistry::class);
        $this->app->singleton(TokenExchanger::class);
        $this->app->singleton(PermissionClient::class);
    }

    public function boot(Router $router): void
    {
        $this->publishes([
            __DIR__.'/../config/sso.php' => config_path('sso.php'),
            __DIR__.'/../config/authz.php' => config_path('authz.php'),
        ], 'sso-config');

        if ($this->app->runningInConsole()) {
            $this->commands([SyncAuthzCommand::class]);
        }

        // `sso.auth` — validate a platform-issued bearer JWT (JWKS/aud/exp) and
        // resolve the local user. Replaces the gateway header-trust middleware.
        $router->aliasMiddleware('sso.auth', AuthenticateSso::class);

        // `sso.can:{ability,…}` — authenticate the bearer AND require every
        // listed platform ability in one alias, with RFC 6750
        // `insufficient_scope` semantics on denial.
        $router->aliasMiddleware('sso.can', AuthorizeSsoPermission::class);

        // Authorization DECISIONS stay on the platform: a granted ability is one
        // present in the user's platform-resolved permission list. Explicit
        // policies still run for abilities not in the list (Gate::before → null).
        Gate::before(function (Authenticatable $user, string $ability): ?bool {
            $token = data_get($user, 'console_access_token');
            $org = data_get($user, 'console_organization_id');

            if (! is_string($token) || $token === '' || ! is_string($org) || $org === '') {
                return null;
            }

            $branch = data_get($user, 'console_branch_id');
            $branch = is_string($branch) && $branch !== '' ? $branch : null;

            return $this->app->make(PermissionClient::class)
                ->permissionsFor($token, $org, $branch)
                ->contains($ability) ? true : null;
        });

        if (config('sso.routes.enabled')) {
            $router->group([
                'prefix' => config('sso.routes.prefix'),
                'middleware' => config('sso.routes.middleware'),
            ], fn () => $this->loadRoutesFrom(__DIR__.'/../routes/web.php'));
        }
    }
}
