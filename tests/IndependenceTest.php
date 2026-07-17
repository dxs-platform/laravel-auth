<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Console\SyncAuthzCommand;
use Dxs\Auth\Services\JwtVerifier;
use Dxs\Auth\Services\OidcDiscovery;
use Dxs\Auth\Services\PermissionClient;
use Dxs\Auth\Services\TokenExchanger;
use Dxs\Auth\SsoClientServiceProvider;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\TestCase;

/**
 * Proves the package boots and self-registers inside a bare Laravel app with NO
 * consumer code beyond config — the definition of "works for every downstream".
 */
final class IndependenceTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('sso.issuer', 'https://platform.example');
        $app['config']->set('sso.service_slug', 'any-downstream');
        $app['config']->set('sso.client_id', 'ci_example');
        $app['config']->set('sso.client_secret', 'secret');
        $app['config']->set('sso.redirect_uri', 'https://any.example/auth/callback');
    }

    public function test_it_registers_the_sso_auth_middleware_alias(): void
    {
        $aliases = $this->app['router']->getMiddleware();

        $this->assertArrayHasKey('sso.auth', $aliases);
    }

    public function test_it_registers_the_auth_routes_under_the_configured_prefix(): void
    {
        $paths = collect(Route::getRoutes()->getRoutes())
            ->map(fn ($route): string => $route->uri())
            ->all();

        $this->assertContains('auth/redirect', $paths);
        $this->assertContains('auth/callback', $paths);
        $this->assertContains('auth/logout', $paths);
    }

    public function test_a_consumer_can_override_the_route_prefix(): void
    {
        $this->app['config']->set('sso.routes.prefix', 'sso');
        (new SsoClientServiceProvider($this->app))->boot($this->app['router']);

        $paths = collect(Route::getRoutes()->getRoutes())
            ->map(fn ($route): string => $route->uri())
            ->all();

        $this->assertContains('sso/redirect', $paths);
    }

    public function test_it_resolves_every_core_service_from_the_container(): void
    {
        $this->assertInstanceOf(OidcDiscovery::class, $this->app->make(OidcDiscovery::class));
        $this->assertInstanceOf(JwtVerifier::class, $this->app->make(JwtVerifier::class));
        $this->assertInstanceOf(TokenExchanger::class, $this->app->make(TokenExchanger::class));
        $this->assertInstanceOf(PermissionClient::class, $this->app->make(PermissionClient::class));
    }

    public function test_it_registers_the_authz_sync_command(): void
    {
        $this->assertArrayHasKey('dxs:sync-authz', $this->app[Kernel::class]->all());
        $this->assertTrue(class_exists(SyncAuthzCommand::class));
    }

    public function test_it_merges_the_default_authz_catalog_without_publishing_config(): void
    {
        $this->assertSame([], config('authz.permissions'));
        $this->assertSame([], config('authz.roles'));
        $this->assertNull(config('authz.default_role'));
    }
}
