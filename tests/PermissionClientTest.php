<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\Services\PermissionClient;
use Dxs\Auth\SsoClientServiceProvider;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

final class PermissionClientTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.permissions_ttl', 300);
        $app['config']->set('cache.default', 'array');
    }

    protected function setUp(): void
    {
        parent::setUp();
        Cache::clear();
    }

    public function test_it_sends_the_downstream_bearer_and_exact_authorization_context(): void
    {
        Http::fake([
            'https://id.example.test/api/sso/me/permissions*' => Http::response([
                'permissions' => ['records.read', 'records.write'],
                'roles' => ['operator'],
                'service_access' => ['consumer-a' => ['permissions' => ['records.read']]],
                'contract_version' => '1.0',
            ]),
        ]);

        $result = $this->app->make(PermissionClient::class)->fetch(
            'service-access-token',
            '9f79d9ee-d735-4673-a80d-c11339f252be',
            '00e9289b-f980-48ea-8943-b91cb4de3e85',
        );

        $this->assertSame(['records.read', 'records.write'], $result['permissions']);
        $this->assertSame(['operator'], $result['roles']);
        Http::assertSent(fn (Request $request): bool => $request->hasHeader('Authorization', 'Bearer service-access-token')
            && $request['organization_id'] === '9f79d9ee-d735-4673-a80d-c11339f252be'
            && $request['branch_id'] === '00e9289b-f980-48ea-8943-b91cb4de3e85');
    }

    public function test_cache_is_isolated_by_token_organization_and_branch(): void
    {
        Http::fakeSequence()
            ->push(['permissions' => ['a'], 'roles' => []])
            ->push(['permissions' => ['b'], 'roles' => []])
            ->push(['permissions' => ['c'], 'roles' => []]);

        $client = $this->app->make(PermissionClient::class);

        $this->assertSame(['a'], $client->fetch('token-a', 'org-a', 'branch-a')['permissions']);
        $this->assertSame(['a'], $client->fetch('token-a', 'org-a', 'branch-a')['permissions']);
        $this->assertSame(['b'], $client->fetch('token-a', 'org-a', 'branch-b')['permissions']);
        $this->assertSame(['c'], $client->fetch('token-b', 'org-a', 'branch-a')['permissions']);
        Http::assertSentCount(3);
    }

    public function test_platform_denial_fails_closed_without_caching_a_permission_result(): void
    {
        Http::fake([
            '*' => Http::response(['error' => 'CONTEXT_UNAVAILABLE'], 403),
        ]);

        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('Permission fetch failed (403)');

        $this->app->make(PermissionClient::class)->fetch('token', 'wrong-org');
    }
}
