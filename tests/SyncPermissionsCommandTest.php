<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\SsoClientServiceProvider;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

final class SyncPermissionsCommandTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.service_id', 'service/a?tenant=other');
        $app['config']->set('sso.authz_path', 'api/admin/services/{service}/authz');
        $app['config']->set('sso.admin_token', 'admin-secret');
        $app['config']->set('sso.http_timeout', 5);
        $app['config']->set('permissions', $this->catalog('consumer-a.read'));
    }

    public function test_dry_run_is_deterministic_and_performs_no_http_request(): void
    {
        Http::fake();

        $this->artisan('dxs:sync-permissions', ['--dry-run' => true])
            ->expectsOutputToContain('consumer-a.read')
            ->assertSuccessful();

        Http::assertNothingSent();
    }

    public function test_invalid_duplicates_unknown_references_and_default_role_fail_before_http(): void
    {
        Http::fake();

        foreach ([
            ['permissions' => [['slug' => 'same'], ['slug' => 'same']]],
            ['permissions' => [['slug' => 'known']], 'roles' => [['role' => 'admin', 'permissions' => ['unknown']]]],
            ['permissions' => [['slug' => '']]],
            ['permissions' => [['slug' => 'known']], 'roles' => [], 'default_role' => 'missing'],
        ] as $catalog) {
            config()->set('permissions', $catalog);

            $this->artisan('dxs:sync-permissions')->assertFailed();
        }

        Http::assertNothingSent();
    }

    public function test_service_identifier_is_encoded_and_repeated_sync_is_idempotent(): void
    {
        Http::fake(['*' => Http::response(['registered' => true])]);

        $this->artisan('dxs:sync-permissions')->assertSuccessful();
        $this->artisan('dxs:sync-permissions')->assertSuccessful();

        Http::assertSentCount(2);
        Http::assertSent(fn (Request $request): bool => $request->url() === 'https://id.example.test/api/admin/services/service%2Fa%3Ftenant%3Dother/authz'
            && $request->hasHeader('Authorization', 'Bearer admin-secret')
            && $request['permissions'][0]['slug'] === 'consumer-a.read');
    }

    public function test_two_services_send_disjoint_catalogs_to_disjoint_endpoints(): void
    {
        Http::fake(['*' => Http::response(['registered' => true])]);

        config()->set('sso.service_id', 'service-a');
        $this->artisan('dxs:sync-permissions')->assertSuccessful();

        config()->set('sso.service_id', 'service-b');
        config()->set('permissions', $this->catalog('consumer-b.write'));
        $this->artisan('dxs:sync-permissions')->assertSuccessful();

        Http::assertSent(fn (Request $request): bool => str_contains($request->url(), '/service-a/authz')
            && $request['permissions'][0]['slug'] === 'consumer-a.read');
        Http::assertSent(fn (Request $request): bool => str_contains($request->url(), '/service-b/authz')
            && $request['permissions'][0]['slug'] === 'consumer-b.write');
    }

    public function test_failed_sync_does_not_reflect_the_response_body(): void
    {
        Http::fake(['*' => Http::response(['debug' => 'access-token-secret'], 422)]);

        try {
            $this->artisan('dxs:sync-permissions')->run();
            $this->fail('Expected sync failure.');
        } catch (SsoException $exception) {
            $this->assertSame('Permission catalog sync failed.', $exception->getMessage());
            $this->assertStringNotContainsString('access-token-secret', $exception->getMessage());
        }
    }

    /** @return array{permissions: array<int, array{slug: string, display_name: string}>, roles: array<int, array{role: string, permissions: array<int, string>}>, default_role: string} */
    private function catalog(string $slug): array
    {
        return [
            'permissions' => [['slug' => $slug, 'display_name' => 'Permission']],
            'roles' => [['role' => 'operator', 'permissions' => [$slug]]],
            'default_role' => 'operator',
        ];
    }
}
