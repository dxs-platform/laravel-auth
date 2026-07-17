<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\SsoClientServiceProvider;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

final class RegisterPermissionsCommandTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.service_slug', 'consumer-a');
        $app['config']->set('sso.service_id', 'service/a?tenant=other');
        $app['config']->set('sso.admin_token', 'admin-secret');
        $app['config']->set('sso.http_timeout', 5);
        $app['config']->set('sso.permissions_manifest', $this->manifest('consumer-a.read'));
    }

    public function test_dry_run_is_deterministic_and_performs_no_http_request(): void
    {
        Http::fake();

        $this->artisan('dxs-auth:register-permissions', ['--dry-run' => true])
            ->expectsOutputToContain('consumer-a.read')
            ->assertSuccessful();

        Http::assertNothingSent();
    }

    public function test_invalid_duplicate_and_unknown_role_permissions_fail_before_http(): void
    {
        Http::fake();

        foreach ([
            ['permissions' => [['code' => 'same'], ['code' => 'same']]],
            ['permissions' => [['code' => 'known']], 'roles' => [['role' => 'admin', 'permissions' => ['unknown']]]],
            ['permissions' => [['code' => '']]],
        ] as $manifest) {
            config()->set('sso.permissions_manifest', $manifest);

            $this->artisan('dxs-auth:register-permissions')->assertFailed();
        }

        Http::assertNothingSent();
    }

    public function test_service_identifier_is_encoded_and_repeated_registration_is_idempotent(): void
    {
        Http::fake(['*' => Http::response(['registered' => true])]);

        $this->artisan('dxs-auth:register-permissions')->assertSuccessful();
        $this->artisan('dxs-auth:register-permissions')->assertSuccessful();

        Http::assertSentCount(2);
        Http::assertSent(fn (Request $request): bool => $request->url() === 'https://id.example.test/api/admin/services/service%2Fa%3Ftenant%3Dother/authz'
            && $request->hasHeader('Authorization', 'Bearer admin-secret')
            && $request['permissions'][0]['code'] === 'consumer-a.read');
    }

    public function test_two_services_send_disjoint_catalogs_to_disjoint_endpoints(): void
    {
        Http::fake(['*' => Http::response(['registered' => true])]);

        config()->set('sso.service_id', 'service-a');
        $this->artisan('dxs-auth:register-permissions')->assertSuccessful();

        config()->set('sso.service_id', 'service-b');
        config()->set('sso.permissions_manifest', $this->manifest('consumer-b.write'));
        $this->artisan('dxs-auth:register-permissions')->assertSuccessful();

        Http::assertSent(fn (Request $request): bool => str_contains($request->url(), '/service-a/authz')
            && $request['permissions'][0]['code'] === 'consumer-a.read');
        Http::assertSent(fn (Request $request): bool => str_contains($request->url(), '/service-b/authz')
            && $request['permissions'][0]['code'] === 'consumer-b.write');
    }

    public function test_failed_registration_does_not_reflect_the_response_body(): void
    {
        Http::fake(['*' => Http::response(['debug' => 'access-token-secret'], 422)]);

        try {
            $this->artisan('dxs-auth:register-permissions')->run();
            $this->fail('Expected registration failure.');
        } catch (SsoException $exception) {
            $this->assertSame('Permission registration failed.', $exception->getMessage());
            $this->assertStringNotContainsString('access-token-secret', $exception->getMessage());
        }
    }

    /** @return array{permissions: array<int, array{code: string, name: string}>, roles: array<int, array{role: string, permissions: array<int, string>}>} */
    private function manifest(string $code): array
    {
        return [
            'permissions' => [['code' => $code, 'name' => 'Permission']],
            'roles' => [['role' => 'operator', 'permissions' => [$code]]],
        ];
    }
}
