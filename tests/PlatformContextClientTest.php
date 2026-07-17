<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\Services\PlatformContextClient;
use Dxs\Auth\SsoClientServiceProvider;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

final class PlatformContextClientTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.http_timeout', 5);
    }

    public function test_it_reads_every_tenant_context_with_the_server_side_bearer(): void
    {
        Http::preventStrayRequests();
        Http::fake([
            'https://id.example.test/api/sso/organizations' => Http::response([
                ['organization_id' => 'org-1', 'organization_slug' => 'acme', 'organization_name' => 'Acme'],
            ]),
            'https://id.example.test/api/sso/access*' => Http::response(['service_role' => 'admin']),
            'https://id.example.test/api/sso/branches*' => Http::response(['branches' => [['id' => 'branch-1']]]),
            'https://id.example.test/api/sso/brands*' => Http::response(['brands' => [['brand_id' => 'brand-1']]]),
        ]);

        $client = $this->app->make(PlatformContextClient::class);

        $this->assertSame('org-1', $client->organizations('secret-token')[0]['organization_id']);
        $this->assertSame('admin', $client->access('secret-token', 'acme')['service_role']);
        $this->assertSame('branch-1', $client->branches('secret-token', 'acme')['branches'][0]['id']);
        $this->assertSame('brand-1', $client->brands('secret-token', 'acme')['brands'][0]['brand_id']);

        Http::assertSent(function (Request $request): bool {
            if (! $request->hasHeader('Authorization', 'Bearer secret-token')) {
                return false;
            }

            return ! str_contains($request->url(), 'organization_slug=')
                || str_contains($request->url(), 'organization_slug=acme');
        });
        Http::assertSentCount(4);
    }

    public function test_it_rejects_denied_and_malformed_context_responses_without_echoing_secrets(): void
    {
        Http::fakeSequence()
            ->push(['error' => 'CONTEXT_UNAVAILABLE', 'token' => 'must-not-leak'], 403)
            ->push('not-json');

        $client = $this->app->make(PlatformContextClient::class);

        try {
            $client->access('secret-token', 'foreign');
            $this->fail('Expected the denied context response to throw.');
        } catch (SsoException $exception) {
            $this->assertStringContainsString('failed (403)', $exception->getMessage());
            $this->assertStringNotContainsString('must-not-leak', $exception->getMessage());
            $this->assertStringNotContainsString('secret-token', $exception->getMessage());
        }

        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('returned malformed JSON');
        $client->organizations('secret-token');
    }
}
