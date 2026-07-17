<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\SsoClientServiceProvider;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

final class SsoRedirectControllerTest extends TestCase
{
    private const ORGANIZATION_CONTEXT_ID = '9f79d9ee-d735-4673-a80d-c11339f252be';

    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('session.driver', 'array');
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.service_slug', 'consumer-a');
        $app['config']->set('sso.client_id', 'consumer-a-client');
        $app['config']->set('sso.redirect_uri', 'https://consumer-a.example.test/auth/callback');
    }

    protected function setUp(): void
    {
        parent::setUp();

        Http::fake([
            'https://id.example.test/.well-known/openid-configuration' => Http::response([
                'authorization_endpoint' => 'https://id.example.test/sso/authorize',
                'token_endpoint' => 'https://id.example.test/api/sso/token',
                'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
            ]),
        ]);
    }

    public function test_it_binds_the_platform_selected_organization_to_the_oauth_transaction(): void
    {
        $response = $this->get('/auth/redirect?'.http_build_query([
            'organization_context_id' => self::ORGANIZATION_CONTEXT_ID,
            'return' => '/protected',
        ]));

        $response->assertRedirect();
        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);

        $this->assertSame(self::ORGANIZATION_CONTEXT_ID, $query['organization_context_id']);
        $this->assertSame('consumer-a', $query['service_slug']);
        $this->assertSame('code', $query['response_type']);
        $this->assertSame('S256', $query['code_challenge_method']);
        $this->assertNotSame('', $query['state']);
        $this->assertNotSame('', $query['nonce']);
        $this->assertNotSame('', $query['code_challenge']);
        $response->assertSessionHas('sso.organization_context_id', self::ORGANIZATION_CONTEXT_ID);
        $response->assertSessionHas('sso.return', '/protected');
    }

    public function test_fixed_single_tenant_context_cannot_be_overridden_by_the_request(): void
    {
        $this->app['config']->set('sso.organization_context_id', self::ORGANIZATION_CONTEXT_ID);

        $response = $this->get('/auth/redirect?organization_context_id=3efb1df0-1814-480c-9566-42d339758da8');
        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);

        $this->assertSame(self::ORGANIZATION_CONTEXT_ID, $query['organization_context_id']);
    }

    public function test_missing_or_malformed_organization_context_fails_before_authorization(): void
    {
        $this->withoutExceptionHandling();

        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('A valid organization context is required');

        $this->get('/auth/redirect?organization_context_id=not-a-uuid');
    }
}
