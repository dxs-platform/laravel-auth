<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\Services\OidcDiscovery;
use Dxs\Auth\SsoClientServiceProvider;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

final class OidcDiscoveryTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('cache.default', 'array');
        $app['config']->set('sso.issuer', 'https://id.example.test');
    }

    protected function setUp(): void
    {
        parent::setUp();
        Cache::clear();
    }

    public function test_it_rejects_a_discovery_document_from_a_different_issuer(): void
    {
        Http::fake([
            '*' => Http::response($this->document(['issuer' => 'https://attacker.example'])),
        ]);

        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('issuer does not match');

        $this->app->make(OidcDiscovery::class)->document();
    }

    public function test_it_rejects_malformed_or_failed_discovery_responses(): void
    {
        foreach ([
            Http::response('<html>gateway error</html>', 200),
            Http::response(['error' => 'unavailable'], 503),
        ] as $response) {
            Cache::clear();
            Http::fake(['*' => $response]);

            try {
                $this->app->make(OidcDiscovery::class)->document();
                $this->fail('Expected discovery validation to fail.');
            } catch (SsoException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function test_it_rejects_a_missing_required_endpoint(): void
    {
        Http::fake(['*' => Http::response($this->document(['authorization_endpoint' => null]))]);

        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('missing `authorization_endpoint`');

        $this->app->make(OidcDiscovery::class)->authorizationEndpoint();
    }

    public function test_it_rejects_failed_malformed_or_empty_jwks_responses(): void
    {
        foreach ([
            Http::response(['error' => 'unavailable'], 503),
            Http::response('<html>not JSON</html>', 200),
            Http::response(['keys' => []], 200),
        ] as $jwksResponse) {
            Cache::clear();
            Http::fake([
                'https://id.example.test/.well-known/openid-configuration' => Http::response($this->document()),
                'https://id.example.test/.well-known/jwks.json' => $jwksResponse,
            ]);

            try {
                $this->app->make(OidcDiscovery::class)->jwks();
                $this->fail('Expected JWKS validation to fail.');
            } catch (SsoException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function test_it_caches_a_valid_discovery_document_and_jwks(): void
    {
        Http::fake([
            'https://id.example.test/.well-known/openid-configuration' => Http::response($this->document()),
            'https://id.example.test/.well-known/jwks.json' => Http::response(['keys' => [['kty' => 'RSA']]]),
        ]);

        $discovery = $this->app->make(OidcDiscovery::class);
        $this->assertSame('https://id.example.test/sso/authorize', $discovery->authorizationEndpoint());
        $this->assertSame('https://id.example.test/sso/authorize', $discovery->authorizationEndpoint());
        $this->assertCount(1, $discovery->jwks()['keys']);
        $this->assertCount(1, $discovery->jwks()['keys']);
        Http::assertSentCount(2);
    }

    public function test_it_isolates_discovery_and_jwks_cache_by_issuer(): void
    {
        Http::fake(function ($request) {
            $issuer = str_contains($request->url(), 'id-b.example.test')
                ? 'https://id-b.example.test'
                : 'https://id.example.test';

            if (str_ends_with($request->url(), '/.well-known/openid-configuration')) {
                return Http::response([
                    'issuer' => $issuer,
                    'authorization_endpoint' => $issuer.'/sso/authorize',
                    'token_endpoint' => $issuer.'/api/sso/token',
                    'jwks_uri' => $issuer.'/.well-known/jwks.json',
                ]);
            }

            return Http::response(['keys' => [['kty' => 'RSA', 'kid' => $issuer]]]);
        });

        $discovery = $this->app->make(OidcDiscovery::class);
        $this->assertSame('https://id.example.test/sso/authorize', $discovery->authorizationEndpoint());
        $this->assertSame('https://id.example.test', $discovery->jwks()['keys'][0]['kid']);

        config()->set('sso.issuer', 'https://id-b.example.test');

        $this->assertSame('https://id-b.example.test/sso/authorize', $discovery->authorizationEndpoint());
        $this->assertSame('https://id-b.example.test', $discovery->jwks()['keys'][0]['kid']);
        Http::assertSentCount(4);
    }

    /** @param array<string, mixed> $overrides */
    private function document(array $overrides = []): array
    {
        return array_merge([
            'issuer' => 'https://id.example.test',
            'authorization_endpoint' => 'https://id.example.test/sso/authorize',
            'token_endpoint' => 'https://id.example.test/api/sso/token',
            'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
        ], $overrides);
    }
}
