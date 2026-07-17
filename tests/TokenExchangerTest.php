<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\Services\TokenExchanger;
use Dxs\Auth\SsoClientServiceProvider;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Direct contract coverage for both token-endpoint grants: the authorization
 * code exchange (previously only exercised through the callback) and the
 * refresh_token grant (previously untested). Both are confidential-client
 * calls that must carry the service_slug + client credentials and fail closed
 * on transport errors or malformed bodies.
 */
final class TokenExchangerTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('cache.default', 'array');
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.service_slug', 'consumer-a');
        $app['config']->set('sso.client_id', 'consumer-a-client');
        $app['config']->set('sso.client_secret', 'consumer-a-secret');
        $app['config']->set('sso.redirect_uri', 'https://consumer-a.example.test/auth/callback');
    }

    protected function setUp(): void
    {
        parent::setUp();

        Cache::clear();
    }

    public function test_the_code_grant_is_a_confidential_form_post_with_the_pkce_verifier(): void
    {
        $this->fakeTokenEndpoint(['access_token' => 'at-1', 'expires_in' => 900]);

        $tokens = $this->exchanger()->exchangeCode('the-code', 'the-verifier');

        $this->assertSame('at-1', $tokens['access_token']);
        Http::assertSent(fn (Request $request): bool => $request->url() === 'https://id.example.test/api/sso/token'
            && $request->isForm()
            && $request['grant_type'] === 'authorization_code'
            && $request['code'] === 'the-code'
            && $request['code_verifier'] === 'the-verifier'
            && $request['redirect_uri'] === 'https://consumer-a.example.test/auth/callback'
            && $request['service_slug'] === 'consumer-a'
            && $request['client_id'] === 'consumer-a-client'
            && $request['client_secret'] === 'consumer-a-secret');
    }

    public function test_the_refresh_grant_carries_the_refresh_token_and_the_same_client_credentials(): void
    {
        $this->fakeTokenEndpoint(['access_token' => 'at-2', 'refresh_token' => 'rt-2', 'expires_in' => 900]);

        $tokens = $this->exchanger()->refresh('rt-1');

        $this->assertSame('at-2', $tokens['access_token']);
        $this->assertSame('rt-2', $tokens['refresh_token']);
        Http::assertSent(fn (Request $request): bool => $request->url() === 'https://id.example.test/api/sso/token'
            && $request['grant_type'] === 'refresh_token'
            && $request['refresh_token'] === 'rt-1'
            && $request['service_slug'] === 'consumer-a'
            && $request['client_id'] === 'consumer-a-client'
            && $request['client_secret'] === 'consumer-a-secret'
            && ! isset($request['redirect_uri']));
    }

    public function test_a_non_success_status_fails_closed_with_the_status_in_the_message(): void
    {
        $this->fakeTokenEndpoint(['error' => 'invalid_grant'], status: 400);

        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('SSO token exchange failed (400)');

        $this->exchanger()->exchangeCode('bad-code', 'verifier');
    }

    #[DataProvider('malformedBodies')]
    public function test_a_malformed_token_body_fails_closed(mixed $body): void
    {
        Http::fake([
            'https://id.example.test/.well-known/openid-configuration' => Http::response($this->discovery()),
            'https://id.example.test/api/sso/token' => Http::response($body),
        ]);

        $this->expectException(SsoException::class);
        $this->expectExceptionMessage('no access_token');

        $this->exchanger()->refresh('rt-1');
    }

    /** @return iterable<string, array{mixed}> */
    public static function malformedBodies(): iterable
    {
        yield 'missing access_token' => [['token_type' => 'Bearer']];
        yield 'empty access_token' => [['access_token' => '']];
        yield 'non-string access_token' => [['access_token' => ['nested' => 'array']]];
        yield 'non-json body' => ['plain text'];
    }

    private function exchanger(): TokenExchanger
    {
        return $this->app->make(TokenExchanger::class);
    }

    /** @return array<string, string> */
    private function discovery(): array
    {
        return [
            'issuer' => 'https://id.example.test',
            'authorization_endpoint' => 'https://id.example.test/sso/authorize',
            'token_endpoint' => 'https://id.example.test/api/sso/token',
            'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
        ];
    }

    /** @param array<string, mixed> $body */
    private function fakeTokenEndpoint(array $body, int $status = 200): void
    {
        Http::fake([
            'https://id.example.test/.well-known/openid-configuration' => Http::response($this->discovery()),
            'https://id.example.test/api/sso/token' => Http::response($body, $status),
        ]);
    }
}
