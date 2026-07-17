<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Services\LogoutSessionRegistry;
use Dxs\Auth\SsoClientServiceProvider;
use Dxs\Auth\Tests\Support\JwtFactory;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

final class BackChannelLogoutTest extends TestCase
{
    private JwtFactory $jwt;

    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('session.driver', 'array');
        $app['config']->set('cache.default', 'array');
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.service_slug', 'consumer-a');
        $app['config']->set('sso.client_id', 'consumer-a-client');
    }

    protected function setUp(): void
    {
        parent::setUp();

        Cache::clear();
        $this->jwt = new JwtFactory;
        Http::fake([
            'https://id.example.test/.well-known/openid-configuration' => Http::response([
                'issuer' => 'https://id.example.test',
                'authorization_endpoint' => 'https://id.example.test/sso/authorize',
                'token_endpoint' => 'https://id.example.test/api/sso/token',
                'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
            ]),
            'https://id.example.test/.well-known/jwks.json' => Http::response($this->jwt->jwks()),
        ]);
    }

    public function test_a_valid_logout_token_revokes_the_registered_bearer(): void
    {
        $accessToken = $this->jwt->token(['sid' => 'lineage-1']);
        $registry = $this->app->make(LogoutSessionRegistry::class);
        $registry->register(['sid' => 'lineage-1', 'exp' => time() + 300], $accessToken, 'local-session-1');

        $response = $this->post('/auth/backchannel-logout', [
            'logout_token' => $this->logoutToken('lineage-1'),
        ]);

        $response->assertOk();
        $this->assertTrue($registry->tokenIsRevoked($accessToken));
    }

    public function test_logout_delivery_is_idempotent(): void
    {
        $logoutToken = $this->logoutToken('already-gone');

        $this->post('/auth/backchannel-logout', ['logout_token' => $logoutToken])->assertOk();
        $this->post('/auth/backchannel-logout', ['logout_token' => $logoutToken])->assertOk();
    }

    public function test_wrong_audience_nonce_and_missing_event_fail_closed(): void
    {
        $this->post('/auth/backchannel-logout', [
            'logout_token' => $this->logoutToken('lineage-1', ['aud' => 'consumer-b-client']),
        ])->assertBadRequest()->assertJsonPath('error', 'invalid_logout_token');

        $this->post('/auth/backchannel-logout', [
            'logout_token' => $this->logoutToken('lineage-1', ['nonce' => 'forbidden']),
        ])->assertBadRequest()->assertJsonPath('error', 'invalid_logout_token');

        $this->post('/auth/backchannel-logout', [
            'logout_token' => $this->logoutToken('lineage-1', ['events' => []]),
        ])->assertBadRequest()->assertJsonPath('error', 'invalid_logout_token');
    }

    /** @param array<string, mixed> $claims */
    private function logoutToken(string $sessionLineage, array $claims = []): string
    {
        return $this->jwt->token(array_merge([
            'aud' => 'consumer-a-client',
            'sid' => $sessionLineage,
            'jti' => 'logout-'.bin2hex(random_bytes(8)),
            'events' => ['http://schemas.openid.net/event/backchannel-logout' => new \stdClass],
        ], $claims));
    }
}
