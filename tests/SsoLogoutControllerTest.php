<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\SsoClientServiceProvider;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

/**
 * POST /auth/logout — the only session-ending surface a consumer exposes. It
 * must clear the local session, expire the bearer cookie, and hand the browser
 * to the IdP's end-session endpoint when one is advertised (RP-initiated
 * logout), falling back to the local after-logout destination otherwise.
 */
final class SsoLogoutControllerTest extends TestCase
{
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
        $app['config']->set('sso.after_logout', '/goodbye');
    }

    protected function setUp(): void
    {
        parent::setUp();

        Cache::clear();
    }

    public function test_logout_invalidates_the_session_and_expires_the_bearer_cookie(): void
    {
        $this->fakeDiscovery();

        $response = $this->withSession(['pre-logout-marker' => 'still-here'])
            ->post('/auth/logout');

        $this->assertFalse(session()->has('pre-logout-marker'), 'The session must be invalidated on logout.');

        $cookie = collect($response->headers->getCookies())
            ->first(fn ($candidate) => $candidate->getName() === 'token');

        $this->assertNotNull($cookie, 'The bearer cookie must be forgotten on logout.');
        $this->assertLessThan(time(), $cookie->getExpiresTime());
    }

    public function test_logout_redirects_to_the_advertised_end_session_endpoint(): void
    {
        $this->fakeDiscovery(endSession: 'https://id.example.test/sso/logout');

        $response = $this->post('/auth/logout');

        $location = (string) $response->headers->get('Location');

        $this->assertStringStartsWith('https://id.example.test/sso/logout?', $location);
        $this->assertStringContainsString('post_logout_redirect_uri=', $location);
    }

    public function test_inertia_logout_uses_a_top_level_external_location_response(): void
    {
        $this->fakeDiscovery(endSession: 'https://id.example.test/sso/logout');

        $response = $this->withHeader('X-Inertia', 'true')
            ->withSession(['pre-logout-marker' => 'must-be-cleared'])
            ->post('/auth/logout');

        $response->assertConflict()
            ->assertHeader('X-Inertia-Location');
        $this->assertStringStartsWith(
            'https://id.example.test/sso/logout?',
            (string) $response->headers->get('X-Inertia-Location'),
        );
        $this->assertFalse(session()->has('pre-logout-marker'));
    }

    public function test_logout_falls_back_to_the_local_destination_without_an_end_session_endpoint(): void
    {
        $this->fakeDiscovery();

        $this->post('/auth/logout')->assertRedirect('/goodbye');
    }

    public function test_logout_still_completes_locally_when_discovery_is_unavailable(): void
    {
        Http::fake([
            'https://id.example.test/.well-known/openid-configuration' => Http::response(['error' => 'unavailable'], 503),
        ]);

        $response = $this->withSession(['pre-logout-marker' => 'must-be-cleared'])
            ->withCookie('token', 'bearer-must-be-forgotten')
            ->post('/auth/logout');

        $response->assertRedirect('/goodbye')
            ->assertSessionHas('sso.warning');
        $this->assertFalse(session()->has('pre-logout-marker'));

        $cookie = collect($response->headers->getCookies())
            ->first(fn ($candidate) => $candidate->getName() === 'token');

        $this->assertNotNull($cookie);
        $this->assertLessThan(time(), $cookie->getExpiresTime());
    }

    public function test_logout_regenerates_the_csrf_token(): void
    {
        $this->fakeDiscovery();

        $this->withSession(['_token' => 'pre-logout-token'])->post('/auth/logout');

        $this->assertNotSame('pre-logout-token', session()->token());
    }

    public function test_logout_is_post_only(): void
    {
        $this->fakeDiscovery();

        $this->get('/auth/logout')->assertMethodNotAllowed();
    }

    private function fakeDiscovery(?string $endSession = null): void
    {
        $document = [
            'issuer' => 'https://id.example.test',
            'authorization_endpoint' => 'https://id.example.test/sso/authorize',
            'token_endpoint' => 'https://id.example.test/api/sso/token',
            'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
        ];
        if ($endSession !== null) {
            $document['end_session_endpoint'] = $endSession;
        }

        Http::fake([
            'https://id.example.test/.well-known/openid-configuration' => Http::response($document),
        ]);
    }
}
