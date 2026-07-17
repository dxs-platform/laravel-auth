<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Services\TokenRefresher;
use Dxs\Auth\SsoClientServiceProvider;
use Dxs\Auth\Support\SsoCache;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Auth\User as AuthUser;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase;

/**
 * Short-lived access tokens outlived by the session must be refreshed in place,
 * or the user silently loses all access at the access-token TTL. The refresher
 * runs at most once per request, only near expiry, and fails soft.
 */
final class TokenRefreshTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('cache.default', 'array');
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.service_slug', 'consumer-a');
        $app['config']->set('sso.client_id', 'consumer-a-client');
        $app['config']->set('sso.client_secret', 'consumer-a-secret');
    }

    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('users', function (Blueprint $table): void {
            $table->increments('id');
            $table->string('console_access_token')->nullable();
            $table->string('console_refresh_token')->nullable();
            $table->timestamp('console_token_expires_at')->nullable();
        });
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();
        parent::tearDown();
    }

    public function test_a_token_near_expiry_is_refreshed_in_place(): void
    {
        $this->fakeTokenEndpoint(['access_token' => 'fresh-at', 'refresh_token' => 'fresh-rt', 'expires_in' => 900]);
        $user = $this->makeUser('old-at', 'old-rt', now()->addSeconds(30));

        $this->refresher()->ensureFresh($user);

        $user->refresh();
        $this->assertSame('fresh-at', $user->console_access_token);
        $this->assertSame('fresh-rt', $user->console_refresh_token);
        $this->assertEqualsWithDelta(now()->addSeconds(900)->timestamp, Carbon::parse($user->console_token_expires_at)->timestamp, 5);
    }

    public function test_an_already_expired_token_is_refreshed(): void
    {
        $this->fakeTokenEndpoint(['access_token' => 'fresh-at', 'expires_in' => 900]);
        $user = $this->makeUser('old-at', 'old-rt', now()->subMinutes(5));

        $this->refresher()->ensureFresh($user);

        $this->assertSame('fresh-at', $user->refresh()->console_access_token);
    }

    public function test_a_token_comfortably_valid_is_left_untouched(): void
    {
        Http::fake();
        $user = $this->makeUser('good-at', 'good-rt', now()->addMinutes(10));

        $this->refresher()->ensureFresh($user);

        $this->assertSame('good-at', $user->refresh()->console_access_token);
        Http::assertNothingSent();
    }

    public function test_the_refresh_happens_at_most_once_per_request(): void
    {
        $this->fakeTokenEndpoint(['access_token' => 'fresh-at', 'expires_in' => 900]);
        $user = $this->makeUser('old-at', 'old-rt', now()->subMinute());

        $refresher = $this->refresher();
        $refresher->ensureFresh($user);
        $refresher->ensureFresh($user);
        $refresher->ensureFresh($user);

        $this->assertSame(1, collect(Http::recorded())->filter(fn (array $p): bool => str_contains($p[0]->url(), 'token'))->count());
    }

    public function test_a_missing_refresh_token_is_a_no_op(): void
    {
        Http::fake();
        $user = $this->makeUser('old-at', null, now()->subMinute());

        $this->refresher()->ensureFresh($user);

        Http::assertNothingSent();
    }

    public function test_a_failed_refresh_is_swallowed_and_leaves_the_token_in_place(): void
    {
        $this->fakeTokenEndpoint(['error' => 'invalid_grant'], 400);
        $user = $this->makeUser('old-at', 'stale-rt', now()->subMinute());

        // No exception bubbles up (that would break the page/authorization check).
        $this->refresher()->ensureFresh($user);

        $this->assertSame('old-at', $user->refresh()->console_access_token);
    }

    public function test_a_concurrent_holder_of_the_refresh_lock_blocks_a_double_refresh(): void
    {
        $this->fakeTokenEndpoint(['access_token' => 'fresh-at', 'expires_in' => 900]);
        $user = $this->makeUser('old-at', 'shared-rt', now()->subMinute());

        // Simulate another request already refreshing: it holds the lock.
        $held = SsoCache::store()
            ->lock('sso:refresh-lock:'.hash('sha256', 'shared-rt'), 10);
        $this->assertTrue($held->get());

        // A fresh refresher instance (different "request") cannot take the lock.
        $this->app->forgetInstance(TokenRefresher::class);
        $this->refresher()->ensureFresh($user->refresh());

        $this->assertSame('old-at', $user->refresh()->console_access_token);
        Http::assertNothingSent();

        $held->release();
    }

    public function test_refresh_can_be_disabled(): void
    {
        config()->set('sso.refresh.enabled', false);
        Http::fake();
        $user = $this->makeUser('old-at', 'old-rt', now()->subMinute());

        $this->refresher()->ensureFresh($user);

        Http::assertNothingSent();
    }

    private function refresher(): TokenRefresher
    {
        return $this->app->make(TokenRefresher::class);
    }

    private function makeUser(string $access, ?string $refresh, Carbon $expiresAt): RefreshableUser
    {
        return RefreshableUser::query()->create([
            'console_access_token' => $access,
            'console_refresh_token' => $refresh,
            'console_token_expires_at' => $expiresAt,
        ]);
    }

    /** @param array<string, mixed> $body */
    private function fakeTokenEndpoint(array $body, int $status = 200): void
    {
        Http::fake([
            'https://id.example.test/.well-known/openid-configuration' => Http::response([
                'issuer' => 'https://id.example.test',
                'authorization_endpoint' => 'https://id.example.test/sso/authorize',
                'token_endpoint' => 'https://id.example.test/api/sso/token',
                'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
            ]),
            'https://id.example.test/api/sso/token' => Http::response($body, $status),
        ]);
    }
}

final class RefreshableUser extends AuthUser
{
    protected $table = 'users';

    protected $guarded = [];

    public $timestamps = false;

    protected $casts = ['console_token_expires_at' => 'datetime'];
}
