<?php

declare(strict_types=1);

namespace Dxs\Auth\Tests;

use Dxs\Auth\Contracts\ProvisionsUsers;
use Dxs\Auth\Services\PermissionClient;
use Dxs\Auth\SsoClientServiceProvider;
use Dxs\Auth\Tests\Support\JwtFactory;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

/**
 * A downstream service's REAL resource surface, end to end through the package
 * primitives: platform-issued bearer → `sso.auth` (JWKS verification + JIT
 * provisioning) → `can:` abilities answered by the platform-resolved
 * permission list (Gate::before → PermissionClient).
 *
 * The simulated consumer app exposes the flows a service like kintai ships:
 * registering branches / brands / employees, fetching their details, listing
 * the org — each behind its own ability. Three personas hold different
 * platform permission sets and must see exactly their slice: admins register,
 * staff read, outsiders authenticate but touch nothing.
 */
final class DownstreamResourceAuthorizationTest extends TestCase
{
    private const ORG_ID = '019f6ece-2629-730a-ab0b-0f323d4e2e02';

    private const BRANCH_ID = '019f6ece-bbbb-7bbb-8bbb-000000000001';

    private const ADMIN_PERMISSIONS = [
        'orgs.view',
        'branches.view', 'branches.create',
        'brands.view', 'brands.create',
        'employees.view', 'employees.create',
    ];

    private const STAFF_PERMISSIONS = ['orgs.view', 'branches.view', 'brands.view', 'employees.view'];

    private JwtFactory $jwt;

    private string $adminToken;

    private string $staffToken;

    private string $outsiderToken;

    private string $branchToken;

    protected function getPackageProviders($app): array
    {
        return [SsoClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        // Production forces the REAL bearer path — no actingAs/dev bypasses.
        $app['env'] = 'production';
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('session.driver', 'array');
        $app['config']->set('cache.default', 'array');
        $app['config']->set('sso.issuer', 'https://id.example.test');
        $app['config']->set('sso.service_slug', 'consumer-a');
        $app['config']->set('sso.client_id', 'consumer-a-client');
        $app['config']->set('sso.client_secret', 'consumer-a-secret');
        $app['config']->set('sso.permissions_path', 'api/sso/me/permissions');
        $app['config']->set('sso.permissions_ttl', 300);
    }

    protected function setUp(): void
    {
        parent::setUp();

        Cache::clear();
        $this->jwt = new JwtFactory;
        $this->app->instance(ProvisionsUsers::class, new DownstreamUserDirectory);

        $this->adminToken = $this->jwt->token(['sub' => 'user-admin', 'organization_id' => self::ORG_ID]);
        $this->staffToken = $this->jwt->token(['sub' => 'user-staff', 'organization_id' => self::ORG_ID]);
        $this->outsiderToken = $this->jwt->token(['sub' => 'user-outsider', 'organization_id' => self::ORG_ID]);
        $this->branchToken = $this->jwt->token([
            'sub' => 'user-branch-manager',
            'organization_id' => self::ORG_ID,
            'branch_id' => self::BRANCH_ID,
        ]);

        $this->registerConsumerResourceRoutes();
        $this->fakePlatform();
    }

    // ---- Registration flows (đăng ký) -----------------------------------

    public function test_an_admin_registers_a_branch_a_brand_and_an_employee(): void
    {
        $this->asBearer($this->adminToken)
            ->postJson('/api/branches', ['name' => 'Shibuya'])
            ->assertCreated()
            ->assertJsonPath('branch.name', 'Shibuya')
            ->assertJsonPath('registered_by', 'user-admin');

        $this->asBearer($this->adminToken)
            ->postJson('/api/brands', ['name' => 'Gino Coffee'])
            ->assertCreated()
            ->assertJsonPath('brand.name', 'Gino Coffee');

        $this->asBearer($this->adminToken)
            ->postJson('/api/employees', ['name' => 'Taro Yamada'])
            ->assertCreated()
            ->assertJsonPath('employee.name', 'Taro Yamada');
    }

    public function test_staff_cannot_register_anything_but_the_same_requests_succeed_for_admins(): void
    {
        foreach (['/api/branches', '/api/brands', '/api/employees'] as $endpoint) {
            $this->asBearer($this->staffToken)
                ->postJson($endpoint, ['name' => 'nope'])
                ->assertForbidden();

            $this->asBearer($this->adminToken)
                ->postJson($endpoint, ['name' => 'yes'])
                ->assertCreated();
        }
    }

    // ---- Detail / listing flows (lấy detail, lấy org & branch) ----------

    public function test_staff_reads_the_org_branch_brand_and_employee_details(): void
    {
        $this->asBearer($this->staffToken)
            ->getJson('/api/org')
            ->assertOk()
            ->assertJsonPath('org.id', self::ORG_ID);

        $this->asBearer($this->staffToken)
            ->getJson('/api/branches/'.self::BRANCH_ID)
            ->assertOk()
            ->assertJsonPath('branch.id', self::BRANCH_ID)
            ->assertJsonPath('viewer', 'user-staff');

        $this->asBearer($this->staffToken)
            ->getJson('/api/brands/br-9')
            ->assertOk()
            ->assertJsonPath('brand.id', 'br-9');

        $this->asBearer($this->staffToken)
            ->getJson('/api/employees/emp-7')
            ->assertOk()
            ->assertJsonPath('employee.id', 'emp-7');
    }

    public function test_the_detail_response_is_bound_to_the_verified_token_identity_not_request_input(): void
    {
        // Whatever the client claims in the payload, identity comes from the
        // JWKS-verified token (`sso_subject`), never from user input.
        $this->asBearer($this->adminToken)
            ->postJson('/api/branches', ['name' => 'X', 'registered_by' => 'spoofed-user'])
            ->assertCreated()
            ->assertJsonPath('registered_by', 'user-admin');
    }

    // ---- Permission correctness (lấy đúng quyền) -------------------------

    public function test_an_authenticated_user_with_no_permissions_reaches_identity_but_no_resources(): void
    {
        // /api/me needs authentication only — outsiders still resolve.
        $this->asBearer($this->outsiderToken)
            ->getJson('/api/me')
            ->assertOk()
            ->assertJsonPath('subject', 'user-outsider');

        foreach (['/api/org', '/api/branches/'.self::BRANCH_ID, '/api/brands/br-1', '/api/employees/emp-1'] as $endpoint) {
            $this->asBearer($this->outsiderToken)->getJson($endpoint)->assertForbidden();
        }
        foreach (['/api/branches', '/api/brands', '/api/employees'] as $endpoint) {
            $this->asBearer($this->outsiderToken)->postJson($endpoint, [])->assertForbidden();
        }
    }

    public function test_no_token_is_401_with_a_challenge_wrong_permission_is_403(): void
    {
        $this->getJson('/api/org')
            ->assertUnauthorized()
            ->assertHeader('WWW-Authenticate', 'Bearer realm="sso"');

        $this->asBearer($this->staffToken)
            ->postJson('/api/branches', [])
            ->assertForbidden();
    }

    public function test_the_permission_list_is_fetched_once_per_bearer_across_many_resource_hits(): void
    {
        $this->asBearer($this->staffToken)->getJson('/api/org')->assertOk();
        $this->asBearer($this->staffToken)->getJson('/api/branches/'.self::BRANCH_ID)->assertOk();
        $this->asBearer($this->staffToken)->getJson('/api/employees/emp-1')->assertOk();

        $permissionCalls = collect(Http::recorded())
            ->filter(fn (array $pair): bool => str_contains($pair[0]->url(), 'api/sso/me/permissions'))
            ->count();

        $this->assertSame(1, $permissionCalls);
    }

    public function test_branch_scoped_users_fetch_branch_scoped_permissions(): void
    {
        $this->asBearer($this->branchToken)->getJson('/api/org')->assertOk();

        Http::assertSent(fn (ClientRequest $request): bool => str_contains($request->url(), 'api/sso/me/permissions')
            && str_contains($request->url(), 'organization_id='.self::ORG_ID)
            && str_contains($request->url(), 'branch_id='.self::BRANCH_ID));
    }

    public function test_the_platform_roles_payload_reaches_the_downstream_service_intact(): void
    {
        $result = $this->app->make(PermissionClient::class)
            ->fetch($this->staffToken, self::ORG_ID);

        $this->assertSame(self::STAFF_PERMISSIONS, $result['permissions']);
        $this->assertSame([['role' => 'staff', 'display_name' => 'Staff', 'level' => 10]], $result['roles']);
    }

    // ---- wiring ----------------------------------------------------------

    private function registerConsumerResourceRoutes(): void
    {
        $router = $this->app['router'];

        $router->middleware(['sso.auth'])->group(function () use ($router): void {
            $router->get('/api/me', fn () => response()->json([
                'subject' => request()->attributes->get('sso_subject'),
            ]));

            $router->get('/api/org', fn () => response()->json([
                'org' => ['id' => request()->attributes->get('sso_claims')['organization_id'] ?? null],
            ]))->middleware('can:orgs.view');

            $router->get('/api/branches/{id}', fn (string $id) => response()->json([
                'branch' => ['id' => $id, 'name' => 'Branch '.$id],
                'viewer' => request()->attributes->get('sso_subject'),
            ]))->middleware('can:branches.view');
            $router->post('/api/branches', fn () => response()->json([
                'branch' => ['name' => request()->input('name')],
                'registered_by' => request()->attributes->get('sso_subject'),
            ], 201))->middleware('can:branches.create');

            $router->get('/api/brands/{id}', fn (string $id) => response()->json([
                'brand' => ['id' => $id],
            ]))->middleware('can:brands.view');
            $router->post('/api/brands', fn () => response()->json([
                'brand' => ['name' => request()->input('name')],
            ], 201))->middleware('can:brands.create');

            $router->get('/api/employees/{id}', fn (string $id) => response()->json([
                'employee' => ['id' => $id],
            ]))->middleware('can:employees.view');
            $router->post('/api/employees', fn () => response()->json([
                'employee' => ['name' => request()->input('name')],
            ], 201))->middleware('can:employees.create');
        });
    }

    private function fakePlatform(): void
    {
        $discovery = [
            'issuer' => 'https://id.example.test',
            'authorization_endpoint' => 'https://id.example.test/sso/authorize',
            'token_endpoint' => 'https://id.example.test/api/sso/token',
            'jwks_uri' => 'https://id.example.test/.well-known/jwks.json',
        ];

        Http::fake(function (ClientRequest $request) use ($discovery) {
            if (str_contains($request->url(), 'openid-configuration')) {
                return Http::response($discovery);
            }
            if (str_contains($request->url(), 'jwks.json')) {
                return Http::response($this->jwt->jwks());
            }
            if (str_contains($request->url(), 'api/sso/me/permissions')) {
                return Http::response($this->permissionsForBearer((string) $request->header('Authorization')[0]));
            }

            return Http::response(['error' => 'unexpected request '.$request->url()], 500);
        });
    }

    /** @return array{permissions: list<string>, roles: list<array<string, mixed>>} */
    private function permissionsForBearer(string $authorization): array
    {
        $token = str_replace('Bearer ', '', $authorization);

        return match (true) {
            $token === $this->adminToken => [
                'permissions' => self::ADMIN_PERMISSIONS,
                'roles' => [['role' => 'admin', 'display_name' => 'Administrator', 'level' => 100]],
            ],
            $token === $this->staffToken, $token === $this->branchToken => [
                'permissions' => self::STAFF_PERMISSIONS,
                'roles' => [['role' => 'staff', 'display_name' => 'Staff', 'level' => 10]],
            ],
            default => ['permissions' => [], 'roles' => []],
        };
    }

    private function asBearer(string $token): static
    {
        return $this->withHeader('Authorization', 'Bearer '.$token);
    }
}

/**
 * JIT user directory keyed on the platform subject — the downstream mirror of
 * app/Sso/UserProvisioner in a real consumer, carrying the context Gate::before
 * needs (token, organization, optional branch).
 */
final class DownstreamUserDirectory implements ProvisionsUsers
{
    /** @var array<string, GenericUser> */
    private array $users = [];

    public function provision(array $claims, array $tokens): Authenticatable
    {
        $subject = (string) $claims['sub'];

        return $this->users[$subject] = new GenericUser(array_filter([
            'id' => $subject,
            'console_access_token' => $tokens['access_token'] ?? null,
            'console_organization_id' => $claims['organization_id'] ?? null,
            'console_branch_id' => $claims['branch_id'] ?? null,
        ], fn ($value) => $value !== null));
    }

    public function resolveBySubject(string $subject): ?Authenticatable
    {
        return $this->users[$subject] ?? null;
    }
}
