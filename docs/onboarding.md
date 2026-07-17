# Onboarding a downstream Laravel app onto platform SSO

This guide walks a fresh Laravel app through a complete `dxs/laravel-auth`
integration against the GoDX platform IdP — from registering the service to a
working browser login with JIT-provisioned users. Every step and every gotcha
below was hit for real while onboarding a consumer (`gino-cloud` at
`https://ql.test`) against a local platform at `https://platform.test`.

Time budget: ~30 minutes when nothing surprises you.

## Prerequisites

- A running platform (locally: Herd/Valet at `https://platform.test`, seeded).
- A Laravel 11+ app served over **HTTPS** (`herd secure` — redirect URIs are
  exact-match, and the IdP will not downgrade to `http`).
- Composer access to this package:

```jsonc
// composer.json
"repositories": [
    { "type": "vcs", "url": "https://github.com/dxs-platform/laravel-auth.git" }
]
```

```bash
composer require "dxs/laravel-auth:^0.4.0"
```

v0.4.0 is the minimum version that works against the current platform IdP —
older versions reject its `organization_id` token claim and drop ID-token
profile claims (issues #4, #5).

## Step 1 — Register the service + instance on the platform

Locally, use the **dev-admin API** (`APP_ENV=local` only; key from
`config/dev-admin.php`, env `DXS_DEV_ADMIN_API_KEY`). There is no artisan
command or `gxa` command that mints a service instance today.

```bash
BASE=https://platform.test
KEY=<dev-admin key>

# 1a. The catalog Service
curl --fail-with-body -X POST "$BASE/api/dev/services" \
  -H "X-Admin-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{
    "slug": "my-service",
    "name": "My Service",
    "default_base_url": "https://my-app.test",
    "default_redirect_uris": ["https://my-app.test/auth/callback"]
  }'

# 1b. The ServiceInstance — this is the OAuth client
curl --fail-with-body -X POST "$BASE/api/dev/services/my-service/instances" \
  -H "X-Admin-Key: $KEY" -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -d '{
    "name": "My Service (Local)",
    "slug": "my-service-local",
    "environment": "local",
    "deployment_type": "cloud",
    "organization_id": "<internal Organization id — see gotcha below>",
    "base_url": "https://my-app.test",
    "allowed_redirect_uris": ["https://my-app.test/auth/callback"]
  }'
```

The `201` response contains `client_id` (`si_…`) and `client_secret` (`sk_…`).
**The secret is shown exactly once** — store it immediately.

### Gotchas at this step

- **Slugs are `[a-z0-9-]` only.** A reverse-domain name like
  `jp.example.my-service` is rejected by the validation regex (dots). Keep the
  dotted form as the display `name`; hyphenate the slug.
- **`organization_id` here is the platform-internal `organizations.id`**, not
  the console organization id. If you pass an unknown id you get a validation
  error; look the org up first (`gxa org list`, tinker, or the dev-admin API).
- **The instance is born `provision_status=pending` — logins will fail with
  `error=access_denied`** at the authorize step until it is `ready`
  (`ServiceLaunchPolicy` requires it). Locally, flip it:

  ```php
  ServiceInstance::where('slug', 'my-service-local')
      ->first()->forceFill(['provision_status' => 'ready'])->save();
  ```

- **Every logging-in user needs a `ServiceUserAccess` row** (org + service +
  user) — no grant, no login (`access_denied` again). Grant at least your test
  user. The user must also be **active, email-verified and a member of the
  organization**; seeded local accounts differ here (one of ours had password
  `password`, was unverified and not an org member — pick a user that passes
  all three or fix the record).

## Step 2 — Configure the consumer app

```dotenv
# .env
SSO_ISSUER=https://platform.test
SSO_SERVICE_SLUG=my-service-local          # the INSTANCE slug = token audience
SSO_CLIENT_ID=si_...
SSO_CLIENT_SECRET=sk_...
SSO_REDIRECT_URI=https://my-app.test/auth/callback
SSO_SCOPES="openid profile email offline_access"

# TWO different UUIDs for the SAME organization — do not mix them up:
SSO_ORGANIZATION_CONTEXT_ID=<console organization id>   # sent to /sso/authorize
SSO_ORGANIZATION_ID=<internal organization id>          # validated against the token's organization_id claim

SSO_AFTER_LOGIN=/dashboard
SSO_AFTER_LOGOUT=/
# optional: where failed logins land (falls back to SSO_AFTER_LOGOUT, then /)
# SSO_FAILURE_REDIRECT=/login
```

Why two organization values: the authorize request carries the **console**
organization id (`organization_context_id`), but the platform currently stamps
the instance's **internal** organization id into the access token as
`organization_id`. The package validates whichever claim arrives (legacy
`organization_context_id` takes precedence; `organization_id` requires
`SSO_ORGANIZATION_ID` to be set).

The package auto-registers `GET /auth/redirect`, `GET /auth/callback`,
`POST /auth/logout`, `POST /auth/backchannel-logout` (prefix configurable via
`SSO_ROUTES_PREFIX`).

## Step 3 — users table + provisioner

Add the identity columns (keep them **out of `$fillable`**; the SSO path
writes them via `forceFill` after JWKS verification):

```php
Schema::table('users', function (Blueprint $table): void {
    $table->string('password')->nullable()->change();   // SSO-only users have none
    $table->string('console_user_id', 64)->nullable()->unique();  // token `sub`
    $table->uuid('console_organization_id')->nullable();
    $table->text('console_access_token')->nullable();
    $table->text('console_refresh_token')->nullable();
    $table->timestamp('console_token_expires_at')->nullable();
});
```

Implement `Dxs\Auth\Contracts\ProvisionsUsers` (JIT upsert keyed on
`sub → console_user_id`) and bind it:

```php
// AppServiceProvider::register()
$this->app->singleton(ProvisionsUsers::class, UserProvisioner::class);
```

`$claims` includes `sub`, `organization_id`, and — merged from the verified ID
token — `name` and `email` (RFC 9068 access tokens carry authorization claims
only, so the profile fields ride in the ID token; the package ≥0.4.0 surfaces
them for you).

Point your app's login entry at the package:

```php
Route::redirect('/login', '/auth/redirect')->name('login');
```

Laravel's `auth` middleware then bounces guests → `/login` → the IdP, and the
callback logs them in on the standard `web` session guard.

## Step 4 — Verify end-to-end

1. `GET https://my-app.test/auth/redirect` → 302 to
   `https://platform.test/sso/authorize?...&code_challenge_method=S256`.
2. Log in at the platform (locally the flow continues automatically via the
   stored intended URL).
3. Authorize → 302 back to `/auth/callback?code=…&state=…`.
4. Callback → 302 to `SSO_AFTER_LOGIN`; a `users` row exists with
   `console_user_id`, `name`, `email` filled.
5. Deny-path: hitting `/auth/callback?error=access_denied&state=<valid>` must
   redirect to your failure route with `sso.error` flashed — not a 500.

### Debugging map (symptom → cause)

| Symptom | Cause |
| --- | --- |
| authorize → `?error=access_denied` | `ServiceLaunchPolicy`: instance not `ready`, missing `ServiceUserAccess`, user unverified / not an org member, or org/service inactive |
| callback 500 `state mismatch` | expired/double-used transaction (back button, bookmark) — benign; ≥0.4.0 turns this into a redirect + flash |
| callback: `token organization … does not match` | wrong `SSO_ORGANIZATION_ID` (you probably used the console org id — it needs the internal one) |
| provisioned user has empty name/email | package <0.4.0 (ID-token claims were dropped) |
| `redirect_uri` rejected | exact-match: scheme, host, path, trailing slash must all match the registered URI (`https` vs `http` counts) |

## Step 5 — Sync the authorization catalog

Declare permissions/roles in `config/authz.php` (see the package README), then:

```bash
php artisan dxs:sync-authz --dry-run   # inspect the payload
```

Known platform-side caveats for the real sync (as of 2026-07):

- `SSO_SERVICE_ID` must be the **Service UUID** (route-model binding on
  `api/admin/catalog/{service}` binds by id, not slug).
- The `api/admin/*` surface authenticates the **admin-web BFF session**, not a
  bearer token — so `dxs:sync-authz` with `SSO_ADMIN_TOKEN` may 401 against
  current platforms. Locally, the dev-admin mirror accepts the same manifest
  by **slug** with the admin key:

  ```bash
  php artisan dxs:sync-authz --dry-run | tail -n +2 > authz.json
  curl -X PUT "$BASE/api/dev/services/my-service/authz" \
    -H "X-Admin-Key: $KEY" -H 'Content-Type: application/json' \
    --data-binary @authz.json
  ```

- Verify with the admin CLI: `gxa service permissions list <service-uuid>` /
  `gxa service roles list <service-uuid>` (requires a platform with the CLI
  route-binding fix; before it, these always printed `[]`).

## Reference: platform endpoints involved

| Purpose | Endpoint |
| --- | --- |
| OIDC discovery | `GET /.well-known/openid-configuration` |
| JWKS | `GET /.well-known/jwks.json` |
| Authorize | `GET /sso/authorize` (extras: `service_slug`, `organization_context_id`) |
| Token | `POST /api/sso/token` |
| End session | `GET|POST /sso/logout` |
| Dev-admin service registration | `POST /api/dev/services`, `POST /api/dev/services/{slug}/instances` |
| Dev-admin authz manifest | `PUT /api/dev/services/{slug}/authz` |
