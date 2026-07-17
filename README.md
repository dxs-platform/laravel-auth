# dxs/laravel-auth

OAuth2/OIDC **downstream SSO client** for GoDX platform services — Authorization Code + PKCE
(BFF cookie pattern), JWKS-verified bearer resource auth, and platform-authoritative
permission checks. Drop-in for **any** Laravel service that authenticates against the GoDX ID
platform (`id.*` / `platform`).

Authorization decisions stay on the platform: the package fetches the user's resolved
permission list and answers `Gate` from it. The service only declares its permission catalog
(pushed up) and provisions its own user records.

## Install

```bash
composer require dxs/laravel-auth
```

The service provider auto-discovers. Publish config if you want to tweak it:

```bash
php artisan vendor:publish --tag=sso-config
```

## Configure (env only)

```dotenv
SSO_ISSUER=https://platform.godx.jp        # IdP origin; everything else is discovered
SSO_SERVICE_SLUG=my-service                 # token `aud` — this ServiceInstance
SSO_CLIENT_ID=ci_xxx
SSO_CLIENT_SECRET=sk_xxx
SSO_ORGANIZATION_CONTEXT_ID=00000000-0000-4000-8000-000000000000 # fixed only for single-tenant services
SSO_REDIRECT_URI=https://my-service.example/auth/callback
# optional: SSO_SCOPES, SSO_ROUTES_PREFIX, SSO_TOKEN_COOKIE, SSO_AFTER_LOGIN, ...
```

For a multi-tenant downstream, the platform launcher supplies
`organization_context_id` on the downstream URL. The package validates, stores,
and relays that context to the IdP authorization endpoint.

## Wire the one app-specific touch-point

The package never writes your `User` model. Bind the `ProvisionsUsers` contract to your own
implementation (map verified token claims → your user row):

```php
// AppServiceProvider::register()
use Dxs\Auth\Contracts\ProvisionsUsers;

$this->app->singleton(ProvisionsUsers::class, \App\Sso\UserProvisioner::class);
```

That is the **entire** integration. `GET /auth/redirect`, `GET /auth/callback`,
`POST /auth/logout`, the `sso.auth` middleware, and the `Gate::before` permission check are all
provided.

## What you get

| Piece | Purpose |
|---|---|
| `GET {prefix}/redirect` | Start Authorization Code + PKCE (S256) |
| `GET {prefix}/callback`  | Verify state/nonce, exchange code, provision user, set `token` cookie |
| `POST {prefix}/logout`   | Clear the session cookie |
| `sso.auth` middleware    | Validate a platform-issued bearer (JWKS/`aud`/`exp`) and resolve the local user |
| `Gate::before`           | Grant an ability iff it is in the platform-resolved permission list |
| `dxs-auth:register-permissions` | Push this service's declared permission catalog to the platform |

## Independence

The package has **zero** consumer coupling — the only app-facing symbol is the `ProvisionsUsers`
interface. `composer test` boots the provider in a bare Laravel app (via Testbench) and asserts
routes/middleware/services register with config alone. See `tests/IndependenceTest.php`.

## License

Proprietary — © GoDX / DXS platform.
