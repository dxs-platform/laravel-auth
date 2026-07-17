<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | GoDX platform IdP
    |--------------------------------------------------------------------------
    | The issuer is the platform IdP origin. Every other endpoint is resolved
    | from `{issuer}/.well-known/openid-configuration` at runtime (cached), so
    | only the issuer + this instance's own credentials need configuring.
    */
    'issuer' => env('SSO_ISSUER', 'https://platform.test'),

    // This downstream ServiceInstance, minted by the platform on provisioning.
    'service_slug' => env('SSO_SERVICE_SLUG', ''),   // token `aud`
    'client_id' => env('SSO_CLIENT_ID', ''),
    'client_secret' => env('SSO_CLIENT_SECRET', ''),

    // Fixed context for a single-tenant downstream. Multi-tenant downstreams
    // receive this UUID on the platform launch URL and relay it server-side.
    'organization_context_id' => env('SSO_ORGANIZATION_CONTEXT_ID', ''),

    /*
     * Internal platform Organization id expected in the access token's
     * `organization_id` claim. The current platform IdP stamps the service
     * instance's organization id into service tokens instead of the console
     * `organization_context_id`; set this to accept those tokens.
     */
    'organization_id' => env('SSO_ORGANIZATION_ID', ''),

    /*
     * Where a failed SSO flow (denied consent, expired state, unreachable IdP)
     * redirects the user, with the error message flashed under `sso.error`.
     * Falls back to `after_logout`, then `/`.
     */
    'failure_redirect' => env('SSO_FAILURE_REDIRECT', ''),

    /*
     * Lifetime (seconds) of a pending authorization transaction — the window
     * between /auth/redirect and /auth/callback. Expired transactions are
     * rejected at the callback and pruned from the session.
     */
    'transaction_ttl' => (int) env('SSO_TRANSACTION_TTL', 600),

    /*
     * Where and how the package caches (discovery, JWKS, permissions, the
     * back-channel logout registry). `store` names a store from
     * config/cache.php — point it at a SHARED store (redis) in multi-node
     * deployments so logout revocation and permission invalidation reach
     * every node; null uses the app default. `jwks_ttl` (seconds) lets JWKS
     * rotate faster than the discovery document; 0 falls back to
     * `discovery_ttl`.
     */
    'cache' => [
        'store' => env('SSO_CACHE_STORE'),
        'prefix' => env('SSO_CACHE_PREFIX', 'sso'),
        'jwks_ttl' => (int) env('SSO_JWKS_TTL', 0),
    ],

    /*
     * Opt-in scheduled pushes of config/authz.php to the platform.
     * `schedule` accepts a scheduler preset (`daily`, `hourly`, …) or a cron
     * expression. The scheduled run uses --if-changed, so unchanged catalogs
     * cost nothing.
     */
    'sync' => [
        'authz' => [
            'auto' => (bool) env('SSO_SYNC_AUTHZ_AUTO', false),
            'schedule' => env('SSO_SYNC_AUTHZ_SCHEDULE', 'daily'),
        ],
    ],

    // Must exactly match one of the instance's allowed_redirect_uris on the platform.
    'redirect_uri' => env('SSO_REDIRECT_URI', env('APP_URL').'/auth/callback'),

    // Space-delimited scopes requested at authorize.
    'scopes' => env('SSO_SCOPES', 'openid profile email offline_access'),

    /*
    |--------------------------------------------------------------------------
    | Runtime behaviour
    |--------------------------------------------------------------------------
    */
    'discovery_ttl' => (int) env('SSO_DISCOVERY_TTL', 3600),   // seconds to cache discovery + JWKS
    'leeway' => (int) env('SSO_LEEWAY', 30),                    // clock-skew tolerance (s) for exp/iat
    'http_timeout' => (int) env('SSO_TIMEOUT', 5),

    /*
    |--------------------------------------------------------------------------
    | Authorization (consume the platform's authoritative permission list)
    |--------------------------------------------------------------------------
    | Decisions stay on the platform. We fetch the resolved list and check it.
    | NOTE: the endpoint must accept THIS service's OAuth bearer — the platform
    | must expose me/permissions to `idp.verify` (bearer), not only `core.auth`.
    */
    'permissions_path' => env('SSO_PERMISSIONS_PATH', 'api/sso/me/permissions'),
    'permissions_ttl' => (int) env('SSO_PERMISSIONS_TTL', 300),

    /*
    |--------------------------------------------------------------------------
    | Catalog registration (push this service's permission codes UP to the IdP)
    |--------------------------------------------------------------------------
    | The catalog itself lives in `config/authz.php` (the service owns it).
    | `php artisan dxs:sync-authz` PUTs it to the platform authz endpoint.
    */
    'service_id' => env('SSO_SERVICE_ID', ''),                            // {service} for the authz route
    'admin_token' => env('SSO_ADMIN_TOKEN', ''),                          // bearer w/ catalog.authz.manage
    'authz_path' => env('SSO_AUTHZ_PATH', 'api/admin/catalog/{service}/authz'),

    // Where to send the user after a successful / failed login.
    'after_login' => env('SSO_AFTER_LOGIN', '/'),
    'after_logout' => env('SSO_AFTER_LOGOUT', '/'),

    // The bearer cookie name (kept compatible with the existing ReadBearerFromCookie).
    'token_cookie' => env('SSO_TOKEN_COOKIE', 'token'),

    /*
    |--------------------------------------------------------------------------
    | Route registration
    |--------------------------------------------------------------------------
    | The package registers GET /auth/redirect, GET /auth/callback,
    | POST /auth/logout under this prefix + middleware group.
    */
    /*
     * The default JIT provisioner writes to this model (falls back to
     * auth.providers.users.model). Bind your own ProvisionsUsers
     * implementation to take over completely.
     */
    /*
     * Authorization-read resilience. By default a Gate check or Sso facade
     * read fails CLOSED when the platform is unreachable (log + deny) rather
     * than letting the renderable SsoException hijack the page with a redirect.
     * Set strict=true to rethrow instead (e.g. in background jobs).
     */
    'permissions' => [
        'strict' => (bool) env('SSO_PERMISSIONS_STRICT', false),
    ],

    'provisioner' => [
        'model' => env('SSO_PROVISIONER_MODEL'),
    ],

    'routes' => [
        'enabled' => env('SSO_ROUTES_ENABLED', true),
        'prefix' => env('SSO_ROUTES_PREFIX', 'auth'),
        // Register a named `login` route redirecting into /auth/redirect
        // when the app does not define one itself.
        'login_redirect' => (bool) env('SSO_LOGIN_REDIRECT', true),
        'middleware' => ['web'],
    ],
];
