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
    | The catalog itself lives in `config/permissions.php` (the service owns it).
    | `php artisan dxs:sync-permissions` PUTs it to the platform authz endpoint.
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
    'routes' => [
        'enabled' => env('SSO_ROUTES_ENABLED', true),
        'prefix' => env('SSO_ROUTES_PREFIX', 'auth'),
        'middleware' => ['web'],
    ],
];
