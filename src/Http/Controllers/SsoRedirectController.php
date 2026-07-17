<?php

declare(strict_types=1);

namespace Dxs\Auth\Http\Controllers;

use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\Services\OidcDiscovery;
use Dxs\Auth\Support\Pkce;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

/**
 * GET /auth/redirect — begin Authorization Code + PKCE. Stashes the verifier +
 * state + intended return path in the session, then bounces to the IdP.
 */
final class SsoRedirectController
{
    public function __invoke(Request $request, OidcDiscovery $discovery): RedirectResponse
    {
        $pkce = Pkce::generate();
        $state = Str::random(40);
        $nonce = Str::random(40);
        $configuredOrganizationContextId = (string) config('sso.organization_context_id', '');
        $organizationContextId = $configuredOrganizationContextId !== ''
            ? $configuredOrganizationContextId
            : (string) $request->query('organization_context_id', '');

        if (! Str::isUuid($organizationContextId)) {
            throw new SsoException('A valid organization context is required to start SSO.');
        }

        $request->session()->put('sso.verifier', $pkce['verifier']);
        $request->session()->put('sso.state', $state);
        $request->session()->put('sso.nonce', $nonce);
        $request->session()->put('sso.organization_context_id', $organizationContextId);
        if ($request->filled('return')) {
            $request->session()->put('sso.return', (string) $request->query('return'));
        }

        $query = http_build_query([
            'service_slug' => config('sso.service_slug'),
            'organization_context_id' => $organizationContextId,
            'client_id' => config('sso.client_id'),
            'redirect_uri' => config('sso.redirect_uri'),
            'response_type' => 'code',
            'scope' => config('sso.scopes'),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $pkce['challenge'],
            'code_challenge_method' => 'S256',
        ]);

        return redirect()->away($discovery->authorizationEndpoint().'?'.$query);
    }
}
