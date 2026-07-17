<?php

declare(strict_types=1);

namespace Dxs\Auth\Http\Controllers;

use Dxs\Auth\Events\SsoLoggedOut;
use Dxs\Auth\Services\OidcDiscovery;
use Dxs\Auth\Services\PermissionClient;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Symfony\Component\HttpFoundation\Response;

/**
 * POST /auth/logout — clear the local session + bearer cookie, then (if the IdP
 * advertises it) RP-initiated logout at the end-session endpoint.
 */
final class SsoLogoutController
{
    public function __invoke(Request $request, OidcDiscovery $discovery): Response
    {
        $bearer = $request->cookie((string) config('sso.token_cookie'));
        if (is_string($bearer) && $bearer !== '') {
            PermissionClient::forgetForTokenHash(hash('sha256', $bearer));
        }

        SsoLoggedOut::dispatch(Auth::user());

        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        $forget = Cookie::forget((string) config('sso.token_cookie'));
        $end = $discovery->endSessionEndpoint();

        $target = $end !== null
            ? $this->endSessionUrl($end)
            : (string) config('sso.after_logout');

        return redirect()->to($target)->withCookie($forget);
    }

    /**
     * OIDC RP-Initiated Logout 1.0 — identify the RP (`client_id`) and where
     * the IdP may send the browser afterwards (`post_logout_redirect_uri`,
     * as an absolute URL of the local after-logout destination).
     */
    private function endSessionUrl(string $endSessionEndpoint): string
    {
        $query = http_build_query([
            'client_id' => (string) config('sso.client_id'),
            'post_logout_redirect_uri' => url((string) config('sso.after_logout')),
        ]);

        return $endSessionEndpoint.(str_contains($endSessionEndpoint, '?') ? '&' : '?').$query;
    }
}
