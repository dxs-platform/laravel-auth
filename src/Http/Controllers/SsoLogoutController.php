<?php

declare(strict_types=1);

namespace Dxs\Auth\Http\Controllers;

use Dxs\Auth\Services\OidcDiscovery;
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
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        $forget = Cookie::forget((string) config('sso.token_cookie'));
        $end = $discovery->endSessionEndpoint();

        $target = $end ?? (string) config('sso.after_logout');

        return redirect()->to($target)->withCookie($forget);
    }
}
