<?php

declare(strict_types=1);

namespace Dxs\Auth\Http\Controllers;

use Dxs\Auth\Contracts\ProvisionsUsers;
use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\Services\JwtVerifier;
use Dxs\Auth\Services\TokenExchanger;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Symfony\Component\HttpFoundation\Response;

/**
 * GET /auth/callback — validate state, exchange the code, verify the access
 * token against the IdP JWKS, JIT-provision the local user, then establish the
 * session AND the bearer cookie (BFF: the SPA never sees the token).
 */
final class SsoCallbackController
{
    public function __invoke(
        Request $request,
        TokenExchanger $exchanger,
        JwtVerifier $verifier,
        ProvisionsUsers $provisioner,
    ): Response {
        if ($request->filled('error')) {
            throw new SsoException('SSO authorization failed: '.$request->query('error'));
        }

        $sessionState = $request->session()->pull('sso.state');
        $verifierCode = $request->session()->pull('sso.verifier');
        $return = $request->session()->pull('sso.return');

        if (! is_string($sessionState) || ! hash_equals($sessionState, (string) $request->query('state'))) {
            throw new SsoException('SSO state mismatch — possible CSRF or expired flow.');
        }
        if (! $request->filled('code') || ! is_string($verifierCode)) {
            throw new SsoException('SSO callback is missing the authorization code.');
        }

        $tokens = $exchanger->exchangeCode((string) $request->query('code'), $verifierCode);
        $claims = $verifier->verify($tokens['access_token']);

        $user = $provisioner->provision($claims, $tokens);
        Auth::login($user);
        $request->session()->regenerate();

        $seconds = (int) ($tokens['expires_in'] ?? 900);
        $cookie = Cookie::make(
            name: (string) config('sso.token_cookie'),
            value: $tokens['access_token'],
            minutes: (int) max(1, floor($seconds / 60)),
            path: '/',
            domain: null,
            secure: $request->isSecure(),
            httpOnly: true,
            raw: false,
            sameSite: 'lax',
        );

        return redirect()->to(is_string($return) && $return !== '' ? $return : (string) config('sso.after_login'))
            ->withCookie($cookie);
    }
}
