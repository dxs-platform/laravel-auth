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
        $sessionState = $request->session()->pull('sso.state');
        $verifierCode = $request->session()->pull('sso.verifier');
        $expectedNonce = $request->session()->pull('sso.nonce');
        $expectedOrganizationContextId = $request->session()->pull('sso.organization_context_id');
        $return = $request->session()->pull('sso.return');
        $callbackState = $request->query('state');

        if (! is_string($sessionState) || ! is_string($callbackState) || ! hash_equals($sessionState, $callbackState)) {
            throw new SsoException('SSO state mismatch — possible CSRF or expired flow.');
        }
        if ($request->filled('error')) {
            throw new SsoException('SSO authorization was denied by the identity provider.');
        }

        $authorizationCode = $request->query('code');
        if (! is_string($authorizationCode) || $authorizationCode === '' || ! is_string($verifierCode) || $verifierCode === '') {
            throw new SsoException('SSO callback is missing the authorization code or PKCE verifier.');
        }
        if (! is_string($expectedNonce)
            || $expectedNonce === ''
            || ! is_string($expectedOrganizationContextId)
            || $expectedOrganizationContextId === ''
        ) {
            throw new SsoException('SSO callback transaction is missing its nonce or organization context.');
        }

        $tokens = $exchanger->exchangeCode($authorizationCode, $verifierCode);
        $claims = $verifier->verify($tokens['access_token']);
        $idToken = $tokens['id_token'] ?? null;
        if ((! is_string($idToken) || $idToken === '') && $this->requestsOpenId()) {
            throw new SsoException('SSO token response has no id_token.');
        }

        if (is_string($idToken) && $idToken !== '') {
            $idClaims = $verifier->verifyIdToken($idToken, $expectedNonce);
            if (! hash_equals((string) ($claims['sub'] ?? ''), (string) ($idClaims['sub'] ?? ''))) {
                throw new SsoException('SSO access token and ID token subjects do not match.');
            }
        }
        $tokenOrganizationContextId = $claims['organization_context_id'] ?? null;
        if (! is_string($tokenOrganizationContextId)
            || ! hash_equals($expectedOrganizationContextId, $tokenOrganizationContextId)
        ) {
            throw new SsoException('SSO token organization context does not match the selected organization.');
        }

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

    private function requestsOpenId(): bool
    {
        return in_array('openid', preg_split('/\s+/', trim((string) config('sso.scopes'))) ?: [], true);
    }
}
