<?php

declare(strict_types=1);

namespace Dxs\Auth\Http\Controllers;

use Dxs\Auth\Contracts\ProvisionsUsers;
use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\Services\JwtVerifier;
use Dxs\Auth\Services\LogoutSessionRegistry;
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
        LogoutSessionRegistry $logoutSessions,
    ): Response {
        $callbackState = $request->query('state');
        $transaction = is_string($callbackState) && $callbackState !== ''
            ? $request->session()->pull("sso.transactions.{$callbackState}")
            : null;

        if (! is_array($transaction)) {
            throw new SsoException('SSO state mismatch — possible CSRF or expired flow.');
        }

        $ttl = (int) config('sso.transaction_ttl', 600);
        if ((int) ($transaction['created_at'] ?? 0) < now()->timestamp - $ttl) {
            throw new SsoException('SSO sign-in took too long — please try again.');
        }
        $verifierCode = $transaction['verifier'] ?? null;
        $expectedNonce = $transaction['nonce'] ?? null;
        $expectedOrganizationContextId = $transaction['organization_context_id'] ?? null;
        $return = $transaction['return'] ?? null;

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

            // RFC 9068 access tokens carry authorization claims only; profile
            // claims (name, email) travel in the OIDC ID token. Surface them to
            // the provisioner without letting them shadow access-token claims.
            foreach (['name', 'email'] as $profileClaim) {
                if (! isset($claims[$profileClaim]) && isset($idClaims[$profileClaim])) {
                    $claims[$profileClaim] = $idClaims[$profileClaim];
                }
            }
        }

        $this->assertOrganizationClaim($claims, $expectedOrganizationContextId);

        $user = $provisioner->provision($claims, $tokens);
        Auth::login($user);
        $request->session()->regenerate();
        $logoutSessions->register($claims, $tokens['access_token'], $request->session()->getId());

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

    /**
     * Bind the token to the organization selected at /auth/redirect.
     *
     * Two IdP claim shapes exist: the legacy `organization_context_id` (console
     * organization id, mirrored from the authorize request) and the current
     * platform's `organization_id` (the service instance's internal platform
     * organization id, validated against `sso.organization_id`). Accept either,
     * but never neither.
     *
     * @param  array<string, mixed>  $claims
     */
    private function assertOrganizationClaim(array $claims, string $expectedOrganizationContextId): void
    {
        $tokenOrganizationContextId = $claims['organization_context_id'] ?? null;
        if (is_string($tokenOrganizationContextId) && $tokenOrganizationContextId !== '') {
            if (! hash_equals($expectedOrganizationContextId, $tokenOrganizationContextId)) {
                throw new SsoException('SSO token organization context does not match the selected organization.');
            }

            return;
        }

        $tokenOrganizationId = $claims['organization_id'] ?? null;
        $expectedOrganizationId = (string) config('sso.organization_id', '');
        if (is_string($tokenOrganizationId) && $tokenOrganizationId !== '' && $expectedOrganizationId !== '') {
            if (! hash_equals($expectedOrganizationId, $tokenOrganizationId)) {
                throw new SsoException('SSO token organization does not match the configured organization.');
            }

            return;
        }

        throw new SsoException('SSO token is missing a verifiable organization claim.');
    }

    private function requestsOpenId(): bool
    {
        return in_array('openid', preg_split('/\s+/', trim((string) config('sso.scopes'))) ?: [], true);
    }
}
