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
        $requestedOrganizationContextId = $request->query('organization_context_id');
        $organizationContextId = $configuredOrganizationContextId !== ''
            ? $configuredOrganizationContextId
            : (is_string($requestedOrganizationContextId) ? $requestedOrganizationContextId : '');

        if (! Str::isUuid($organizationContextId)) {
            throw new SsoException('A valid organization context is required to start SSO.');
        }

        $returnPath = $this->safeReturnPath($request->query('return'));
        $request->session()->put("sso.transactions.{$state}", [
            'verifier' => $pkce['verifier'],
            'nonce' => $nonce,
            'organization_context_id' => $organizationContextId,
            'return' => $returnPath,
            'created_at' => now()->timestamp,
        ]);

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

    private function safeReturnPath(mixed $returnPath): ?string
    {
        if (! is_string($returnPath) || ! $this->isLocalPath($returnPath)) {
            return null;
        }

        $decodedPath = $returnPath;
        for ($decodePass = 0; $decodePass < 2; $decodePass++) {
            $decodedPath = rawurldecode($decodedPath);
            if (! $this->isLocalPath($decodedPath)) {
                return null;
            }
        }

        return $returnPath;
    }

    private function isLocalPath(string $path): bool
    {
        if ($path === ''
            || ! str_starts_with($path, '/')
            || str_starts_with($path, '//')
            || str_contains($path, '\\')
            || preg_match('/[\x00-\x1F\x7F]/', $path) === 1
        ) {
            return false;
        }

        $parts = parse_url($path);

        return $parts !== false
            && ! isset($parts['scheme'])
            && ! isset($parts['host'])
            && ! isset($parts['user'])
            && ! isset($parts['pass']);
    }
}
