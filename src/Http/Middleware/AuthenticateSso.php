<?php

declare(strict_types=1);

namespace Dxs\Auth\Http\Middleware;

use Closure;
use Dxs\Auth\Contracts\ProvisionsUsers;
use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\Services\JwtVerifier;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

/**
 * `sso.auth` — per-request resource-server auth. Reads the platform-issued
 * bearer (Authorization header; the app's ReadBearerFromCookie promotes the
 * cookie to a header first), verifies it against the IdP JWKS (`iss`/`aud`/
 * `exp`), and resolves/JIT-provisions the local user. Replaces the gateway
 * header-trust middleware — no shared gateway secret, no injected identity.
 */
final class AuthenticateSso
{
    public function __construct(
        private readonly JwtVerifier $verifier,
        private readonly ProvisionsUsers $provisioner,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->bearerToken();

        if (! is_string($token) || $token === '') {
            return $this->unauthenticated($request);
        }

        try {
            $claims = $this->verifier->verify($token);
        } catch (SsoException) {
            return $this->unauthenticated($request);
        }

        $subject = (string) $claims['sub'];
        $user = $this->provisioner->resolveBySubject($subject)
            ?? $this->provisioner->provision($claims, ['access_token' => $token]);

        Auth::setUser($user);
        $request->setUserResolver(fn () => $user);
        $request->attributes->set('sso_claims', $claims);
        $request->attributes->set('sso_subject', $subject);

        return $next($request);
    }

    private function unauthenticated(Request $request): Response
    {
        if ($request->expectsJson()) {
            return response()->json(['message' => 'Unauthenticated.'], 401);
        }

        return redirect()->guest(route('sso.redirect', ['return' => $request->getRequestUri()]));
    }
}
