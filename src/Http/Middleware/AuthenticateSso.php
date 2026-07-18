<?php

declare(strict_types=1);

namespace Dxs\Auth\Http\Middleware;

use Closure;
use Dxs\Auth\Contracts\ProvisionsUsers;
use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\Services\JwtVerifier;
use Dxs\Auth\Services\LogoutSessionRegistry;
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
        private readonly LogoutSessionRegistry $logoutSessions,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->bearerToken();

        // Dev/test escape hatches — mirror the gateway middleware this replaces.
        // NEVER active in production (real JWKS-verified bearer only there).
        if (app()->environment() !== 'production') {
            // 1. Honour an already-authenticated user only when the request has
            //    no bearer. An explicit bearer must remain authoritative and
            //    must not force custom-provisioner consumers to resolve the
            //    default session provider first.
            if ((! is_string($token) || $token === '') && Auth::check()) {
                return $next($request);
            }

            // 2. Accept a `Bearer dev:<subject>` token → resolve/JIT-provision the
            //    local user for that subject with no network round-trip.
            if (is_string($token) && str_starts_with($token, 'dev:')) {
                $subject = substr($token, 4);

                if ($subject !== '') {
                    $user = $this->provisioner->resolveBySubject($subject)
                        ?? $this->provisioner->provision(['sub' => $subject], ['access_token' => $token]);

                    Auth::setUser($user);
                    $request->setUserResolver(fn () => $user);
                    $request->attributes->set('sso_subject', $subject);

                    return $next($request);
                }
            }
        }

        if (! is_string($token) || $token === '') {
            return $this->unauthenticated($request);
        }

        if ($this->logoutSessions->tokenIsRevoked($token)) {
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
            // RFC 6750 §3 — a 401 to a protected resource MUST carry a
            // WWW-Authenticate challenge; `invalid_token` only when a token
            // was actually presented (a bare challenge otherwise).
            $challenge = $request->bearerToken()
                ? 'Bearer realm="sso", error="invalid_token"'
                : 'Bearer realm="sso"';

            return response()->json(['message' => 'Unauthenticated.'], 401)
                ->header('WWW-Authenticate', $challenge);
        }

        return redirect()->guest(route('sso.redirect', ['return' => $request->getRequestUri()]));
    }
}
