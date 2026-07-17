<?php

declare(strict_types=1);

namespace Dxs\Auth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Symfony\Component\HttpFoundation\Response;

/**
 * `sso.can:{ability[,ability…]}` — the package-owned authorization gate for
 * downstream resource routes. One alias does the whole pipeline: authenticate
 * the platform bearer (via {@see AuthenticateSso}), then require EVERY listed
 * ability, answered by the platform-resolved permission list (Gate::before)
 * with local Gate definitions still applying for abilities outside it.
 *
 * Denials speak RFC 6750 §3.1: a 403 carries
 * `WWW-Authenticate: Bearer realm="sso", error="insufficient_scope"` naming
 * the missing ability — so API clients can distinguish "wrong token" (401,
 * invalid_token) from "right token, missing permission" without parsing
 * bodies. Consumers keep Laravel's plain `can:` working too; this alias just
 * removes the need to pair it with `sso.auth` and standardises the error
 * shape across every downstream service.
 */
final class AuthorizeSsoPermission
{
    public function __construct(private readonly AuthenticateSso $authenticate) {}

    public function handle(Request $request, Closure $next, string ...$abilities): Response
    {
        return $this->authenticate->handle($request, function (Request $request) use ($next, $abilities): Response {
            $user = Auth::user();

            foreach ($abilities as $ability) {
                if ($user === null || ! Gate::forUser($user)->allows($ability)) {
                    return $this->insufficientScope($request, $ability);
                }
            }

            return $next($request);
        });
    }

    private function insufficientScope(Request $request, string $ability): Response
    {
        $challenge = sprintf('Bearer realm="sso", error="insufficient_scope", scope="%s"', $ability);

        if ($request->expectsJson()) {
            return response()->json([
                'message' => 'Forbidden.',
                'required_permission' => $ability,
            ], 403)->header('WWW-Authenticate', $challenge);
        }

        return response('Forbidden.', 403, ['WWW-Authenticate' => $challenge]);
    }
}
