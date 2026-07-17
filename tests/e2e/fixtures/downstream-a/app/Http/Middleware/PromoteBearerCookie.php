<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class PromoteBearerCookie
{
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->cookie((string) config('sso.token_cookie'));
        if (is_string($token) && $token !== '') {
            $request->headers->set('Authorization', 'Bearer '.$token);
        }

        return $next($request);
    }
}
