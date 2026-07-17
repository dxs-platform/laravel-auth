<?php

use App\Http\Middleware\PromoteBearerCookie;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(web: __DIR__.'/../routes/web.php', commands: __DIR__.'/../routes/console.php', health: '/up')
    ->withMiddleware(fn (Middleware $middleware) => $middleware->alias(['bearer.cookie' => PromoteBearerCookie::class]))
    ->withExceptions(fn (Exceptions $exceptions) => null)
    ->create();
