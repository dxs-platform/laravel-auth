<?php

namespace App\Providers;

use App\Sso\UserProvisioner;
use Dxs\Auth\Contracts\ProvisionsUsers;
use Illuminate\Support\ServiceProvider;

final class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(ProvisionsUsers::class, UserProvisioner::class);
    }
}
