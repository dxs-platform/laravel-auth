<?php

declare(strict_types=1);

use Dxs\Auth\Http\Controllers\SsoCallbackController;
use Dxs\Auth\Http\Controllers\SsoLogoutController;
use Dxs\Auth\Http\Controllers\SsoRedirectController;
use Illuminate\Support\Facades\Route;

// Prefix + middleware are applied by the service provider's route group.
Route::get('/redirect', SsoRedirectController::class)->name('sso.redirect');
Route::get('/callback', SsoCallbackController::class)->name('sso.callback');
Route::post('/logout', SsoLogoutController::class)->name('sso.logout');
