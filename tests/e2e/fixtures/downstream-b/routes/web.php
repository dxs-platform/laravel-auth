<?php

use Dxs\Auth\Services\PermissionClient;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

$organization = '3efb1df0-1814-480c-9566-42d339758da8';

Route::get('/', fn () => response('<!doctype html><title>Consumer B</title><a href="/auth/redirect?organization_context_id='.$organization.'&return=%2Fprotected">Start SSO login</a>'));
Route::get('/protected', function (Request $request) {
    $claims = $request->attributes->get('sso_claims');
    return response('<!doctype html><title>Protected B</title><p data-testid="service">'.e((string) config('sso.service_slug')).'</p><p data-testid="organization">'.e((string) $claims['organization_context_id']).'</p><a href="/permissions">Load permissions</a>');
})->middleware(['bearer.cookie', 'sso.auth']);
Route::get('/permissions', function (Request $request, PermissionClient $permissions) {
    $claims = $request->attributes->get('sso_claims');
    $grants = $permissions->permissionsFor((string) $request->bearerToken(), (string) $claims['organization_context_id']);
    return response('<!doctype html><title>Permissions B</title><p>'.e($grants->join(',' )).'</p>');
})->middleware(['bearer.cookie', 'sso.auth']);
