<?php

use Dxs\Auth\Services\PermissionClient;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

$organization = '9f79d9ee-d735-4673-a80d-c11339f252be';

Route::get('/', fn () => response('<!doctype html><title>Consumer A</title><a href="/auth/redirect?organization_context_id='.$organization.'&return=%2Fprotected">Start SSO login</a>'));
Route::get('/protected', function (Request $request) {
    $claims = $request->attributes->get('sso_claims');
    return response('<!doctype html><title>Protected A</title><p data-testid="service">'.e((string) config('sso.service_slug')).'</p><p data-testid="organization">'.e((string) $claims['organization_context_id']).'</p><a href="/permissions">Load permissions</a>');
})->middleware(['bearer.cookie', 'sso.auth']);
Route::get('/permissions', function (Request $request, PermissionClient $permissions) {
    $claims = $request->attributes->get('sso_claims');
    $grants = $permissions->permissionsFor((string) $request->bearerToken(), (string) $claims['organization_context_id']);
    return response('<!doctype html><title>Permissions A</title><p>'.e($grants->join(',' )).'</p>');
})->middleware(['bearer.cookie', 'sso.auth']);
