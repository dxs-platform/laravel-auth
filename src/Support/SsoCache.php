<?php

declare(strict_types=1);

namespace Dxs\Auth\Support;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;

/**
 * Single resolver for every cache the package touches (discovery, JWKS,
 * permissions, logout registry). Downstream services configure WHERE the
 * package caches (`sso.cache.store` — e.g. a shared redis so back-channel
 * logout and permission invalidation reach every node) and under WHICH
 * namespace (`sso.cache.prefix`) without touching the app's default store.
 */
final class SsoCache
{
    public static function store(): Repository
    {
        $store = config('sso.cache.store');

        return Cache::store(is_string($store) && $store !== '' ? $store : null);
    }

    public static function key(string $suffix): string
    {
        $prefix = (string) config('sso.cache.prefix', 'sso');

        return rtrim($prefix, ':').':'.$suffix;
    }
}
