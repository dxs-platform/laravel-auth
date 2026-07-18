<?php

declare(strict_types=1);

namespace Dxs\Auth\Facades;

use Dxs\Auth\SsoManager;
use Illuminate\Support\Facades\Facade;

/**
 * @method static \Illuminate\Contracts\Auth\Authenticatable|null user()
 * @method static bool check()
 * @method static \Illuminate\Support\Collection permissions()
 * @method static array roles()
 * @method static array serviceAccess()
 * @method static array organizations()
 * @method static array organizationAccess(string $organizationSlug)
 * @method static array branches(string $organizationSlug)
 * @method static array brands(string $organizationSlug)
 * @method static array teams(string $organizationSlug)
 * @method static bool can(string $ability)
 * @method static bool canAll(string ...$abilities)
 * @method static bool canAny(string ...$abilities)
 * @method static bool hasRole(string $role)
 *
 * @see SsoManager
 */
final class Sso extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return SsoManager::class;
    }
}
