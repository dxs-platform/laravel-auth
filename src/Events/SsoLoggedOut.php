<?php

declare(strict_types=1);

namespace Dxs\Auth\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * A user initiated RP-initiated logout at /auth/logout. Fires BEFORE the local
 * session is torn down, so listeners still see the outgoing user.
 */
final class SsoLoggedOut
{
    use Dispatchable;

    public function __construct(public readonly ?Authenticatable $user) {}
}
