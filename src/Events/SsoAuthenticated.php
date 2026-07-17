<?php

declare(strict_types=1);

namespace Dxs\Auth\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * A user completed the SSO callback and was logged in. Fires AFTER provisioning
 * and Auth::login — hook it for audit trails, welcome emails, last-login stamps.
 * `$firstLogin` is true when the local user record was created by this login.
 */
final class SsoAuthenticated
{
    use Dispatchable;

    /** @param array<string, mixed> $claims validated token claims */
    public function __construct(
        public readonly Authenticatable $user,
        public readonly array $claims,
        public readonly bool $firstLogin,
    ) {}
}
