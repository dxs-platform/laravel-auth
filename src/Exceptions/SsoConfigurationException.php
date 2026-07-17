<?php

declare(strict_types=1);

namespace Dxs\Auth\Exceptions;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

/**
 * An SSO failure caused by consumer misconfiguration (missing client
 * credentials, no organization context, invalid issuer). Unlike the
 * user-recoverable {@see SsoException}, this is an operator error: it keeps
 * default exception handling (500) so it cannot be mistaken for a login the
 * user can simply retry.
 */
final class SsoConfigurationException extends SsoException
{
    public function render(Request $request): RedirectResponse|bool
    {
        return false;
    }

    public function report(): void
    {
        Log::error('SSO misconfiguration: '.$this->getMessage());
    }
}
