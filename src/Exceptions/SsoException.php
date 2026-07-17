<?php

declare(strict_types=1);

namespace Dxs\Auth\Exceptions;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use RuntimeException;

/**
 * A failed SSO flow. These are ordinary, user-recoverable situations (the user
 * denied consent, a state transaction expired, the IdP was unreachable), so the
 * exception renders as a redirect to `sso.failure_redirect` (falling back to
 * `sso.after_logout`) with the message flashed under `sso.error` — never a raw
 * 500. Operator mistakes throw {@see SsoConfigurationException} instead, which
 * keeps default (500) handling.
 */
class SsoException extends RuntimeException
{
    public function render(Request $request): RedirectResponse|bool
    {
        $target = (string) (config('sso.failure_redirect') ?: config('sso.after_logout') ?: '/');

        return redirect()->to($target)->with('sso.error', $this->getMessage());
    }

    public function report(): void
    {
        Log::warning('SSO flow failed: '.$this->getMessage());
    }
}
