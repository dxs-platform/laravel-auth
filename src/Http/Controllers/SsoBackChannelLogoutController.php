<?php

declare(strict_types=1);

namespace Dxs\Auth\Http\Controllers;

use Dxs\Auth\Exceptions\SsoException;
use Dxs\Auth\Services\JwtVerifier;
use Dxs\Auth\Services\LogoutSessionRegistry;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class SsoBackChannelLogoutController
{
    public function __invoke(
        Request $request,
        JwtVerifier $verifier,
        LogoutSessionRegistry $sessions,
    ): Response {
        $logoutToken = $request->input('logout_token');
        if (! is_string($logoutToken) || $logoutToken === '') {
            return response()->json(['error' => 'invalid_request'], 400);
        }

        try {
            $claims = $verifier->verifyLogoutToken($logoutToken);
        } catch (SsoException) {
            return response()->json(['error' => 'invalid_logout_token'], 400);
        }

        $sessionLineage = $claims['sid'] ?? null;
        if (! is_string($sessionLineage) || $sessionLineage === '') {
            return response()->json(['error' => 'subject_logout_not_supported'], 400);
        }

        $registration = $sessions->revoke($sessionLineage);
        if ($registration !== null) {
            $request->session()->getHandler()->destroy($registration['session_id']);
        }

        return response('', 200);
    }
}
