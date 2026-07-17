<?php

declare(strict_types=1);

namespace Dxs\Auth\Services;

use Dxs\Auth\Exceptions\SsoException;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;

/**
 * Exchanges the authorization code (and later the refresh token) at the
 * platform token endpoint. The platform binds the client to `service_slug`.
 */
final class TokenExchanger
{
    public function __construct(private readonly OidcDiscovery $discovery) {}

    /**
     * @return array{access_token: string, token_type?: string, expires_in?: int, refresh_token?: string, id_token?: string, scope?: string}
     */
    public function exchangeCode(string $code, string $codeVerifier): array
    {
        return $this->post([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => (string) config('sso.redirect_uri'),
            'code_verifier' => $codeVerifier,
        ]);
    }

    /** @return array{access_token: string, expires_in?: int, refresh_token?: string} */
    public function refresh(string $refreshToken): array
    {
        return $this->post([
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
        ]);
    }

    /**
     * @param  array<string, string>  $payload
     * @return array<string, mixed>
     */
    private function post(array $payload): array
    {
        try {
            $response = Http::connectTimeout(min(3, (int) config('sso.http_timeout')))
                ->timeout((int) config('sso.http_timeout'))
                ->asForm()
                ->acceptJson()
                ->post($this->discovery->tokenEndpoint(), array_merge($payload, [
                    'service_slug' => (string) config('sso.service_slug'),
                    'client_id' => (string) config('sso.client_id'),
                    'client_secret' => (string) config('sso.client_secret'),
                ]));
        } catch (ConnectionException $exception) {
            throw new SsoException('SSO token endpoint is temporarily unreachable.', previous: $exception);
        }

        if ($response->failed()) {
            throw new SsoException("SSO token exchange failed ({$response->status()}).");
        }

        $data = $response->json();

        if (! is_array($data) || ! isset($data['access_token']) || ! is_string($data['access_token']) || $data['access_token'] === '') {
            throw new SsoException('SSO token response has no access_token.');
        }

        return $data;
    }
}
