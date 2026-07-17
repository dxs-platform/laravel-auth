<?php

declare(strict_types=1);

namespace Dxs\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * The consuming app implements this to map validated SSO token claims to its
 * own local user record (JIT upsert), keyed on the platform subject (`sub`).
 * Bind an implementation to this interface in the app's container.
 */
interface ProvisionsUsers
{
    /**
     * @param  array<string, mixed>  $claims  validated token claims
     *                                        (sub, email, name, organization_context_id, organization_id, organization_access_mode, scope, …)
     * @param  array{access_token: string, refresh_token?: string, expires_in?: int}  $tokens
     */
    public function provision(array $claims, array $tokens): Authenticatable;

    /** Resolve an already-provisioned user for a request, by subject. */
    public function resolveBySubject(string $subject): ?Authenticatable;
}
