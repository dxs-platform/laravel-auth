<?php

declare(strict_types=1);

namespace Dxs\Auth\Contracts;

/** Authorizes a development-only bearer subject before any user is resolved. */
interface ValidatesDevelopmentSubjects
{
    public function allows(string $subject): bool;
}
