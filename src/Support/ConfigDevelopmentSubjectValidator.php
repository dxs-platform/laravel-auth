<?php

declare(strict_types=1);

namespace Dxs\Auth\Support;

use Dxs\Auth\Contracts\ValidatesDevelopmentSubjects;

/** Fail-closed validator backed by the explicit development subject list. */
final class ConfigDevelopmentSubjectValidator implements ValidatesDevelopmentSubjects
{
    public function allows(string $subject): bool
    {
        return in_array($subject, (array) config('sso.dev_bypass.subjects', []), true);
    }
}
