<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Service authorization catalog
|--------------------------------------------------------------------------
| The permission codes THIS service declares. Pushed to the GoDX ID platform
| with `php artisan dxs:sync-authz`; the platform builds roles from them
| and resolves them per user at login. The service owns this file.
|
| Each permission: ['slug' => 'group.action', 'display_name' => '...', 'group' => '...'].
| Roles/assignments are optional and typically managed on the platform.
*/

return [
    'permissions' => [
        // ['slug' => 'absences.view', 'display_name' => 'Absences · View', 'group' => 'absences'],
    ],

    'roles' => [
        // ['role' => 'admin', 'display_name' => 'Administrator', 'level' => 100, 'permissions' => ['absences.view']],
    ],

    'default_role' => null,
];
