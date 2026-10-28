<?php

namespace Io\Auth;

use Io\PermissionProvider;

/** For #[Permissions('pages.edit')]: what the session's roles allow, as Principal::claims() put it. AuthPlugin binds it. */
final class RolePermissions implements PermissionProvider
{
    public function hasPermission(mixed $jwt, string $permission): bool
    {
        if (!is_array($jwt)) {
            return false;
        }
        $permissions = $jwt['permissions'] ?? null;

        return ($jwt['admin'] ?? false) === true || (is_array($permissions) && in_array($permission, $permissions, true));
    }
}
