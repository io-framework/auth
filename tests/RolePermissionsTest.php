<?php

namespace Io\Auth\Tests;

use Io\Auth\{Principal, RolePermissions};
use PHPUnit\Framework\TestCase;

final class RolePermissionsTest extends TestCase
{
    public function testWhatTheSessionsRolesAllow(): void
    {
        $permissions = new RolePermissions();
        $editor = new Principal(2, 1, 'Ed', 'ed@example.test', ['Editors'], false, ['pages.edit'])->claims();
        $admin = new Principal(3, 1, 'Ada', 'ada@example.test', ['Admin'], true, [])->claims();

        $this->assertTrue($permissions->hasPermission($editor, 'pages.edit'));
        $this->assertFalse($permissions->hasPermission($editor, 'users.manage'));
        $this->assertTrue($permissions->hasPermission($admin, 'users.manage'));
        $this->assertFalse($permissions->hasPermission(null, 'pages.edit'));
    }
}
