<?php

namespace Io\Auth;

use Data\Postgres;
use Io\Attributes\Inject;
use Io\Support\Row;

/** The roles: built from the PermissionCatalog's permissions; the built-in Admin role has all of them, always. */
final class Roles
{
    #[Inject]
    private Postgres $db;

    #[Inject]
    private PermissionCatalog $catalog;

    /** @return list<Role> Admin first, then by name */
    public function all(): array
    {
        return $this->db->query(
            "SELECT r.id, r.name, r.builtin, r.two_factor_required,
                    coalesce((SELECT array_agg(permission ORDER BY permission) FROM auth_role_permissions WHERE role_id = r.id), '{}') AS permissions,
                    (SELECT count(*)::int FROM auth_user_roles WHERE role_id = r.id) AS users
             FROM auth_roles r ORDER BY r.builtin DESC, lower(r.name)",
            as: Role::from(...),
        );
    }

    public function find(int $id): ?Role
    {
        foreach ($this->all() as $role) {
            if ($role->id === $id) {
                return $role;
            }
        }

        return null;
    }

    /** A new role without permissions; refused when one with the name exists, in any case */
    public function create(string $name): int
    {
        $name = self::name($name);

        return $this->db->first(
            'INSERT INTO auth_roles (name) SELECT $1 WHERE NOT EXISTS (SELECT 1 FROM auth_roles WHERE lower(name) = lower($1))
             ON CONFLICT DO NOTHING RETURNING id',
            [$name],
            as: fn (array $row): int => Row::of($row)->int('id'),
        ) ?? throw new AccountRefused(Refusal::RoleTaken);
    }

    /**
     * The role's name, permissions and whether it asks for a second factor. Permissions not in the catalog are left
     * out; someone who isn't an admin only changes the permissions they hold themselves, the rest stay as they were.
     *
     * @param list<string> $permissions
     */
    public function update(Principal $by, int $id, string $name, array $permissions, bool $twoFactor): void
    {
        $role = $this->find($id) ?? throw new AccountRefused(Refusal::UnknownRole);
        if ($role->builtin) {
            throw new AccountRefused(Refusal::BuiltinRole);
        }
        $name = self::name($name);
        $wanted = array_values(array_filter($permissions, $this->catalog->has(...)));
        if (!$by->admin) {
            $own = $by->permissions;
            $wanted = array_merge(array_intersect($wanted, $own), array_diff($role->permissions, $own));
        }
        $wanted = array_values(array_unique($wanted));
        $this->db->transaction(function (Postgres $tx) use ($id, $name, $wanted, $twoFactor): void {
            if ($tx->first('SELECT 1 FROM auth_roles WHERE lower(name) = lower($1) AND id <> $2', [$name, $id]) !== null) {
                throw new AccountRefused(Refusal::RoleTaken);
            }
            $tx->execute('UPDATE auth_roles SET name = $2, two_factor_required = $3 WHERE id = $1', [$id, $name, $twoFactor]);
            $tx->execute('DELETE FROM auth_role_permissions WHERE role_id = $1', [$id]);
            foreach ($wanted as $permission) {
                $tx->execute('INSERT INTO auth_role_permissions (role_id, permission) VALUES ($1, $2)', [$id, $permission]);
            }
        });
    }

    /** Deletes the role, its users lose what it allowed; never the Admin role */
    public function delete(int $id): void
    {
        if ($this->db->execute('DELETE FROM auth_roles WHERE id = $1 AND NOT builtin', [$id]) === 0 && $this->find($id)?->builtin === true) {
            throw new AccountRefused(Refusal::BuiltinRole);
        }
    }

    private static function name(string $name): string
    {
        $name = trim($name);
        if ($name === '' || mb_strlen($name) > 60) {
            throw new AccountRefused(Refusal::InvalidRoleName);
        }

        return $name;
    }
}
