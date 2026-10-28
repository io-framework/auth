<?php

namespace Io\Auth;

use BackedEnum;

/** A signed-in user as one request sees them: their session, their roles, and what those allow right now. */
final readonly class Principal
{
    /**
     * @param list<string> $roles the roles' names
     * @param list<string> $permissions every permission one of the roles allows
     */
    public function __construct(
        public int $id,
        public int $session,
        public string $name,
        public string $email,
        public array $roles,
        public bool $admin,
        public array $permissions,
    ) {
    }

    /** The Admin role may do everything, other users what one of their roles allows; an enum counts by its value */
    public function can(string|BackedEnum $permission): bool
    {
        $name = $permission instanceof BackedEnum ? (string) $permission->value : $permission;

        return $this->admin || in_array($name, $this->permissions, true);
    }

    /**
     * What Io keeps as $req->principal: #[Authenticated], #[Role] (one of 'roles') and #[Permissions] read it.
     *
     * @return array{sub: int, session: int, name: string, email: string, roles: list<string>, admin: bool, permissions: list<string>}
     */
    public function claims(): array
    {
        return [
            'sub' => $this->id,
            'session' => $this->session,
            'name' => $this->name,
            'email' => $this->email,
            'roles' => $this->roles,
            'admin' => $this->admin,
            'permissions' => $this->permissions,
        ];
    }
}
