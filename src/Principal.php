<?php

namespace Io\Auth;

use BackedEnum;
use Io\SignOuts;

/** A signed-in user as one request sees them: their session, their roles, and what those allow right now. */
final readonly class Principal
{
    /**
     * @param string $name the display name, or the handle when the site has none
     * @param list<string> $roles the roles' names
     * @param list<string> $permissions every permission one of the roles allows
     * @param int $expires when a connection that outlives its request (a WebSocket) asks the session again, as a
     *     Unix time; 0 for never
     */
    public function __construct(
        public int $id,
        public int $session,
        public string $handle,
        public string $name,
        public string $email,
        public array $roles,
        public bool $admin,
        public array $permissions,
        public int $expires = 0,
    ) {
    }

    /** The Admin role may do everything, other users what one of their roles allows; an enum counts by its value */
    public function can(string|BackedEnum $permission): bool
    {
        $name = $permission instanceof BackedEnum ? (string) $permission->value : $permission;

        return $this->admin || in_array($name, $this->permissions, true);
    }

    /**
     * What Io keeps as $req->principal: #[Authenticated], #[Role] (one of 'roles') and #[Permissions] read it. 'sid'
     * names the session for Io's SignOuts, 'exp' tells a WebSocket when to ask the session again.
     *
     * @return array{sub: int, sid: string, handle: string, name: string, email: string, roles: list<string>, admin: bool, permissions: list<string>, exp?: int}
     */
    public function claims(): array
    {
        return [
            'sub' => $this->id,
            SignOuts::CLAIM => (string) $this->session,
            'handle' => $this->handle,
            'name' => $this->name,
            'email' => $this->email,
            'roles' => $this->roles,
            'admin' => $this->admin,
            'permissions' => $this->permissions,
        ] + ($this->expires > 0 ? ['exp' => $this->expires] : []);
    }
}
