<?php

namespace Io\Auth;

use BackedEnum;
use Io\Support\Row;

/** A role as a list of roles shows it. */
final readonly class Role
{
    /** @param list<string> $permissions */
    public function __construct(
        public int $id,
        public string $name,
        public bool $builtin,
        public bool $twoFactor,
        public array $permissions,
        public int $users,
    ) {
    }

    /** @param array<string, mixed> $row */
    public static function from(array $row): self
    {
        $r = Row::of($row);

        return new self(
            $r->int('id'),
            $r->string('name'),
            $r->bool('builtin'),
            $r->bool('two_factor_required'),
            $r->list('permissions', 'string'),
            $r->int('users'),
        );
    }

    /** The Admin role allows everything; an enum counts by its value */
    public function allows(string|BackedEnum $permission): bool
    {
        $name = $permission instanceof BackedEnum ? (string) $permission->value : $permission;

        return $this->builtin || in_array($name, $this->permissions, true);
    }
}
